// src/main.rs

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use pairing::bls12_381::{Bls12, Fr};
use pairing::{Field, PrimeField};
use sapling_crypto::jubjub::JubjubBls12;
use serde_json::{json, Value, from_str as from_json_str};
use sonic_ucse::protocol::Aggregate;
use std::{
    collections::HashMap,
    fs::{self, File},
    io::Cursor,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};
use warp::{Filter, reject::Reject};
use base64::{encode, decode};

use sonic_ucse::{
    bundle::{CircuitChoice, ProofBundle, Scheme},
    circuits::{
        adaptor::AdaptorCircuit,
        pedersen::{BBLamassuPedersenHashPreimageCircuit, PedersenHashPreimageCircuit},
        sha256::{BBLamassuSHA256PreimageCircuit, SHA256PreimageCircuit},
    },
    protocol::{create_proof, create_underlying_proof, MultiVerifier, SonicProof, UCProof, create_aggregate, create_advice},
    srs::SRS,
    synthesis::Permutation3,
    util::dusk_to_sapling,
    Circuit, Statement,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_ENGINE};
use sapling_crypto::jubjub::{edwards::Point, PrimeOrder};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// A simple wrapper to carry an error string through Warp rejects.
#[derive(Debug)]
struct RejectMessage(String);
impl Reject for RejectMessage {}

/// Command-line interface
#[derive(Parser, Debug)]
#[command(author, version, about = "A CLI for BB-Lamassu & Sonic zk-SNARKs")]
struct Cli {
    /// Run as HTTP server (in-memory, keyed by UUID)
    #[arg(long)]
    http: bool,
    #[arg(long, default_value = "127.0.0.1")]
    http_host: String,
    #[arg(long, default_value = "4000")]
    http_port: u16,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Setup(SetupArgs),
    Prove(ProveArgs),
    Verify(VerifyArgs),
}

#[derive(Args, Debug)] struct SetupArgs {
    #[arg(long)] degree: Option<usize>,
    #[arg(short, long, default_value = "srs.bin")] srs_path: PathBuf,
    #[arg(long)] dummy: bool,
    #[arg(long)] preimage_bits: Option<usize>,
}

#[derive(Args, Debug)] struct ProveArgs {
    #[arg(long, value_enum)] scheme: Scheme,
    #[arg(long, value_enum)] circuit: CircuitChoice,
    #[arg(short, long, default_value = "srs.bin")] srs_path: PathBuf,
    #[arg(short, long)] witness_path: PathBuf,
    #[arg(short, long, default_value = "proof.bin")] proof_path: PathBuf,
}

#[derive(Args, Debug)] struct VerifyArgs {
    #[arg(short, long, default_value = "srs.bin")] srs_path: PathBuf,
    #[arg(short, long, default_value = "proof.bin")] proof_path: PathBuf,
}



#[derive(serde::Deserialize)]
struct Witness { preimage: Vec<bool> }

/// Trait to unify proof verification
trait Verifier<'a> {
    fn add_uc_proof(&mut self, proof: &UCProof<Bls12>, inputs: &[Fr]);
    fn add_sonic_proof(&mut self, proof: &SonicProof<Bls12>, inputs: &[Fr]);
    fn add_aggregate(&mut self, proofs: &[(SonicProof<Bls12>, sonic_ucse::protocol::SxyAdvice<Bls12>)], aggregate: &Aggregate<Bls12>);
    fn check_all(self: Box<Self>) -> bool;
}

impl<'a, C, S> Verifier<'a> for MultiVerifier<Bls12, C, S>
where
    C: 'a + Circuit<Bls12> + Send + Sync + Statement,
    S: 'static + sonic_ucse::synthesis::SynthesisDriver,
{
    fn add_uc_proof(&mut self, proof: &UCProof<Bls12>, inputs: &[Fr]) {
        self.add_proof(proof, inputs, |_, _| None);
    }
    fn add_sonic_proof(&mut self, proof: &SonicProof<Bls12>, inputs: &[Fr]) {
        self.add_underlying_proof(proof, inputs, |_, _| None);
    }
    fn add_aggregate(&mut self, proofs: &[(SonicProof<Bls12>, sonic_ucse::protocol::SxyAdvice<Bls12>)], aggregate: &Aggregate<Bls12>) { 
        MultiVerifier::add_aggregate(self, proofs, aggregate); 
    }

    fn check_all(self: Box<Self>) -> bool {
        MultiVerifier::check_all(*self)
    }
}


#[derive(Serialize, Deserialize)]
struct RunBenchmarkBody {
    srs_id: String,
    circuit: CircuitChoice,
    witness_bits: usize,
    samples: usize,
}


#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.http {
        run_http_server(cli.http_host, cli.http_port).await?;
        return Ok(());
    }

    let cmd = cli.command.expect("Subcommand required unless --http");
    match cmd {
        Commands::Setup(a)  => handle_setup(a).context("Setup failed")?,
        Commands::Prove(a)  => handle_prove(a).context("Prove failed")?,
        Commands::Verify(a) => handle_verify(a).context("Verify failed")?,
    }
    Ok(())
}

/// HTTP server: in-memory SRS keyed by UUID, full /setup_srs, /prove, and /verify
async fn run_http_server(host: String, port: u16) -> Result<()> {
    let srs_map = Arc::new(Mutex::new(HashMap::<String, SRS<Bls12>>::new()));

    // GET /setup_srs?id=&degree=&dummy=&preimage_bits=
    let setup_map = srs_map.clone();
    let setup = warp::path("setup_srs")
        .and(warp::get())
        .and(warp::query::<HashMap<String,String>>())
        .and_then(move |params: HashMap<String,String>| {
            let map = setup_map.clone();
            async move {
                let id = params.get("id")
                    .cloned()
                    .ok_or_else(|| warp::reject::custom(RejectMessage("Missing id".into())))?;
                let dummy = params.get("dummy").map_or(false, |v| v=="1");
                let degree = params.get("degree").and_then(|d| d.parse().ok());
                let preimage_bits = params.get("preimage_bits").and_then(|b| b.parse().ok());

                let srs = if dummy {
                    SRS::<Bls12>::dummy(preimage_bits.unwrap_or(0), Fr::one(), Fr::one())
                } else {
                    let d = degree.ok_or_else(|| warp::reject::custom(RejectMessage(
                        "Missing degree for real setup".into()
                    )))?;
                    SRS::<Bls12>::new(d, Fr::one(), Fr::one())
                };

                map.lock().unwrap().insert(id.clone(), srs);
                Ok::<_, warp::Rejection>(warp::reply::json(&json!({ "success": true })))
            }
        });

    // POST /prove?id=&scheme=&circuit=   body={"witness":[true,false,...]}
    let prove_map = srs_map.clone();
    let prove = warp::path("prove")
        .and(warp::post())
        .and(warp::query::<HashMap<String,String>>())
        .and(warp::body::json())
        .and_then(move |params: HashMap<String, String>, body: Value| {
            let map = prove_map.clone();
            async move {
                let id = params.get("id")
                    .cloned()
                    .ok_or_else(|| warp::reject::custom(RejectMessage("Missing id".into())))?;
                let scheme_str = params.get("scheme").cloned().unwrap_or_default();
                let circuit_str = params.get("circuit").cloned().unwrap_or_default();

                let srs = map.lock().unwrap()
                    .get(&id).cloned()
                    .ok_or_else(|| warp::reject::custom(RejectMessage("Unknown id".into())))?;

                let scheme = match scheme_str.to_lowercase().as_str() {
                    "sonic"      => Scheme::Sonic,
                    "bb-lamassu" => Scheme::BbLamassu,
                    other        => return Err(warp::reject::custom(
                        RejectMessage(format!("Invalid scheme: {}", other))
                    )),
                };
                let circuit_choice = match circuit_str.to_lowercase().as_str() {
                    "pedersen" => CircuitChoice::Pedersen,
                    "sha256"   => CircuitChoice::Sha256,
                    other      => return Err(warp::reject::custom(
                        RejectMessage(format!("Invalid circuit: {}", other))
                    )),
                };

                let arr = body.get("witness")
                    .and_then(Value::as_array)
                    .ok_or_else(|| warp::reject::custom(RejectMessage("Missing witness".into())))?;
                let mut witness: Vec<Option<bool>> = Vec::with_capacity(arr.len());
                for v in arr {
                    witness.push(v.as_bool());
                }
                let bits = witness.len();

                let params_jubjub = JubjubBls12::new();
                let bundle_res: Result<ProofBundle, anyhow::Error> = (|| {
                    match scheme {
                        Scheme::Sonic => {
                            let proof = match circuit_choice {
                                CircuitChoice::Pedersen => {
                                    let c = AdaptorCircuit(PedersenHashPreimageCircuit::new(witness.clone()));
                                    create_underlying_proof::<Bls12, _, Permutation3>(&c, &srs)?
                                }
                                CircuitChoice::Sha256 => {
                                    let c = AdaptorCircuit(SHA256PreimageCircuit::new(witness.clone()));
                                    create_underlying_proof::<Bls12, _, Permutation3>(&c, &srs)?
                                }
                            };
                            Ok(ProofBundle::new_sonic(proof, bits, circuit_choice))
                        }
                        Scheme::BbLamassu => {
                            let (proof, digest) = match circuit_choice {
                                CircuitChoice::Pedersen => {
                                    let mut c = BBLamassuPedersenHashPreimageCircuit::new_from_witness(
                                        &srs, &params_jubjub, witness.clone()
                                    );
                                    let p = create_proof::<Bls12, _, Permutation3>(&AdaptorCircuit(c.clone()), &srs)?;
                                    (p, c.digest)
                                }
                                CircuitChoice::Sha256 => {
                                    let mut c = BBLamassuSHA256PreimageCircuit::new_from_witness(
                                        &srs, &params_jubjub, witness.clone()
                                    );
                                    let p = create_proof::<Bls12, _, Permutation3>(&AdaptorCircuit(c.clone()), &srs)?;
                                    (p, c.digest)
                                }
                            };
                            Ok(ProofBundle::new_bb_lamassu(proof, digest, bits, circuit_choice))
                        }
                    }
                })();

                let bundle = bundle_res
                    .map_err(|e| warp::reject::custom(RejectMessage(e.to_string())))?;

                let mut buf = Vec::new();
                bundle.write(&mut buf).map_err(|e| warp::reject::custom(RejectMessage(e.to_string())))?;
                let encoded = encode(&buf);

                Ok::<_, warp::Rejection>(warp::reply::json(&json!({ "proof": encoded })))
            }
        });

    // POST /verify?id=…   body={"proof":"BASE64","public_signals":[...]}
    let verify_map = srs_map.clone();
    let verify = warp::path("verify")
        .and(warp::post())
        .and(warp::query::<HashMap<String,String>>())
        .and(warp::body::json())
        .and_then(move |params: HashMap<String, String>, body: Value| {
            let map = verify_map.clone();
            async move {
                let id = params.get("id")
                    .cloned()
                    .ok_or_else(|| warp::reject::custom(RejectMessage("Missing id".into())))?;
                let srs = map.lock().unwrap()
                    .get(&id).cloned()
                    .ok_or_else(|| warp::reject::custom(RejectMessage("Unknown id".into())))?;

                let proof_str = body.get("proof")
                    .and_then(Value::as_str)
                    .ok_or_else(|| warp::reject::custom(RejectMessage("Missing proof".into())))?;
                let proof_bytes = decode(proof_str)
                    .map_err(|e| warp::reject::custom(RejectMessage(e.to_string())))?;

                let mut cursor = Cursor::new(&proof_bytes);
                let bundle = ProofBundle::read(&mut cursor)
                    .map_err(|e| warp::reject::custom(RejectMessage(e.to_string())))?;

                let params_jubjub = JubjubBls12::new();
                let is_valid_res: Result<bool, anyhow::Error> = (|| {
                    match bundle.scheme {
                        Scheme::BbLamassu => {
                            let uc = bundle.uc_proof.ok_or_else(|| anyhow!("Missing UC proof"))?;
                            let digest = bundle.digest.ok_or_else(|| anyhow!("Missing digest"))?;
                            let sap_c: Vec<_> = uc.c.iter()
                                .map(|c| (dusk_to_sapling(c.gamma()), dusk_to_sapling(c.delta())))
                                .collect();
                            let mut v: Box<dyn Verifier<'_>> = match bundle.circuit_choice {
                                CircuitChoice::Pedersen => {
                                    let c = AdaptorCircuit(
                                        BBLamassuPedersenHashPreimageCircuit::new_for_verifier(
                                            &srs, &params_jubjub, digest, sap_c.clone(), bundle.witness_bits
                                        )
                                    );
                                    Box::new(MultiVerifier::<_, _, Permutation3>::new(c, &srs)?)
                                }
                                CircuitChoice::Sha256 => {
                                    let c = AdaptorCircuit(
                                        BBLamassuSHA256PreimageCircuit::new_for_verifier(
                                            &srs, &params_jubjub, digest, sap_c.clone(), bundle.witness_bits
                                        )
                                    );
                                    Box::new(MultiVerifier::<_, _, Permutation3>::new(c, &srs)?)
                                }
                            };
                            v.add_uc_proof(&uc, &[]);
                            Ok(v.check_all())
                        }
                        Scheme::Sonic => {
                            let sp = bundle.sonic_proof.ok_or_else(|| anyhow!("Missing Sonic proof"))?;
                            let mut v: Box<dyn Verifier<'_>> = match bundle.circuit_choice {
                                CircuitChoice::Pedersen => {
                                    let c = AdaptorCircuit(PedersenHashPreimageCircuit::new(vec![None; bundle.witness_bits]));
                                    Box::new(MultiVerifier::<_, _, Permutation3>::new(c, &srs)?)
                                }
                                CircuitChoice::Sha256 => {
                                    let c = AdaptorCircuit(SHA256PreimageCircuit::new(vec![None; bundle.witness_bits]));
                                    Box::new(MultiVerifier::<_, _, Permutation3>::new(c, &srs)?)
                                }
                            };
                            v.add_sonic_proof(&sp, &[]);
                            Ok(v.check_all())
                        }
                    }
                })();

                let is_valid = is_valid_res
                    .map_err(|e| warp::reject::custom(RejectMessage(e.to_string())))?;
                Ok::<_, warp::Rejection>(warp::reply::json(&json!({ "valid": is_valid })))
            }
        });

    let benchmark = {
        let srs_map_clone = srs_map.clone();
        warp::path("run-aggregate-benchmark")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(move |body: HashMap<String, Value>| {
                let map = srs_map_clone.clone();
                async move {
                    let circuit_str = body.get("circuit").and_then(Value::as_str).ok_or_else(|| warp::reject::custom(RejectMessage("Missing or invalid 'circuit' field".into())))?;
                    let witness_bits = body.get("witness_bits").and_then(Value::as_u64).ok_or_else(|| warp::reject::custom(RejectMessage("Missing or invalid 'witness_bits' field".into())))? as usize;
                    let samples = body.get("samples").and_then(Value::as_u64).ok_or_else(|| warp::reject::custom(RejectMessage("Missing or invalid 'samples' field".into())))? as usize;
                    let srs_id = body.get("srs_id").and_then(Value::as_str).ok_or_else(|| warp::reject::custom(RejectMessage("Missing or invalid 'srs_id' field".into())))?;

                    let srs = map.lock().unwrap().get(srs_id).cloned()
                        .ok_or_else(|| warp::reject::custom(RejectMessage("Unknown SRS id".into())))?;
                    
                    let params = JubjubBls12::new();

                    let circuit_choice = match circuit_str {
                        "pedersen" => CircuitChoice::Pedersen,
                        "sha256" => CircuitChoice::Sha256,
                        _ => return Err(warp::reject::custom(RejectMessage("Invalid circuit name specified".into()))),
                    };

                    match circuit_choice {
                        CircuitChoice::Pedersen => {
                             let mut proofs_with_advice = Vec::new();
                            let proof_gen_start = Instant::now();
                            for _ in 0..samples {
                                let circuit = AdaptorCircuit(BBLamassuPedersenHashPreimageCircuit::new_from_witness(&srs, &params, vec![Some(true); witness_bits]));
                                let uc_proof = create_proof::<Bls12, _, Permutation3>(&circuit, &srs)
                                    .map_err(|e| warp::reject::custom(RejectMessage(format!("Proof creation failed: {:?}", e))))?;
                                let sonic_proof = uc_proof.pi;
                                let advice = create_advice::<Bls12, _, Permutation3>(&circuit, &sonic_proof, &srs);
                                proofs_with_advice.push((sonic_proof, advice));
                            }
                            let proof_creation_avg_ms = proof_gen_start.elapsed().as_millis() as f64 / samples as f64;

                            let circuit_for_agg = AdaptorCircuit(BBLamassuPedersenHashPreimageCircuit::new_from_witness(&srs, &params, vec![Some(true); witness_bits]));
                            let agg_create_start = Instant::now();
                            let aggregate = create_aggregate::<Bls12, _, Permutation3>(&circuit_for_agg, &proofs_with_advice, &srs);
                            let aggregate_creation_ms = agg_create_start.elapsed().as_millis() as f64;

                            let circuit_for_verify = AdaptorCircuit(BBLamassuPedersenHashPreimageCircuit::new_from_witness(&srs, &params, vec![Some(true); witness_bits]));
                            let single_verify_start = Instant::now();
                            let mut single_verifier = MultiVerifier::<Bls12, _, Permutation3>::new(circuit_for_verify.clone(), &srs).unwrap();
                            single_verifier.add_underlying_proof(&proofs_with_advice[0].0, &[], |_,_| None);
                            assert!(single_verifier.check_all());
                            let single_verify_ms = single_verify_start.elapsed().as_millis() as f64;

                            let naive_batch_start = Instant::now();
                            let mut naive_verifier = MultiVerifier::<Bls12, _, Permutation3>::new(circuit_for_verify.clone(), &srs).unwrap();
                            for (proof, _) in &proofs_with_advice {
                                naive_verifier.add_underlying_proof(proof, &[], |_,_| None);
                            }
                            assert!(naive_verifier.check_all());
                            let naive_batch_verify_ms = naive_batch_start.elapsed().as_millis() as f64;
                            
                            let helped_verify_start = Instant::now();
                            let mut helped_verifier = MultiVerifier::<Bls12, _, Permutation3>::new(circuit_for_verify.clone(), &srs).unwrap();
                            helped_verifier.add_aggregate(&proofs_with_advice, &aggregate);
                            assert!(helped_verifier.check_all());
                            let helped_verify_ms = helped_verify_start.elapsed().as_millis() as f64;

                            let marginal_cost_ms = if samples > 1 { (helped_verify_ms - single_verify_ms) / (samples - 1) as f64 } else { 0.0 };

                            Ok(warp::reply::json(&json!({
                                "proof_creation_avg_ms": proof_creation_avg_ms,
                                "aggregate_creation_ms": aggregate_creation_ms,
                                "single_verify_ms": single_verify_ms,
                                "naive_batch_verify_ms": naive_batch_verify_ms,
                                "helped_verify_ms": helped_verify_ms,
                                "marginal_cost_ms": marginal_cost_ms,
                            })))
                        },
                        CircuitChoice::Sha256 => {
                            let mut proofs_with_advice = Vec::new();
                            let proof_gen_start = Instant::now();
                            for _ in 0..samples {
                                let circuit = AdaptorCircuit(BBLamassuSHA256PreimageCircuit::new_from_witness(&srs, &params, vec![Some(true); witness_bits]));
                                let uc_proof = create_proof::<Bls12, _, Permutation3>(&circuit, &srs)
                                    .map_err(|e| warp::reject::custom(RejectMessage(format!("Proof creation failed: {:?}", e))))?;
                                let sonic_proof = uc_proof.pi;
                                let advice = create_advice::<Bls12, _, Permutation3>(&circuit, &sonic_proof, &srs);
                                proofs_with_advice.push((sonic_proof, advice));
                            }
                            let proof_creation_avg_ms = proof_gen_start.elapsed().as_millis() as f64 / samples as f64;

                            let circuit_for_agg = AdaptorCircuit(BBLamassuSHA256PreimageCircuit::new_from_witness(&srs, &params, vec![Some(true); witness_bits]));
                            let agg_create_start = Instant::now();
                            let aggregate = create_aggregate::<Bls12, _, Permutation3>(&circuit_for_agg, &proofs_with_advice, &srs);
                            let aggregate_creation_ms = agg_create_start.elapsed().as_millis() as f64;
                            
                            let circuit_for_verify = AdaptorCircuit(BBLamassuSHA256PreimageCircuit::new_from_witness(&srs, &params, vec![Some(true); witness_bits]));
                            let single_verify_start = Instant::now();
                            let mut single_verifier = MultiVerifier::<Bls12, _, Permutation3>::new(circuit_for_verify.clone(), &srs).unwrap();
                            single_verifier.add_underlying_proof(&proofs_with_advice[0].0, &[], |_,_| None);
                            assert!(single_verifier.check_all());
                            let single_verify_ms = single_verify_start.elapsed().as_millis() as f64;

                            let naive_batch_start = Instant::now();
                            let mut naive_verifier = MultiVerifier::<Bls12, _, Permutation3>::new(circuit_for_verify.clone(), &srs).unwrap();
                            for (proof, _) in &proofs_with_advice {
                                naive_verifier.add_underlying_proof(proof, &[], |_,_| None);
                            }
                            assert!(naive_verifier.check_all());
                            let naive_batch_verify_ms = naive_batch_start.elapsed().as_millis() as f64;

                            let helped_verify_start = Instant::now();
                            let mut helped_verifier = MultiVerifier::<Bls12, _, Permutation3>::new(circuit_for_verify.clone(), &srs).unwrap();
                            helped_verifier.add_aggregate(&proofs_with_advice, &aggregate);
                            assert!(helped_verifier.check_all());
                            let helped_verify_ms = helped_verify_start.elapsed().as_millis() as f64;
                            
                            let marginal_cost_ms = if samples > 1 { (helped_verify_ms - single_verify_ms) / (samples - 1) as f64 } else { 0.0 };

                            Ok(warp::reply::json(&json!({
                                "proof_creation_avg_ms": proof_creation_avg_ms,
                                "aggregate_creation_ms": aggregate_creation_ms,
                                "single_verify_ms": single_verify_ms,
                                "naive_batch_verify_ms": naive_batch_verify_ms,
                                "helped_verify_ms": helped_verify_ms,
                                "marginal_cost_ms": marginal_cost_ms,
                            })))
                        }
                    }
                }
            })
    };    


    let routes = setup
        .or(prove)
        .or(verify)
        .or(benchmark)
        .recover(|rej: warp::Rejection| async move {
            let msg = rej.find::<RejectMessage>().map(|e| e.0.clone())
                .unwrap_or_else(|| "Unknown error".into());
            Ok::<_, std::convert::Infallible>(
                warp::reply::with_status(
                    warp::reply::json(&json!({ "error": msg })),
                    warp::http::StatusCode::BAD_REQUEST,
                )
            )
        });

    println!("Starting HTTP server on http://{}:{}", host, port);
    let ip = host.parse::<std::net::IpAddr>().unwrap();
    warp::serve(routes).run((ip, port)).await;
    Ok(())
}

// --- CLI handlers (unchanged) ---

fn handle_setup(args: SetupArgs) -> Result<()> {
    let srs_x     = Fr::from_str("23923").unwrap();
    let srs_alpha = Fr::from_str("23728792").unwrap();
    let srs = if args.dummy {
        let deg = args.preimage_bits.unwrap_or(0);
        SRS::<Bls12>::dummy(deg, srs_x, srs_alpha)
    } else {
        let d = args.degree.ok_or_else(|| anyhow!("--degree required"))?;
        SRS::<Bls12>::new(d, srs_x, srs_alpha)
    };
    srs.write_to_file(&args.srs_path).context("Writing SRS failed")?;
    println!("✅ SRS written to {:?}", args.srs_path);
    Ok(())
}

fn handle_prove(args: ProveArgs) -> Result<()> {
    println!("▶️  Generating proof for scheme={:?}, circuit={:?}", args.scheme, args.circuit);
    let start = Instant::now();

    let srs = SRS::<Bls12>::read_from_file(&args.srs_path)
        .context("Reading SRS file failed")?;
    let witness_str = fs::read_to_string(&args.witness_path)
        .context("Reading witness file failed")?;
    let witness: Witness = from_json_str(&witness_str)?;
    let preimage: Vec<Option<bool>> = witness.preimage.into_iter().map(Some).collect();
    let bits = preimage.len();

    let params = JubjubBls12::new();
    let bundle = match args.scheme {
        Scheme::Sonic => {
            let proof = match args.circuit {
                CircuitChoice::Pedersen => {
                    let c = AdaptorCircuit(PedersenHashPreimageCircuit::new(preimage.clone()));
                    create_underlying_proof::<Bls12, _, Permutation3>(&c, &srs)?
                }
                CircuitChoice::Sha256 => {
                    let c = AdaptorCircuit(SHA256PreimageCircuit::new(preimage.clone()));
                    create_underlying_proof::<Bls12, _, Permutation3>(&c, &srs)?
                }
            };
            ProofBundle::new_sonic(proof, bits, args.circuit)
        }
        Scheme::BbLamassu => {
            let (proof, digest) = match args.circuit {
                CircuitChoice::Pedersen => {
                    let mut c = BBLamassuPedersenHashPreimageCircuit::new_from_witness(&srs, &params, preimage.clone());
                    let p = create_proof::<Bls12, _, Permutation3>(&AdaptorCircuit(c.clone()), &srs)?;
                    (p, c.digest)
                }
                CircuitChoice::Sha256 => {
                    let mut c = BBLamassuSHA256PreimageCircuit::new_from_witness(&srs, &params, preimage.clone());
                    let p = create_proof::<Bls12, _, Permutation3>(&AdaptorCircuit(c.clone()), &srs)?;
                    (p, c.digest)
                }
            };
            ProofBundle::new_bb_lamassu(proof, digest, bits, args.circuit)
        }
    };

    let mut out = File::create(&args.proof_path).context("Creating proof file failed")?;
    bundle.write(&mut out)?;
    println!("✅ Proof written to {:?} (elapsed {:?})", args.proof_path, start.elapsed());
    Ok(())
}

fn handle_verify(args: VerifyArgs) -> Result<()> {
    println!("▶️  Verifying proof in {:?}", args.proof_path);
    let start = Instant::now();

    let srs = SRS::<Bls12>::read_from_file(&args.srs_path).context("Reading SRS failed")?;
    let mut f = File::open(&args.proof_path).context("Opening proof file failed")?;
    let bundle = ProofBundle::read(&mut f)?;
    println!("   Loaded bundle: scheme={:?}, circuit={:?}", bundle.scheme, bundle.circuit_choice);

    let params = JubjubBls12::new();
    let is_valid = match bundle.scheme {
        Scheme::BbLamassu => {
            let uc = bundle.uc_proof.ok_or_else(|| anyhow!("Expected BbLamassu proof"))?;
            let digest = bundle.digest.ok_or_else(|| anyhow!("Expected digest"))?;
            let sap_c: Vec<_> = uc.c.iter()
                .map(|c| (dusk_to_sapling(c.gamma()), dusk_to_sapling(c.delta())))
                .collect();
            let mut v: Box<dyn Verifier<'_>> = match bundle.circuit_choice {
                CircuitChoice::Pedersen => {
                    let c = AdaptorCircuit(
                        BBLamassuPedersenHashPreimageCircuit::new_for_verifier(
                            &srs, &params, digest, sap_c.clone(), bundle.witness_bits
                        )
                    );
                    Box::new(MultiVerifier::<_, _, Permutation3>::new(c, &srs)?)
                }
                CircuitChoice::Sha256 => {
                    let c = AdaptorCircuit(
                        BBLamassuSHA256PreimageCircuit::new_for_verifier(
                            &srs, &params, digest, sap_c.clone(), bundle.witness_bits
                        )
                    );
                    Box::new(MultiVerifier::<_, _, Permutation3>::new(c, &srs)?)
                }
            };
            v.add_uc_proof(&uc, &[]);
            v.check_all()
        }
        Scheme::Sonic => {
            let sp = bundle.sonic_proof.ok_or_else(|| anyhow!("Expected Sonic proof"))?;
            let mut v: Box<dyn Verifier<'_>> = match bundle.circuit_choice {
                CircuitChoice::Pedersen => {
                    let c = AdaptorCircuit(PedersenHashPreimageCircuit::new(vec![None; bundle.witness_bits]));
                    Box::new(MultiVerifier::<_, _, Permutation3>::new(c, &srs)?)
                }
                CircuitChoice::Sha256 => {
                    let c = AdaptorCircuit(SHA256PreimageCircuit::new(vec![None; bundle.witness_bits]));
                    Box::new(MultiVerifier::<_, _, Permutation3>::new(c, &srs)?)
                }
            };
            v.add_sonic_proof(&sp, &[]);
            v.check_all()
        }
    };

    println!("✅ Verification result: {} (elapsed {:?})", is_valid, start.elapsed());
    Ok(())
}