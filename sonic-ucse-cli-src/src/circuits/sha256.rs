// src/circuits/sha256.rs

use crate::{
    srs::SRS,
    util::{be_opt_vec_to_jubjub_scalar, bool_vec_to_bytes, dusk_to_sapling, le_bytes_to_le_bits},
    Statement, WitnessScalar,
};
use crypto::digest::Digest;
use dusk_bytes::Serializable;
use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};
use pairing::bls12_381::Bls12;
use pairing::Engine;
use sapling_crypto::{
    circuit::{
        boolean::{AllocatedBit, Boolean},
        ecc::EdwardsPoint,
        sha256 as circuit_sha256,
    },
    jubjub::{edwards::Point, JubjubBls12, PrimeOrder},
};


/***** Basic SHA256 Preimage Circuit (for Sonic Scheme) *****/

#[derive(Clone)]
pub struct SHA256PreimageCircuit {
    pub preimage: Vec<Option<bool>>,
}

impl SHA256PreimageCircuit {
    pub fn new(preimage_opt: Vec<Option<bool>>) -> Self {
        Self { preimage: preimage_opt }
    }
}

impl Statement for SHA256PreimageCircuit {
    fn get_statement_bytes(&self) -> &[u8] {
        b"sha256_preimage_statement"
    }
}

impl WitnessScalar for SHA256PreimageCircuit {
    fn get_witness_scalar(&self) -> Vec<JubJubScalar> {
        be_opt_vec_to_jubjub_scalar(&self.preimage)
    }
}

impl<E: Engine> bellman::Circuit<E> for SHA256PreimageCircuit {
    fn synthesize<CS: bellman::ConstraintSystem<E>>(
        self,
        cs: &mut CS,
    ) -> Result<(), bellman::SynthesisError> {
        let mut preimage_bits = Vec::with_capacity(self.preimage.len());
        for (i, bit) in self.preimage.iter().enumerate() {
            preimage_bits.push(Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| format!("preimage bit {}", i)),
                *bit,
            )?));
        }
        circuit_sha256::sha256(cs.namespace(|| "sha256"), &preimage_bits)?;
        Ok(())
    }
}


/***** BB-Lamassu (UC+SE) SHA256 Preimage Circuit *****/

#[derive(Clone)]
pub struct BBLamassuSHA256PreimageCircuit<'a> {
    pub params: &'a JubjubBls12,
    // Public Inputs
    pub pk: Point<Bls12, PrimeOrder>,
    pub digest: Point<Bls12, PrimeOrder>,
    pub c: Vec<(Point<Bls12, PrimeOrder>, Point<Bls12, PrimeOrder>)>,
    pub cpk: Point<Bls12, PrimeOrder>,
    pub cpk_o: Point<Bls12, PrimeOrder>,
    // Witness
    pub preimage: Vec<Option<bool>>,
    pub preimage_pts: Vec<Point<Bls12, PrimeOrder>>,
    pub omegas: Vec<Vec<Option<bool>>>,
    pub shift: Vec<Option<bool>>,
}

impl<'a> BBLamassuSHA256PreimageCircuit<'a> {
    /// Creates a new circuit instance for a Prover.
    pub fn new_from_witness(
        srs: &'a SRS<Bls12>,
        params: &'a JubjubBls12,
        preimage_opt: Vec<Option<bool>>,
    ) -> Self {
        let preimage_bool: Vec<bool> = preimage_opt.iter().map(|b| b.unwrap_or(false)).collect();
        let preimage_chunks_dusk = be_opt_vec_to_jubjub_scalar(&preimage_opt)
            .iter()
            .map(|scalar| GENERATOR_EXTENDED * scalar)
            .collect::<Vec<_>>();
        let preimage_chunk_pts = preimage_chunks_dusk
            .iter()
            .map(|chunk| dusk_to_sapling(*chunk))
            .collect::<Vec<_>>();

        let mut rand_le_opt_vec = vec![];
        let mut cts_sapling = vec![];
        for chunk in &preimage_chunks_dusk {
            let rand = JubJubScalar::random(&mut rand::thread_rng());
            let mut buf = [false; 256];
            le_bytes_to_le_bits(&rand.to_bytes(), 32, &mut buf);
            rand_le_opt_vec.push(buf.iter().map(|&b| Some(b)).collect());
            let c = srs.pk.encrypt(*chunk, rand);
            cts_sapling.push((dusk_to_sapling(c.gamma()), dusk_to_sapling(c.delta())));
        }

        let mut hasher = crypto::sha2::Sha256::new();
        hasher.input(&bool_vec_to_bytes(&preimage_bool));
        let mut padded_digest = [0u8; 64];
        hasher.result(&mut padded_digest[32..]);
        let digest_dusk = GENERATOR_EXTENDED * JubJubScalar::from_bytes_wide(&padded_digest);

        Self {
            params,
            pk: dusk_to_sapling(srs.pk.0),
            digest: dusk_to_sapling(digest_dusk),
            c: cts_sapling,
            cpk: dusk_to_sapling(*srs.cpk.as_ref()),
            cpk_o: dusk_to_sapling(GENERATOR_EXTENDED),
            preimage: preimage_opt,
            preimage_pts: preimage_chunk_pts,
            omegas: rand_le_opt_vec,
            shift: vec![Some(true); 256],
        }
    }

    /// Creates a new circuit instance for a Verifier.
    pub fn new_for_verifier(
        srs: &'a SRS<Bls12>,
        params: &'a JubjubBls12,
        digest: Point<Bls12, PrimeOrder>,
        c: Vec<(Point<Bls12, PrimeOrder>, Point<Bls12, PrimeOrder>)>,
        preimage_bits: usize,
    ) -> Self {
        let num_chunks = (preimage_bits + 47) / 48;
        Self {
            params,
            pk: dusk_to_sapling(srs.pk.0),
            digest,
            c,
            cpk: dusk_to_sapling(*srs.cpk.as_ref()),
            cpk_o: dusk_to_sapling(GENERATOR_EXTENDED),
            preimage: vec![None; preimage_bits],
            preimage_pts: vec![Point::zero(); num_chunks],
            omegas: vec![vec![None; 256]; num_chunks],
            shift: vec![None; 256],
        }
    }
}

impl<'a> Statement for BBLamassuSHA256PreimageCircuit<'a> {
    fn get_statement_bytes(&self) -> &[u8] {
        b"bb_lamassu_sha256_statement"
    }
}

impl<'a> WitnessScalar for BBLamassuSHA256PreimageCircuit<'a> {
    fn get_witness_scalar(&self) -> Vec<JubJubScalar> {
        be_opt_vec_to_jubjub_scalar(&self.preimage)
    }
}

impl<'a> bellman::Circuit<Bls12> for BBLamassuSHA256PreimageCircuit<'a> {
    fn synthesize<CS: bellman::ConstraintSystem<Bls12>>(
        self,
        cs: &mut CS,
    ) -> Result<(), bellman::SynthesisError> {
        assert_eq!(self.c.len(), self.omegas.len());
        assert_eq!(self.omegas.len(), self.preimage_pts.len());

        let mut preimage = Vec::with_capacity(self.preimage.len());
        for (i, bit) in self.preimage.iter().enumerate() {
            preimage.push(Boolean::from(AllocatedBit::alloc(cs.namespace(|| format!("preimage bit {}", i)), *bit)?));
        }
        let mut shift = Vec::with_capacity(self.shift.len());
        for (i, bit) in self.shift.iter().enumerate() {
            shift.push(Boolean::from(AllocatedBit::alloc(cs.namespace(|| format!("shift bit {}", i)), *bit)?));
        }
        let mut omegas = Vec::with_capacity(self.omegas.len());
        for (i, omega_vec) in self.omegas.iter().enumerate() {
            let mut input_omega = Vec::with_capacity(omega_vec.len());
            for (j, &bit) in omega_vec.iter().enumerate() {
                input_omega.push(Boolean::from(AllocatedBit::alloc(cs.namespace(|| format!("omega {} bit {}", i, j)), bit)?));
            }
            omegas.push(input_omega);
        }

        let pk = EdwardsPoint::witness(cs.namespace(|| "pk"), Some(self.pk), self.params)?;
        let mut preimage_msgs = vec![];
        for (i, preimage_pt) in self.preimage_pts.iter().enumerate() {
            preimage_msgs.push(EdwardsPoint::witness(cs.namespace(|| format!("preimage point {}", i)), Some(preimage_pt.clone()), self.params)?);
        }
        let generator = EdwardsPoint::witness(cs.namespace(|| "generator"), Some(self.cpk_o.clone()), self.params)?;

        for i in 0..self.c.len() {
            let gamma = EdwardsPoint::witness(cs.namespace(|| format!("gamma {}", i)), Some(self.c[i].0.clone()), self.params)?;
            let delta = EdwardsPoint::witness(cs.namespace(|| format!("delta {}", i)), Some(self.c[i].1.clone()), self.params)?;
            let s_prime = pk.mul(cs.namespace(|| format!("s' {}", i)), &omegas[i], self.params)?;
            let delta_prime = s_prime.add(cs.namespace(|| format!("delta' {}", i)), &preimage_msgs[i], self.params)?;
            let gamma_prime = generator.mul(cs.namespace(|| format!("gamma' {}", i)), &omegas[i], self.params)?;
            cs.enforce(|| format!("gamma {} x-coord", i), |lc| lc + gamma.get_x().get_variable(), |lc| lc + CS::one(), |lc| lc + gamma_prime.get_x().get_variable());
            cs.enforce(|| format!("gamma {} y-coord", i), |lc| lc + gamma.get_y().get_variable(), |lc| lc + CS::one(), |lc| lc + gamma_prime.get_y().get_variable());
            cs.enforce(|| format!("delta {} x-coord", i), |lc| lc + delta.get_x().get_variable(), |lc| lc + CS::one(), |lc| lc + delta_prime.get_x().get_variable());
            cs.enforce(|| format!("delta {} y-coord", i), |lc| lc + delta.get_y().get_variable(), |lc| lc + CS::one(), |lc| lc + delta_prime.get_y().get_variable());
        }

        let cpk_o = generator.clone();
        let neg_cpk = EdwardsPoint::witness(cs.namespace(|| "neg cpk"), Some(self.cpk.negate()), self.params)?;
        let cpk_prime = cpk_o.mul(cs.namespace(|| "cpk' = cpk_o * shift"), &shift, self.params)?;
        let left_branch = cpk_prime.add(cs.namespace(|| "left branch = cpk' - cpk"), &neg_cpk, self.params)?;

        let h_prime_bits = circuit_sha256::sha256(cs.namespace(|| "h' = H(preimage)"), &preimage)?;
        let computed_digest_point = generator.mul(cs.namespace(|| "convert h_prime to point"), &h_prime_bits, self.params)?;
        let neg_digest = EdwardsPoint::witness(cs.namespace(|| "neg digest"), Some(self.digest.negate()), self.params)?;
        let right_branch = computed_digest_point.add(cs.namespace(|| "right branch"), &neg_digest, self.params)?;
        
        cs.enforce(|| "or constraint", |lc| lc + left_branch.get_x().get_variable(), |lc| lc + right_branch.get_x().get_variable(), |lc| lc);

        Ok(())
    }
}