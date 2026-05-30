use anyhow::{anyhow, Result};
use clap::ValueEnum;
use pairing::bls12_381::Bls12;
use sapling_crypto::jubjub::{edwards::Point, JubjubBls12, PrimeOrder};
use std::io::{Read, Write};
use serde::{Deserialize, Serialize};

use crate::protocol::{SonicProof, UCProof};
use crate::util::{read_point, write_point};


#[derive(ValueEnum, Clone, Debug, Copy, PartialEq, Eq)]
pub enum Scheme {
    Sonic,
    BbLamassu,
}
#[derive(ValueEnum, Clone, Debug, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CircuitChoice {
    Pedersen,
    Sha256,
}
#[derive(Clone)]
pub struct ProofBundle {
    pub scheme: Scheme,
    pub circuit_choice: CircuitChoice,
    pub witness_bits: usize,
    pub uc_proof: Option<UCProof<Bls12>>,
    pub sonic_proof: Option<SonicProof<Bls12>>,
    pub digest: Option<Point<Bls12, PrimeOrder>>,
}

impl ProofBundle {
    pub fn new_sonic(proof: SonicProof<Bls12>, witness_bits: usize, circuit_choice: CircuitChoice) -> Self {
        Self {
            scheme: Scheme::Sonic,
            circuit_choice,
            witness_bits,
            uc_proof: None,
            sonic_proof: Some(proof),
            digest: None,
        }
    }

    pub fn new_bb_lamassu(proof: UCProof<Bls12>, digest: Point<Bls12, PrimeOrder>, witness_bits: usize, circuit_choice: CircuitChoice) -> Self {
        Self {
            scheme: Scheme::BbLamassu,
            circuit_choice,
            witness_bits,
            uc_proof: Some(proof),
            sonic_proof: None,
            digest: Some(digest),
        }
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&(self.scheme as u8).to_le_bytes())?;
        writer.write_all(&(self.circuit_choice as u8).to_le_bytes())?;
        writer.write_all(&self.witness_bits.to_le_bytes())?;

        match self.scheme {
            Scheme::Sonic => {
                let proof = self.sonic_proof.as_ref().ok_or_else(|| anyhow!("Missing Sonic proof"))?;
                proof.write(writer)?;
            }
            Scheme::BbLamassu => {
                let proof = self.uc_proof.as_ref().ok_or_else(|| anyhow!("Missing BB-Lamassu proof"))?;
                let digest = self.digest.as_ref().ok_or_else(|| anyhow!("Missing digest"))?;
                proof.write(writer)?;
                write_point(writer, digest)?;
            }
        }
        Ok(())
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Self> {
        let mut scheme_byte = [0u8; 1];
        reader.read_exact(&mut scheme_byte)?;
        let scheme = match scheme_byte[0] {
            0 => Scheme::Sonic,
            1 => Scheme::BbLamassu,
            _ => return Err(anyhow!("Invalid scheme type")),
        };

        let mut circuit_byte = [0u8; 1];
        reader.read_exact(&mut circuit_byte)?;
        let circuit_choice = match circuit_byte[0] {
            0 => CircuitChoice::Pedersen,
            1 => CircuitChoice::Sha256,
            _ => return Err(anyhow!("Invalid circuit type")),
        };

        let mut bits_bytes = [0u8; 8];
        reader.read_exact(&mut bits_bytes)?;
        let witness_bits = usize::from_le_bytes(bits_bytes);

        match scheme {
            Scheme::Sonic => {
                let sonic_proof = SonicProof::read(reader)?;
                Ok(Self::new_sonic(sonic_proof, witness_bits, circuit_choice))
            }
            Scheme::BbLamassu => {
                let uc_proof = UCProof::read(reader)?;
                let params = JubjubBls12::new();
                let digest = read_point(reader, &params)?;
                Ok(Self::new_bb_lamassu(uc_proof, digest, witness_bits, circuit_choice))
            }
        }
    }
}