// src/srs.rs

use std::{
    fs::File,
    io::{self, Read, Write, Cursor},
    path::PathBuf,
};
use memmap2::MmapOptions;
#[cfg(unix)]
use libc;
use pairing::{Engine, CurveAffine, CurveProjective, EncodedPoint, Field};
use rand::thread_rng;
use rayon::prelude::*;

use dusk_bytes::Serializable;
use dusk_jubjub::{JubJubAffine, JubJubExtended};
use dusk_pki::{PublicKey as SigPK, SecretKey as SigSK};
use jubjub_elgamal::{PrivateKey as EncSK, PublicKey as EncPK};

use crate::usig::{Schnorr, Sig};

#[derive(Clone)]
pub struct SRS<E: Engine> {
    pub d: usize,
    pub g_negative_x:       Vec<E::G1Affine>,
    pub g_positive_x:       Vec<E::G1Affine>,
    pub h_negative_x:       Vec<E::G2Affine>,
    pub h_positive_x:       Vec<E::G2Affine>,
    pub g_negative_x_alpha: Vec<E::G1Affine>,
    pub g_positive_x_alpha: Vec<E::G1Affine>,
    pub h_negative_x_alpha: Vec<E::G2Affine>,
    pub h_positive_x_alpha: Vec<E::G2Affine>,
    pub cpk:                SigPK,
    pub pk:                 EncPK,
}

impl<E: Engine> SRS<E> {
    /// Insecure dummy SRS for testing
    pub fn dummy(d: usize, _: E::Fr, _: E::Fr) -> Self {
        let usig = Schnorr;
        let (_sk_sig, pk_sig): (SigSK, SigPK) = Sig::kgen(&usig);
        let mut rng = thread_rng();
        let sk = EncSK::new(&mut rng);
        let pk = EncPK::from(sk);

        SRS {
            d,
            g_negative_x:        vec![E::G1Affine::one(); d + 1],
            g_positive_x:        vec![E::G1Affine::one(); d + 1],
            h_negative_x:        vec![E::G2Affine::one(); d + 1],
            h_positive_x:        vec![E::G2Affine::one(); d + 1],
            g_negative_x_alpha:  vec![E::G1Affine::one(); d],
            g_positive_x_alpha:  vec![E::G1Affine::one(); d],
            h_negative_x_alpha:  vec![E::G2Affine::one(); d + 1],
            h_positive_x_alpha:  vec![E::G2Affine::one(); d + 1],
            cpk:                 pk_sig,
            pk,
        }
    }

    /// Real, single-party trusted setup: computes all ±x powers and α-shifts.
    pub fn new(d: usize, mut x: E::Fr, mut alpha: E::Fr) -> Self {
        // 1) Schnorr & ElGamal key generation
        let usig = Schnorr;
        let (_sk_sig, pk_sig): (SigSK, SigPK) = Sig::kgen(&usig);
        let mut rng = thread_rng();
        let sk = EncSK::new(&mut rng);
        let pk = EncPK::from(sk);

        // 2) Compute ±x^i in G1 and G2
        let mut g_pos: Vec<E::G1Affine> = Vec::with_capacity(d + 1);
        let mut g_neg: Vec<E::G1Affine> = Vec::with_capacity(d + 1);
        let mut h_pos: Vec<E::G2Affine> = Vec::with_capacity(d + 1);
        let mut h_neg: Vec<E::G2Affine> = Vec::with_capacity(d + 1);

        let mut pow_pos = E::Fr::one();
        let mut x_inv = x.inverse().expect("x must be nonzero");
        let mut pow_neg = E::Fr::one();

        for _ in 0..=d {
            // G1
            let mut p1 = E::G1::one();
            p1.mul_assign(pow_pos);
            g_pos.push(p1.into_affine());

            let mut n1 = E::G1::one();
            n1.mul_assign(pow_neg);
            g_neg.push(n1.into_affine());

            // G2
            let mut p2 = E::G2::one();
            p2.mul_assign(pow_pos);
            h_pos.push(p2.into_affine());

            let mut n2 = E::G2::one();
            n2.mul_assign(pow_neg);
            h_neg.push(n2.into_affine());

            pow_pos.mul_assign(&x);
            pow_neg.mul_assign(&x_inv);
        }

        // 3) Compute α-shifted tables
        let mut g_pos_alpha: Vec<E::G1Affine> = Vec::with_capacity(d);
        let mut g_neg_alpha: Vec<E::G1Affine> = Vec::with_capacity(d);
        for i in 0..d {
            let mut gp = g_pos[i].into_projective();
            gp.mul_assign(alpha);
            g_pos_alpha.push(gp.into_affine());

            let mut gn = g_neg[i].into_projective();
            gn.mul_assign(alpha);
            g_neg_alpha.push(gn.into_affine());
        }

        let mut h_pos_alpha: Vec<E::G2Affine> = Vec::with_capacity(d + 1);
        let mut h_neg_alpha: Vec<E::G2Affine> = Vec::with_capacity(d + 1);
        for i in 0..=d {
            let mut hp = h_pos[i].into_projective();
            hp.mul_assign(alpha);
            h_pos_alpha.push(hp.into_affine());

            let mut hn = h_neg[i].into_projective();
            hn.mul_assign(alpha);
            h_neg_alpha.push(hn.into_affine());
        }

        SRS {
            d,
            g_negative_x:       g_neg,
            g_positive_x:       g_pos,
            h_negative_x:       h_neg,
            h_positive_x:       h_pos,
            g_negative_x_alpha: g_neg_alpha,
            g_positive_x_alpha: g_pos_alpha,
            h_negative_x_alpha: h_neg_alpha,
            h_positive_x_alpha: h_pos_alpha,
            cpk:                pk_sig,
            pk,
        }
    }

    /// Serialize into any writer.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.d.to_le_bytes())?;
        write_g1_vec::<E, _>(w, &self.g_negative_x)?;
        write_g1_vec::<E, _>(w, &self.g_positive_x)?;
        write_g2_vec::<E, _>(w, &self.h_negative_x)?;
        write_g2_vec::<E, _>(w, &self.h_positive_x)?;
        write_g1_vec::<E, _>(w, &self.g_negative_x_alpha)?;
        write_g1_vec::<E, _>(w, &self.g_positive_x_alpha)?;
        write_g2_vec::<E, _>(w, &self.h_negative_x_alpha)?;
        write_g2_vec::<E, _>(w, &self.h_positive_x_alpha)?;
        w.write_all(&self.cpk.to_bytes())?;
        let pa: JubJubAffine = self.pk.0.into();
        w.write_all(&pa.to_bytes())?;
        Ok(())
    }

    /// Fast file write (mmap fallback on Unix).
    pub fn write_to_file(&self, path: &PathBuf) -> io::Result<()> {
        let mut buf = Vec::new();
        self.write(&mut buf)?;
        std::fs::write(path, &buf)
    }

    /// Fast file read: mmap + madvise on Unix.
    pub fn read_from_file(path: &PathBuf) -> io::Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { MmapOptions::new().populate().map(&file)? };
        #[cfg(unix)]
        unsafe {
            libc::madvise(mmap.as_ptr() as *mut _, mmap.len(), libc::MADV_WILLNEED);
        }
        let mut cursor = Cursor::new(&mmap[..]);
        SRS::read(&mut cursor).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Deserialize from any reader.
    pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
        let mut d_bytes = [0u8; 8];
        r.read_exact(&mut d_bytes)?;
        let d = usize::from_le_bytes(d_bytes);

        let g_negative_x       = read_g1_vec::<E, _>(r)?;
        let g_positive_x       = read_g1_vec::<E, _>(r)?;
        let h_negative_x       = read_g2_vec::<E, _>(r)?;
        let h_positive_x       = read_g2_vec::<E, _>(r)?;
        let g_negative_x_alpha = read_g1_vec::<E, _>(r)?;
        let g_positive_x_alpha = read_g1_vec::<E, _>(r)?;
        let h_negative_x_alpha = read_g2_vec::<E, _>(r)?;
        let h_positive_x_alpha = read_g2_vec::<E, _>(r)?;

        let mut cpk_bytes = [0u8; 32];
        r.read_exact(&mut cpk_bytes)?;
        let cpk = SigPK::from_bytes(&cpk_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;

        let mut pk_bytes = [0u8; 32];
        r.read_exact(&mut pk_bytes)?;
        let pa = <JubJubAffine as Serializable<32>>::from_bytes(&pk_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
        let pk = EncPK(JubJubExtended::from(pa));

        Ok(SRS {
            d,
            g_negative_x,
            g_positive_x,
            h_negative_x,
            h_positive_x,
            g_negative_x_alpha,
            g_positive_x_alpha,
            h_negative_x_alpha,
            h_positive_x_alpha,
            cpk,
            pk,
        })
    }
}

// ———— helpers ————

fn write_g1_vec<E: Engine, W: Write>(w: &mut W, v: &[E::G1Affine]) -> io::Result<()> {
    w.write_all(&(v.len() as u64).to_le_bytes())?;
    for p in v {
        w.write_all(p.into_compressed().as_ref())?;
    }
    Ok(())
}

fn write_g2_vec<E: Engine, W: Write>(w: &mut W, v: &[E::G2Affine]) -> io::Result<()> {
    w.write_all(&(v.len() as u64).to_le_bytes())?;
    for p in v {
        w.write_all(p.into_compressed().as_ref())?;
    }
    Ok(())
}

fn read_g1_vec<E: Engine, R: Read>(r: &mut R) -> io::Result<Vec<E::G1Affine>> {
    let mut len_bytes = [0u8; 8];
    r.read_exact(&mut len_bytes)?;
    let len = u64::from_le_bytes(len_bytes) as usize;

    let comp_size = <E::G1Affine as CurveAffine>::Compressed::size();
    let mut all = vec![0u8; len * comp_size];
    r.read_exact(&mut all)?;

    Ok(all
        .par_chunks(comp_size)
        .map(|chunk| {
            let mut c = <E::G1Affine as CurveAffine>::Compressed::empty();
            c.as_mut().copy_from_slice(chunk);
            c.into_affine().unwrap()
        })
        .collect())
}

fn read_g2_vec<E: Engine, R: Read>(r: &mut R) -> io::Result<Vec<E::G2Affine>> {
    let mut len_bytes = [0u8; 8];
    r.read_exact(&mut len_bytes)?;
    let len = u64::from_le_bytes(len_bytes) as usize;

    let comp_size = <E::G2Affine as CurveAffine>::Compressed::size();
    let mut all = vec![0u8; len * comp_size];
    r.read_exact(&mut all)?;

    Ok(all
        .par_chunks(comp_size)
        .map(|chunk| {
            let mut c = <E::G2Affine as CurveAffine>::Compressed::empty();
            c.as_mut().copy_from_slice(chunk);
            c.into_affine().unwrap()
        })
        .collect())
}

// ———— Serde glue ————

impl<E: Engine> serde::Serialize for SRS<E> {
    fn serialize<S_>(&self, ser: S_) -> Result<S_::Ok, S_::Error>
    where S_: serde::Serializer
    {
        let mut buf = Vec::new();
        self.write(&mut buf).map_err(serde::ser::Error::custom)?;
        ser.serialize_bytes(&buf)
    }
}

impl<'de, E: Engine> serde::Deserialize<'de> for SRS<E> {
    fn deserialize<D_>(de: D_) -> Result<Self, D_::Error>
    where D_: serde::Deserializer<'de>
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(de)?;
        let mut cur = Cursor::new(bytes);
        SRS::read(&mut cur).map_err(serde::de::Error::custom)
    }
}
