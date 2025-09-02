# src/blind_signatures/crypto/signature.py

import secrets
from typing import Tuple, Dict, Any
from py_ecc.secp256k1 import secp256k1
from ..utils.hash_utils import hash_to_scalar

# BabyJubJub base field prime
_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
# Curve parameters
_A = 168700
_D = 168696
# “BASE8” generator from circomlib
G: Tuple[int,int] = (
    5299619240641551281634865583518297030282874472190772894086521144482721001553,
    16950150798460657717958625567821834550301663161624707787222815936182638968203
)
# Prime‐order subgroup for Schnorr
R = 2736030358979909402780800718157159386076813972158567259200215660948447373041

def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)

def _ed_add(P1: Tuple[int,int], P2: Tuple[int,int]) -> Tuple[int,int]:
    x1, y1 = P1
    x2, y2 = P2
    # twisted‐Edwards addition
    num_x = (x1 * y2 + y1 * x2) % _P
    den_x = (1 + _D * x1 * x2 * y1 * y2) % _P
    x3 = (num_x * _inv(den_x)) % _P

    num_y = (y1 * y2 - _A * x1 * x2) % _P
    den_y = (1 - _D * x1 * x2 * y1 * y2) % _P
    y3 = (num_y * _inv(den_y)) % _P

    return x3, y3

def ed_scalar_mul(point: Tuple[int,int], scalar: int) -> Tuple[int,int]:
    """
    Double‐and‐add scalar multiplication on BabyJubJub subgroup of order R.
    """
    result = (0, 1)  # identity
    addend = (point[0] % _P, point[1] % _P)
    k = scalar % R
    while k:
        if k & 1:
            result = _ed_add(result, addend)
        addend = _ed_add(addend, addend)
        k >>= 1
    return result

class SchnorrSignature:
    """
    Implements Schnorr signatures over the BabyJubJub curve to match the Circom circuit.
    - Challenge `e = H(R, pk, m)`
    - Response `s = k + e * sk`
    """

    def __init__(self):
        self.g = G
        self.order = R

    def keygen(self) -> Tuple[int, Tuple[int, int]]:
        """Generates a Schnorr key pair (sk, vk = g^sk) on BabyJubJub."""
        sk = secrets.randbelow(self.order)
        vk = ed_scalar_mul(self.g, sk)
        return sk, vk

    def sign(self, signing_key: int, message: bytes) -> Dict[str, any]:
        """Signs a message using the signing key on BabyJubJub."""
        k = secrets.randbelow(self.order)
        R_point = ed_scalar_mul(self.g, k)
        
        # Re-derive verification key for the hash, as it's not stored in the signer object
        verification_key = ed_scalar_mul(self.g, signing_key)

        # Generate challenge using domain-separated hash, modulo the BabyJubJub order
        e = hash_to_scalar(b"Schnorr-Challenge", self.order, R_point, verification_key, message)

        s = (k + e * signing_key) % self.order
        return {'R': R_point, 's': s, 'k': k, 'e': e}

    def verify(self, verification_key: Tuple[int, int],
               message: bytes, signature: Dict[str, any]) -> bool:
        """Verifies a BabyJubJub-based Schnorr signature."""
        R_point = tuple(signature['R'])
        s = signature['s']

        # Re-compute the same domain-separated hash, modulo the BabyJubJub order
        e = hash_to_scalar(b"Schnorr-Challenge", self.order, R_point, verification_key, message)

        # Check the Schnorr equation on BabyJubJub: g^s == R + vk^e
        gs = ed_scalar_mul(self.g, s)
        vke = ed_scalar_mul(verification_key, e)
        R_plus_vke = _ed_add(R_point, vke)

        return gs == R_plus_vke