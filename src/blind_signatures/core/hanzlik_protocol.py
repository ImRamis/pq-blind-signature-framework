"""
Core implementation of the Non-Interactive Blind Signature (NIBS) scheme from
Hanzlik '23, using signatures on equivalence classes (SPS-EQ).
Paper: "Non-Interactive Blind Signatures for Random Messages"
"""

import secrets
from hashlib import sha256
from typing import Tuple, Optional

from py_ecc.optimized_bls12_381 import (
    G1, G2, add, multiply, pairing, curve_order as p
)

class HanzlikNIBS:
    """
    Implements the standard Non-Interactive Blind Signature scheme (NIBS).
    This corresponds to Scheme 3 in the Hanzlik '23 paper.
    It uses a standard Signature on Equivalence Classes (SPS-EQ).
    """
    def __init__(self):
        self.order = p
        self.g1 = G1
        self.g2 = G2

    def keygen(self) -> Tuple[Tuple[int, int], Tuple[Tuple, Tuple]]:
        """Generates the signer's key pair (sk, pk) for the SPS-EQ scheme."""
        x1 = secrets.randbelow(self.order)
        x2 = secrets.randbelow(self.order)
        pk1 = multiply(self.g2, x1)
        pk2 = multiply(self.g2, x2)
        return (x1, x2), (pk1, pk2)

    def rkeygen(self) -> Tuple[int, Tuple]:
        """Generates the recipient's key pair (skR, pkR)."""
        skR = secrets.randbelow(self.order)
        pkR = multiply(self.g1, skR)
        return skR, pkR

    def _hash_to_g1(self, data: bytes, domain_separator: bytes) -> Tuple:
        """
        Hashes data to a point in G1 using a domain-separated hash.
        NOTE: For demonstration purposes using SHA256. A production system should
        use a standardized hash-to-curve algorithm.
        """
        hash_input = domain_separator + data
        h = int.from_bytes(sha256(hash_input).digest(), 'big') % self.order
        return multiply(self.g1, h)

    def issue(self, sk: Tuple[int, int], pkR: Tuple, nonce: bytes) -> Tuple[Tuple, Tuple, Tuple]:
        """
        Issues a presignature (psig) on (pkR, H(nonce)).
        This implements Sign_EQ from Scheme 1 of the paper.
        """
        x1, x2 = sk
        M1 = pkR
        M2 = self._hash_to_g1(nonce, b"HanzlikNIBS-M2-V1.0")
        
        y = secrets.randbelow(self.order)
        if y == 0: y = 1

        y_inv = pow(y, -1, self.order)

        base = add(multiply(M1, x1), multiply(M2, x2))
        Z1 = multiply(base, y)
        
        Y1 = multiply(self.g1, y_inv)
        Y2 = multiply(self.g2, y_inv)

        return Z1, Y1, Y2

    def _verify_sps_eq(self, pk: Tuple[Tuple, Tuple], M: Tuple[Tuple, Tuple],
                       sig: Tuple[Tuple, Tuple, Tuple]) -> bool:
        """Verifies an SPS-EQ signature, implementing Verify_EQ from Scheme 1."""
        pk1, pk2 = pk
        M1, M2 = M
        Z1, Y1, Y2 = sig

        # Check: e(M1, pk1) * e(M2, pk2) = e(Z1, Y2)
        lhs1 = pairing(pk1, M1) * pairing(pk2, M2)
        rhs1 = pairing(Y2, Z1)
        if lhs1 != rhs1:
            return False

        # Check: e(Y1, g2) = e(g1, Y2)
        lhs2 = pairing(self.g2, Y1)
        rhs2 = pairing(Y2, self.g1)
        return lhs2 == rhs2

    def obtain(self, skR: int, pk: Tuple[Tuple, Tuple], psig: Tuple[Tuple, Tuple, Tuple],
               nonce: bytes) -> Optional[Tuple[Tuple, Tuple]]:
        """
        Transforms the presignature into a final signature on a random message 'm'.
        This implements ChgRep_EQ from Scheme 1.
        """
        pkR = multiply(self.g1, skR)
        M2 = self._hash_to_g1(nonce, b"HanzlikNIBS-M2-V1.0")

        if not self._verify_sps_eq(pk, (pkR, M2), psig):
            return None

        # Change of representation logic
        μ = pow(skR, -1, self.order)
        ψ = secrets.randbelow(self.order)
        if ψ == 0: ψ = 1
        psi_inv = pow(ψ, -1, self.order)

        Z1, Y1, Y2 = psig
        Z1p = multiply(Z1, (ψ * μ) % self.order)
        Y1p = multiply(Y1, psi_inv)
        Y2p = multiply(Y2, psi_inv)
        
        final_sig = (Z1p, Y1p, Y2p)
        m = multiply(M2, μ) # The random message

        return m, final_sig

    def verify(self, pk: Tuple[Tuple, Tuple], m: Tuple,
               sig: Tuple[Tuple, Tuple, Tuple]) -> bool:
        """Verifies the final message-signature pair (m, sig)."""
        return self._verify_sps_eq(pk, (self.g1, m), sig)


class HanzlikTNIBS:
    """
    Implements the Tagged Non-Interactive Blind Signature scheme (TNIBS).
    This corresponds to Scheme 4 in the Hanzlik '23 paper.
    It uses a Tag-Based Signature on Equivalence Classes (TBEQ).
    """
    def __init__(self):
        self.order = p
        self.g1 = G1
        self.g2 = G2

    def keygen(self) -> Tuple[Tuple[int, int], Tuple[Tuple, Tuple]]:
        """Generates the signer's key pair (sk, pk) for the TBEQ scheme."""
        x1 = secrets.randbelow(self.order)
        x2 = secrets.randbelow(self.order)
        pk1 = multiply(self.g2, x1)
        pk2 = multiply(self.g2, x2)
        return (x1, x2), (pk1, pk2)

    def rkeygen(self) -> Tuple[int, Tuple]:
        """Generates the recipient's key pair (skR, pkR)."""
        skR = secrets.randbelow(self.order)
        pkR = multiply(self.g1, skR)
        return skR, pkR

    def _hash_to_g1(self, data: bytes, domain_separator: bytes) -> Tuple:
        """Hashes data to a point in G1."""
        hash_input = domain_separator + data
        h = int.from_bytes(sha256(hash_input).digest(), 'big') % self.order
        return multiply(self.g1, h)

    def _hash_to_g2(self, data: bytes, domain_separator: bytes) -> Tuple:
        """Hashes data to a point in G2."""
        hash_input = domain_separator + data
        h = int.from_bytes(sha256(hash_input).digest(), 'big') % self.order
        return multiply(self.g2, h)

    def issue(self, sk: Tuple[int, int], pkR: Tuple, nonce: bytes, tag: bytes) -> Tuple[Tuple, Tuple, Tuple, Tuple]:
        """
        Issues a tagged presignature on (pkR, H(nonce)) with tag τ.
        This implements Sign_TEQ from Scheme 2 of the paper.
        """
        x1, x2 = sk
        M1 = pkR
        M2 = self._hash_to_g1(nonce, b"HanzlikTNIBS-M2-V1.0")
        
        y = secrets.randbelow(self.order)
        if y == 0: y = 1
        y_inv = pow(y, -1, self.order)

        base = add(multiply(M1, x1), multiply(M2, x2))
        Z1 = multiply(base, y)
        Y1 = multiply(self.g1, y_inv)
        Y2 = multiply(self.g2, y_inv)
        # New component for the tag, requires hashing to G2
        V2 = multiply(self._hash_to_g2(tag, b"HanzlikTNIBS-Tag-V1.0"), y_inv)

        return Z1, Y1, Y2, V2

    def _verify_tbeq(self, pk: Tuple[Tuple, Tuple], M: Tuple[Tuple, Tuple], tag: bytes,
                        sig: Tuple[Tuple, Tuple, Tuple, Tuple]) -> bool:
        """Verifies a TBEQ signature, implementing Verify_TEQ from Scheme 2."""
        pk1, pk2 = pk
        M1, M2 = M
        Z1, Y1, Y2, V2 = sig

        # Check 1: e(M1, pk1) * e(M2, pk2) = e(Z1, Y2)
        lhs1 = pairing(pk1, M1) * pairing(pk2, M2)
        rhs1 = pairing(Y2, Z1)
        if lhs1 != rhs1:
            return False

        # Check 2: e(Y1, g2) = e(g1, Y2)
        lhs2 = pairing(self.g2, Y1)
        rhs2 = pairing(Y2, self.g1)
        if lhs2 != rhs2:
            return False

        # Check 3 (Tag check): e(g1, V2) = e(Y1, H(τ))
        # This check requires H(τ) to be a G2 element for the pairing to be valid.
        H_tag = self._hash_to_g2(tag, b"HanzlikTNIBS-Tag-V1.0")
        lhs3 = pairing(V2, self.g1)
        rhs3 = pairing(H_tag, Y1)
        return lhs3 == rhs3

    def obtain(self, skR: int, pk: Tuple[Tuple, Tuple], psig: Tuple, nonce: bytes, tag: bytes) -> Optional[Tuple[Tuple, Tuple]]:
        """
        Transforms the tagged presignature into a final signature.
        This implements ChgRep_TEQ from Scheme 2.
        """
        pkR = multiply(self.g1, skR)
        M2 = self._hash_to_g1(nonce, b"HanzlikTNIBS-M2-V1.0")

        if not self._verify_tbeq(pk, (pkR, M2), tag, psig):
            return None

        # Change of representation logic
        μ = pow(skR, -1, self.order)
        ψ = secrets.randbelow(self.order)
        if ψ == 0: ψ = 1
        psi_inv = pow(ψ, -1, self.order)

        Z1, Y1, Y2, V2 = psig
        Z1p = multiply(Z1, (ψ * μ) % self.order)
        Y1p = multiply(Y1, psi_inv)
        Y2p = multiply(Y2, psi_inv)
        V2p = multiply(V2, psi_inv)
        
        final_sig = (Z1p, Y1p, Y2p, V2p)
        m = multiply(M2, μ)

        return m, final_sig

    def verify(self, pk: Tuple[Tuple, Tuple], m: Tuple, tag: bytes,
               sig: Tuple) -> bool:
        """Verifies the final tagged message-signature pair."""
        return self._verify_tbeq(pk, (self.g1, m), tag, sig)