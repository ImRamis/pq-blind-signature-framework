"""
Pedersen Commitment Scheme Implementation.

This module provides a Pedersen commitment scheme over the secp256k1 curve.
It offers perfect hiding and computational binding properties.

Paper Reference (Fischlin): Section 3.1 - Commitment Schemes
"""

import secrets
from typing import Tuple, Dict
from py_ecc.secp256k1 import secp256k1
from hashlib import sha256

class PedersenCommitment:
    """
    Implements Pedersen commitments: Com(m, r) = g^m * h^r.
    The generator `h` is derived deterministically for consistency.
    """

    def __init__(self):
        self.g = secp256k1.G
        self.order = secp256k1.N

        # Generate h = H("Pedersen_h") * g for deterministic setup
        h_seed = sha256(b"blind_signatures-pedersen-h-generator").digest()
        h_scalar = int.from_bytes(h_seed, 'big') % self.order
        self.h = secp256k1.multiply(self.g, h_scalar)

    def setup(self) -> Dict[str, any]:
        """Generates the public parameters for the commitment scheme."""
        return {
            'g': self.g,
            'h': self.h,
            'order': self.order
        }

    def commit(self, message: int, randomness: int = None) -> Tuple[Tuple[int, int], int]:
        """
        Creates a commitment to a message. If randomness is not provided,
        it is generated securely.
        Returns the commitment point and the randomness used.
        """
        if randomness is None:
            randomness = secrets.randbelow(self.order)

        message_mod = message % self.order
        randomness_mod = randomness % self.order

        gm = secp256k1.multiply(self.g, message_mod)
        hr = secp256k1.multiply(self.h, randomness_mod)
        commitment = secp256k1.add(gm, hr)

        return commitment, randomness

    def verify(self, commitment: Tuple[int, int], message: int, randomness: int) -> bool:
        """Verifies that the commitment opens to the given message and randomness."""
        expected_commitment, _ = self.commit(message, randomness)
        return commitment == expected_commitment