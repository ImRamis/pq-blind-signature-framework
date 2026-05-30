"""
ElGamal Encryption Scheme Implementation.

This module provides an ElGamal-like encryption scheme over the secp256k1 curve.
It is enhanced with an authentication tag derived from the ciphertext and a label
to provide integrity and resistance against chosen-ciphertext attacks (IND-CCA2).

Paper Reference (Fischlin): Section 3.2 - Encryption Schemes
"""

import secrets
import json
from typing import Tuple, Dict, Any
from hashlib import sha256
from py_ecc.secp256k1 import secp256k1

class ElGamalEncryption:
    """
    Implements an authenticated ElGamal encryption scheme.
    """

    def __init__(self):
        self.g = secp256k1.G
        self.order = secp256k1.N

    def keygen(self) -> Tuple[int, Tuple[int, int]]:
        """Generates an ElGamal key pair (sk, pk = g^sk)."""
        sk = secrets.randbelow(self.order)
        pk = secp256k1.multiply(self.g, sk)
        return sk, pk

    def encrypt(self, public_key: Tuple[int, int], message: int,
                label: bytes = b"") -> Dict[str, Any]:
        """
        Encrypts a message and generates an authentication tag.
        Ciphertext = {c1: g^r, c2: m XOR H(pk^r, label), tag: H(c1, c2, label)}
        """
        r = secrets.randbelow(self.order)
        c1 = secp256k1.multiply(self.g, r)
        shared_secret_point = secp256k1.multiply(public_key, r)

        # Derive a symmetric key from the shared secret and label
        key_material = str(shared_secret_point).encode() + label
        symmetric_key = int.from_bytes(sha256(key_material).digest(), 'big')
        c2 = message ^ symmetric_key

        # Create an authentication tag
        auth_input = json.dumps({'c1': str(c1), 'c2': str(c2), 'label': label.hex()}, sort_keys=True).encode()
        auth_tag = sha256(auth_input).hexdigest()

        return {
            'c1': c1,
            'c2': c2,
            'auth_tag': auth_tag,
            'label': label.hex()
        }

    def decrypt(self, secret_key: int, ciphertext: Dict[str, Any]) -> int:
        """Verifies the auth tag and decrypts the ciphertext."""
        c1 = tuple(ciphertext['c1'])
        c2 = ciphertext['c2']
        auth_tag = ciphertext['auth_tag']
        label = bytes.fromhex(ciphertext['label'])

        # 1. Verify authentication tag to ensure integrity (CCA2 security)
        expected_auth_input = json.dumps({'c1': str(c1), 'c2': str(c2), 'label': label.hex()}, sort_keys=True).encode()
        expected_tag = sha256(expected_auth_input).hexdigest()
        if auth_tag != expected_tag:
            raise ValueError("Invalid ciphertext: authentication tag mismatch.")

        # 2. Decrypt if authentic
        shared_secret_point = secp256k1.multiply(c1, secret_key)
        key_material = str(shared_secret_point).encode() + label
        symmetric_key = int.from_bytes(sha256(key_material).digest(), 'big')
        message = c2 ^ symmetric_key

        return message