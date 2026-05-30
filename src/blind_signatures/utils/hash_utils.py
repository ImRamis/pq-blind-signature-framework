"""
Cryptographic Hashing Utilities.

This module provides secure, domain-separated hashing functions to prevent
cross-protocol attacks. Using a raw hash function like SHA256 for multiple
cryptographic purposes is insecure without domain separation.

"""
import hashlib
from typing import Any

def domain_separated_hash(domain_separator: bytes, *elements: object) -> bytes:
    """
    Hashes (in SHA-256):
      domain_separator ∥ encode(e1) ∥ encode(e2) ∥ … ∥ encode(en)

    - Scalars (int)        → 32-byte big-endian
    - Group elements       → tuple(int x, int y) → 32B(x) ∥ 32B(y)
    - Nested tuples        → recursively flatten
    - Bytes / bytearrays   → raw bytes
    """
    engine = hashlib.sha256()
    engine.update(domain_separator)

    def _update(elem: object):
        # Nested tuple: flatten
        if isinstance(elem, tuple):
            for sub in elem:
                _update(sub)
        # Scalar in Zq
        elif isinstance(elem, int):
            engine.update(elem.to_bytes(32, 'big'))
        # Raw bytes
        elif isinstance(elem, (bytes, bytearray)):
            engine.update(elem)
        else:
            raise TypeError(f"Cannot hash element of type {type(elem)}")

    for e in elements:
        _update(e)

    return engine.digest()

def hash_to_scalar(domain_separator: bytes, modulus: int, *elements: Any) -> int:
    """
    Hashes a series of elements to a scalar integer within a specified modulus,
    using domain separation.
    """
    digest = domain_separated_hash(domain_separator, *elements)
    return int.from_bytes(digest, 'big') % modulus