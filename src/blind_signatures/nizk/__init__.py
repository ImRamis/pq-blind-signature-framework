"""
Non-Interactive Zero-Knowledge (NIZK) Proof System Module.

This package provides an abstraction layer for generating and verifying
NIZK proofs, which are essential for the Fischlin blind signature scheme.
"""

from .nizk import NIZK, NIZKStatement, NIZKWitness, NIZKProof

__all__ = [
    'NIZK',
    'NIZKStatement',
    'NIZKWitness',
    'NIZKProof'
]