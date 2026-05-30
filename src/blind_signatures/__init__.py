"""
Blind Signatures Library (blind_signatures)

A library providing implementations of modern blind signature schemes
for demonstration and academic use.
"""

__version__ = "1.0.0"

# --- Expose Core Protocol Classes ---
# This allows users to import directly from the library, e.g., `from blind_signatures import FischlinProtocol`
from .core.fischlin_protocol import FischlinBlindSignature
from .core.practical_protocol import KlooReichleWagnerSignature
from .core.hanzlik_protocol import HanzlikNIBS, HanzlikTNIBS

# --- Expose Common Data Structures ---
# These are the shared data types used across the different protocols.
from .common import (
    CRS,
    SignerKeyPair,
    BlindSignatureRequest,
    BlindSignatureResponse,
    UnblindedSignature,
    encode_message
)