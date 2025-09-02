"""
Common data structures and utilities shared across the blind signature schemes.
"""

from dataclasses import dataclass, asdict
from typing import Dict, Any, Tuple, Optional
from enum import Enum
import json
from hashlib import sha256

class ProtocolPhase(Enum):
    SETUP = "setup"
    REQUEST = "request"
    ISSUE = "issue"
    UNBLIND = "unblind"
    VERIFY = "verify"

@dataclass
class CRS:
    """Common Reference String for a protocol."""
    commitment_params: Dict[str, Any]
    encryption_params: Dict[str, Any]
    signature_params: Dict[str, Any]
    nizk_params: Dict[str, Any]
    
    def serialize(self) -> str:
        return json.dumps(asdict(self), default=str)

@dataclass
class SignerKeyPair:
    """Signer's key pair for the Fischlin blind signature scheme."""
    signing_key: int
    verification_key: Tuple[int, int]
    encryption_key: Tuple[int, int]
    decryption_key: int

@dataclass
class BlindSignatureRequest:
    """A user's request for a blind signature."""
    encrypted_message: Dict[str, Any]
    commitment: Tuple[int, int]
    proof: Any
    user_public_key: Optional[Tuple[int, int]] = None
    
@dataclass
class BlindSignatureResponse:
    """A signer's response containing a blind signature."""
    encrypted_signature: Dict[str, Any]
    proof: Any

@dataclass
class UnblindedSignature:
    """The final, unblinded signature that can be verified."""
    signature: Dict[str, int]
    message: bytes

def encode_message(message: bytes, modulus: int) -> int:
    """Encodes message bytes to an integer for cryptographic operations."""
    digest = sha256(message).digest()
    return int.from_bytes(digest, 'big') % modulus