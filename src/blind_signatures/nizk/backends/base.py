"""
Abstract base classes for ZK-SNARK backends.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple, List
from dataclasses import dataclass

@dataclass
class ZKProof:
    """
    A generic container for a zero-knowledge proof from any backend.
    """
    proof_data: Dict[str, Any]
    protocol: str

    def serialize(self) -> Dict[str, Any]:
        """Serializes the proof for transmission."""
        return self.proof_data
    
    @classmethod
    def deserialize(cls, data: Dict[str, Any], protocol: str) -> 'ZKProof':
        """Deserializes a proof from a standard format."""
        return cls(proof_data=data, protocol=protocol)

class ZKBackend(ABC):
    """
    An abstract interface for a generic Zero-Knowledge proof backend.
    Any backend used by the library must implement these methods.
    """
    @abstractmethod
    def setup_keys(self, circuit_name: str, **kwargs) -> Dict[str, str]:
        """Sets up the proving and verification keys for a circuit."""
        pass
    
    @abstractmethod
    def generate_proof(self, circuit_name: str, inputs: Dict[str, Any]) -> Tuple[ZKProof, List[str]]:
        """Generates a proof for a given circuit and inputs."""
        pass
    
    @abstractmethod
    def verify_proof(self, circuit_name: str, proof: ZKProof, public_signals: List[str]) -> bool:
        """Verifies a proof against the public signals."""
        pass
