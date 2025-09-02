"""
Defines the main interface for the NIZK proof system.
"""

from typing import Dict, Any, List
from dataclasses import dataclass, asdict
import json
from hashlib import sha256

from .prover_factory import get_prover
from .backends.base import ZKProof

@dataclass
class NIZKStatement:
    """Represents the public information (statement) to be proven."""
    public_inputs: Dict[str, Any]
    relation: str

@dataclass
class NIZKWitness:
    """Represents the secret information (witness) for the proof."""
    private_inputs: Dict[str, Any]

@dataclass
class NIZKProof:
    """
    A container for the generated proof and its associated public data.
    It holds the native proof from the backend (e.g., snarkjs).
    """
    proof_data: Dict[str, Any]
    statement: NIZKStatement
    native_proof: ZKProof

    def serialize(self) -> Dict[str, Any]:
        """Serializes the proof for transmission or storage."""
        return {
            "proof_data": self.proof_data,
            "statement": asdict(self.statement),
            "native_proof": self.native_proof.serialize()
        }

class NIZK:
    """
    High-level API for generating and verifying Non-Interactive Zero-Knowledge proofs.
    """
    def __init__(self, security_param: int = 128):
        self.prover = get_prover()
        self.crs: Dict[str, Dict] = {}

    def _get_relation_name(self, circuit_type: str) -> str:
        """Maps a high-level relation name to a specific circuit file name."""
        relation_map = {
            'commitment_encryption_consistency': 'commitment_consistency',
            'signature_decryption_consistency': 'signature_consistency',
        }
        return relation_map.get(circuit_type, circuit_type)

    def setup(self, circuit_type: str, use_dummy: bool = False) -> Dict[str, Any]:
        """
        Sets up the proving and verification keys for a given circuit if not already cached.
        """
        relation = self._get_relation_name(circuit_type)
        # Always re-run setup if dummy mode is requested, to ensure correct SRS is used.
        if relation in self.crs and not use_dummy:
            return self.crs[relation]

        # Delegate key setup to the backend, passing the dummy flag
        key_paths = self.prover.setup_keys(relation, use_dummy=use_dummy)
        with open(key_paths['verification_key'], 'r') as f:
            vkey_data = json.load(f)

        self.crs[relation] = {'vkey': vkey_data, 'type': 'groth16'} # Type is legacy, not strictly used by new backends
        return self.crs[relation]

    def prove(self, statement: NIZKStatement, witness: NIZKWitness) -> NIZKProof:
        """Generates a NIZK proof for the given statement and witness."""
        relation = self._get_relation_name(statement.relation)
        
        circuit_inputs = {k: str(v) for k, v in {**witness.private_inputs, **statement.public_inputs}.items()}
        
        native_proof, public_signals = self.prover.generate_proof(relation, circuit_inputs)
        
        proof_data = {
            'public_signals': public_signals,
            'hash': sha256(json.dumps(statement.public_inputs, sort_keys=True, default=str).encode()).hexdigest()
        }
        return NIZKProof(proof_data, statement, native_proof)

    def verify(self, proof: NIZKProof) -> bool:
        """Verifies a NIZK proof."""
        expected_hash = sha256(json.dumps(proof.statement.public_inputs, sort_keys=True, default=str).encode()).hexdigest()
        if expected_hash != proof.proof_data.get('hash'):
            print("Error: Public inputs have been tampered with.")
            return False
            
        public_inputs_for_verification = proof.proof_data['public_signals']
        relation = self._get_relation_name(proof.statement.relation)
        
        return self.prover.verify_proof(relation, proof.native_proof, public_inputs_for_verification)
