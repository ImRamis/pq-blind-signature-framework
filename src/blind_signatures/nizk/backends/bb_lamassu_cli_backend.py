"""
A ZK-SNARK backend that communicates with the compiled Rust CLI for BB-Lamassu.
"""
import subprocess
import json
import tempfile
import os
from typing import Dict, Any, List, Tuple

from .base import ZKBackend, ZKProof
from ... import config

class BBLamassuCliBackend(ZKBackend):
    """
    Implements the ZKBackend interface by calling the `sonic-cli` executable
    to generate and verify proofs.
    """

    def __init__(self):
        cli_path = config.SONIC_UCSE_CLI_PATH
        if not os.path.exists(cli_path):
            raise FileNotFoundError(
                f"sonic-ucse CLI not found at path: {cli_path}. "
                "Please set SONIC_UCSE_CLI_PATH in your .env file."
            )
        self.cli_path = cli_path
        self.srs_path_real = config.PROJECT_ROOT / "srs_sonic_ucse_real.bin"
        self.srs_path_dummy = config.PROJECT_ROOT / "srs_sonic_ucse_dummy.bin"
        self._current_srs_path = None

    def _run_command(self, command_args: List[str]) -> subprocess.CompletedProcess:
        """Executes a shell command and raises an error if it fails."""
        try:
            print(f"[Rust CLI Command]: {' '.join([self.cli_path] + command_args)}")
            result = subprocess.run(
                [self.cli_path] + command_args,
                check=True, capture_output=True, text=True
            )
            if result.stdout:
                print(f"[Rust CLI STDOUT]:\n{result.stdout}")
            if result.stderr:
                print(f"[Rust CLI STDERR]:\n{result.stderr}")
            return result
        except subprocess.CalledProcessError as e:
            print(f"Error running sonic-ucse CLI command: {' '.join(e.cmd)}")
            print(f"STDOUT: {e.stdout}")
            print(f"STDERR: {e.stderr}")
            raise

    def setup_keys(self, circuit_name: str, **kwargs: Any) -> Dict[str, str]:
        """
        Ensures the appropriate SRS exists based on the .env configuration.
        """
        use_dummy = config.SONIC_UCSE_USE_DUMMY_SRS
        self._current_srs_path = self.srs_path_dummy if use_dummy else self.srs_path_real

        if not self._current_srs_path.exists():
            print(f"[sonic-ucse Backend] SRS not found at {self._current_srs_path}. Generating a new one...")
            
            command = ["setup", "--srs-path", str(self._current_srs_path)]
            if use_dummy:
                command.extend(["--dummy", "--preimage-bits", str(config.SONIC_UCSE_DUMMY_PREIMAGE_BITS)])
            else:
                command.extend(["--degree", str(config.SONIC_UCSE_REAL_SRS_DEGREE)])
            
            self._run_command(command)
        else:
            print(f"[sonic-ucse Backend] Using existing SRS at {self._current_srs_path}")

        # Write dummy placeholder files for framework compatibility
        vkey_path = config.KEYS_DIR / f"{circuit_name}_sonic-ucse_vkey.json"
        if not vkey_path.exists():
            os.makedirs(config.KEYS_DIR, exist_ok=True)
            with open(vkey_path, 'w') as f:
                json.dump({"protocol": "sonic-ucse", "srs_path": str(self._current_srs_path)}, f)
        
        pkey_path = config.KEYS_DIR / f"{circuit_name}_sonic-ucse.zkey"
        if not pkey_path.exists():
            pkey_path.touch()

        return {
            "verification_key": str(vkey_path),
            "proving_key": str(pkey_path)
        }

    def generate_proof(self, circuit_name: str, inputs: Dict[str, Any]) -> Tuple[ZKProof, List[str]]:
        """Generates a proof using the Rust CLI based on global config."""
        if self._current_srs_path is None:
            raise RuntimeError("SRS path not set. Please call setup_keys first.")
        
        witness = {"preimage": inputs["message_bits"]}

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".json") as witness_file, \
             tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as proof_file:
            
            witness_path = witness_file.name
            proof_path = proof_file.name
            json.dump(witness, witness_file)
        
        try:
            self._run_command([
                "prove",
                "--scheme", config.SONIC_UCSE_SCHEME,
                "--circuit", config.SONIC_UCSE_CIRCUIT,
                "--srs-path", str(self._current_srs_path),
                "--witness-path", witness_path,
                "--proof-path", proof_path,
            ])

            with open(proof_path, 'rb') as f:
                proof_data_bytes = f.read()

        finally:
            os.remove(witness_path)
            os.remove(proof_path)

        return ZKProof(proof_data={"raw_proof": proof_data_bytes.hex()}, protocol="sonic-ucse"), []

    def verify_proof(self, circuit_name: str, proof: ZKProof, public_signals: List[str]) -> bool:
        """Verifies a proof using the Rust CLI."""
        if self._current_srs_path is None:
            raise RuntimeError("SRS path not set. Please call setup_keys first.")
            
        if proof.protocol != "sonic-ucse":
            raise ValueError("Proof was not generated by the sonic-ucse backend.")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as proof_file:
            proof_path = proof_file.name
            proof_data_bytes = bytes.fromhex(proof.proof_data["raw_proof"])
            proof_file.write(proof_data_bytes)
        
        try:
            # The verify command reads the scheme and circuit from the proof bundle itself.
            result = self._run_command([
                "verify",
                "--srs-path", str(self._current_srs_path),
                "--proof-path", proof_path,
            ])
            return "Proof is VALID" in result.stdout
        except subprocess.CalledProcessError:
            return False
        finally:
            os.remove(proof_path)