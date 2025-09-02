# src/blind_signatures/nizk/backends/snarkjs_engine_backend.py

import subprocess
import atexit
import time
import os
from typing import Dict, Any, List, Tuple, Optional

import requests

from .base import ZKBackend, ZKProof
from .snarkjs_cli_setup import SnarkjsCliSetup
from ... import config

SERVER_PROCESS: Optional[subprocess.Popen] = None

def start_prover_server():
    global SERVER_PROCESS
    if SERVER_PROCESS and SERVER_PROCESS.poll() is None:
        return

    server_script = config.SNARK_ENGINE_DIR / "server.js"
    if not server_script.exists():
        raise FileNotFoundError(f"SNARK Engine server script not found at {server_script}")

    env = os.environ.copy()
    env['SNARK_ENGINE_HOST'] = config.SNARKJS_ENGINE_HOST
    env['SNARK_ENGINE_PORT'] = str(config.SNARKJS_ENGINE_PORT)

    SERVER_PROCESS = subprocess.Popen(
        ["node", str(server_script)],
        cwd=str(config.SNARK_ENGINE_DIR),
        env=env,
    )
    atexit.register(lambda: SERVER_PROCESS.terminate())

    # Wait for the server to be healthy
    for _ in range(10):
        try:
            url = f"http://{config.SNARKJS_ENGINE_HOST}:{config.SNARKJS_ENGINE_PORT}/health"
            resp = requests.get(url, timeout=1)
            if resp.ok:
                return
        except requests.exceptions.RequestException:
            time.sleep(0.5)

    raise RuntimeError("Could not connect to the SNARK Engine server after multiple attempts.")

class SnarkjsEngineBackend(ZKBackend):
    def __init__(self):
        start_prover_server()
        self.base_url = f"http://{config.SNARKJS_ENGINE_HOST}:{config.SNARKJS_ENGINE_PORT}"

    def setup_keys(self, circuit_name: str, **kwargs: Any) -> Dict[str, str]:
        return SnarkjsCliSetup().setup_keys(circuit_name, config.SNARKJS_PROOF_SYSTEM)

    def _post_request(self, endpoint: str, payload: dict) -> dict:
        try:
            resp = requests.post(f"{self.base_url}{endpoint}", json=payload, timeout=60)
            resp.raise_for_status()
            result = resp.json()
            if not result.get("success", False):
                raise RuntimeError(f"SNARK Engine server error: {result.get('error')}")
            return result
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Failed to communicate with SNARK Engine: {e}")

    def generate_proof(self, circuit_name: str, inputs: Dict[str, Any]) -> Tuple[ZKProof, List[str]]:
        """
        Forward the exact scalar inputs from your protocol to the Circom circuit;
        no scalar→point conversion or legacy‐interface mixing.
        """
        payload = {
            "algorithm":   config.SNARKJS_PROOF_SYSTEM,
            "action":      "prove",
            "circuitName": circuit_name,
            "inputs":      inputs,
        }
        result = self._post_request("/zk", payload)
        proof = ZKProof.deserialize(result["proof"], protocol=config.SNARKJS_PROOF_SYSTEM)
        return proof, result["publicSignals"]

    def verify_proof(self, circuit_name: str, proof: ZKProof, public_signals: List[str]) -> bool:
        if proof.protocol != config.SNARKJS_PROOF_SYSTEM:
            raise ValueError(
                f"Proof protocol '{proof.protocol}' does not match configured '{config.SNARKJS_PROOF_SYSTEM}'"
            )
        payload = {
            "algorithm":     config.SNARKJS_PROOF_SYSTEM,
            "action":        "verify",
            "circuitName":   circuit_name,
            "proof":         proof.serialize(),
            "publicSignals": public_signals,
        }
        result = self._post_request("/zk", payload)
        return result.get("isValid", False)

    def calculate_pedersen(self, message: int, randomness: int) -> List[str]:
        payload = {
            "message":    str(message),
            "randomness": str(randomness),
        }
        result = self._post_request("/pedersen", payload)
        return result["commitment"]
