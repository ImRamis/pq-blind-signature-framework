# src/blind_signatures/nizk/backends/bb_lamassu_http_backend.py

import os
import uuid
import time
import socket
import atexit
import subprocess
import json
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

import requests

from .base import ZKBackend, ZKProof
from ... import config

class BBLamassuHttpBackend(ZKBackend):
    """
    Communicates with the Rust HTTP server for in-memory BB-Lamassu proofs.
    Honors the `use_dummy` flag: if False, requests a real SRS setup using
    config.BB_LAMASSU_DEGREE; if True, uses dummy with config.BB_LAMASSU_PREIMAGE_BITS.
    Automatically launches the Rust server if not already running.
    """

    def __init__(self, host: str = None, port: int = None):
        self.host = host or config.SONIC_UCSE_HTTP_HOST
        self.port = port or config.SONIC_UCSE_HTTP_PORT
        self.base_url = f"http://{self.host}:{self.port}"
        self._srs_id: Optional[str] = None
        self._ensure_server()

    def _is_running(self) -> bool:
        try:
            with socket.create_connection((self.host, self.port), timeout=0.5):
                return True
        except Exception:
            return False

    def _ensure_server(self):
        if self._is_running():
            return
        
        rust_cli = config.SONIC_UCSE_CLI_PATH
        cmd = [
            rust_cli,
            "--http",
            "--http-host", self.host,
            "--http-port", str(self.port),
        ]
        
        self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        atexit.register(self._proc.kill)
        for _ in range(50):
            if self._is_running():
                return
            time.sleep(0.1)
        raise RuntimeError(f"Failed to start sonic-ucse-cli HTTP server on {self.host}:{self.port}")

    def setup_keys(
        self,
        circuit_name: str,
        **kwargs: Any
    ) -> Dict[str, str]:
        """
        Requests SRS setup over HTTP and writes out placeholder key files.
        """
        req_id = str(uuid.uuid4())
        use_dummy = config.SONIC_UCSE_USE_DUMMY_SRS
        params: Dict[str, str] = {"id": req_id, "dummy": "1" if use_dummy else "0"}

        if use_dummy:
            params["preimage_bits"] = str(config.SONIC_UCSE_DUMMY_PREIMAGE_BITS)
        else:
            params["degree"] = str(config.SONIC_UCSE_REAL_SRS_DEGREE)

        resp = requests.get(f"{self.base_url}/setup_srs", params=params, timeout=120)
        resp.raise_for_status()
        result = resp.json()
        if not result.get("success"):
            raise RuntimeError(f"SRS setup failed: {result}")

        self._srs_id = req_id

        # Write out placeholder key files for compatibility
        keys_dir = Path(config.KEYS_DIR)
        keys_dir.mkdir(parents=True, exist_ok=True)

        vkey_path = keys_dir / f"{circuit_name}_sonic-ucse-http_vkey.json"
        pkey_path = keys_dir / f"{circuit_name}_sonic-ucse-http.zkey"

        with open(vkey_path, "w") as f:
            json.dump({
                "protocol":      "sonic-ucse-http",
                "srs_id":        req_id,
                "host":          self.host,
                "port":          self.port,
            }, f, indent=2)

        pkey_path.touch()
        return {
            "verification_key": str(vkey_path),
            "proving_key":      str(pkey_path)
        }

    def generate_proof(
        self,
        circuit_name: str,
        inputs: Dict[str, Any]
    ) -> Tuple[ZKProof, List[str]]:
        """
        Requests a proof for the given inputs using the configured scheme and circuit.
        """
        if self._srs_id is None:
            raise RuntimeError("No SRS has been set up. Call setup_keys() first.")
        
        raw = inputs.get("message_bits")
        if raw is None:
            raise RuntimeError("Missing 'message_bits' in inputs for proof generation")
        
        # Ensure witness is a list of booleans
        if isinstance(raw, list):
            witness_bits = raw
        elif isinstance(raw, str):
            sanitized = raw.replace("True", "true").replace("False", "false")
            witness_bits = json.loads(sanitized)
        else:
            raise RuntimeError(f"Unsupported type for message_bits: {type(raw)}")
        params = {
            "id":      self._srs_id,
            "scheme":  config.SONIC_UCSE_SCHEME,
            "circuit": config.SONIC_UCSE_CIRCUIT
        }
        body = {"witness": witness_bits}

        resp = requests.post(
            f"{self.base_url}/prove",
            params=params,
            json=body,
            timeout=120
        )
        resp.raise_for_status()
        data = resp.json()
        if "proof" not in data:
            raise RuntimeError(f"Proof generation failed: {data}")

        return ZKProof(proof_data={"raw": data["proof"]}, protocol="sonic-ucse-http"), []

    def verify_proof(
        self,
        circuit_name: str,
        proof: ZKProof,
        public_signals: List[str]
    ) -> bool:
        """
        Requests proof verification over HTTP.
        """
        if self._srs_id is None:
            raise RuntimeError("No SRS has been set up. Call setup_keys() first.")

        body = {
            "proof":          proof.proof_data["raw"],
            "public_signals": public_signals
        }

        resp = requests.post(
            f"{self.base_url}/verify",
            params={"id": self._srs_id},
            json=body,
            timeout=120
        )
        resp.raise_for_status()
        data = resp.json()
        if "valid" not in data:
            raise RuntimeError(f"Verification failed: {data}")
        return bool(data["valid"])

    def run_aggregate_benchmark(self, circuit_name: str, samples: int) -> Dict[str, float]:
        """
        Triggers the full aggregation benchmark on the Rust server.
        """
        if self._srs_id is None:
            raise RuntimeError("Must call setup_keys before running benchmark.")

        body = {
            "srs_id":       self._srs_id,
            "circuit":      config.SONIC_UCSE_CIRCUIT,
            "witness_bits": config.SONIC_UCSE_DUMMY_PREIMAGE_BITS,
            "samples":      samples
        }
        resp = requests.post(
            f"{self.base_url}/run-aggregate-benchmark",
            json=body,
            timeout=120
        )
        resp.raise_for_status()
        return resp.json()