"""
A utility class that uses the `snarkjs` and `circom` command-line tools
for the one-time setup of proving and verification keys.
"""
import os
import subprocess
from ... import config

class SnarkjsCliSetup:
    """Wraps CLI commands for compiling circuits and generating keys."""

    def _run_command(self, command_list):
        """Executes a shell command and raises an error if it fails."""
        try:
            subprocess.run(" ".join(command_list), shell=True, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            print(f"Error running command: {' '.join(command_list)}")
            print(f"STDOUT: {e.stdout}")
            print(f"STDERR: {e.stderr}")
            raise

    def _compile_circuit(self, circuit_name: str):
        """Compiles a .circom circuit to .r1cs, .wasm, and .sym formats."""
        r1cs_file = config.BUILD_DIR / circuit_name / f"{circuit_name}.r1cs"
        if r1cs_file.exists():
            return

        print(f"[Setup] Compiling circuit: {circuit_name}...")
        circuit_file = str(config.CIRCUITS_DIR / "blindsig" / f"{circuit_name}.circom")
        output_dir = str(config.BUILD_DIR / circuit_name)
        os.makedirs(output_dir, exist_ok=True)
        
        self._run_command(["circom", circuit_file, "--r1cs", "--wasm", "--sym", "-o", output_dir])

    def setup_keys(self, circuit_name: str, algorithm: str) -> dict:
        """Generates and saves the proving and verification keys for a specific algorithm."""
        self._compile_circuit(circuit_name)
        os.makedirs(config.KEYS_DIR, exist_ok=True)
        
        zkey_path = str(config.KEYS_DIR / f"{circuit_name}_{algorithm}.zkey")
        vkey_path = str(config.KEYS_DIR / f"{circuit_name}_{algorithm}_vkey.json")
        
        if os.path.exists(zkey_path) and os.path.exists(vkey_path):
            return {"proving_key": zkey_path, "verification_key": vkey_path}
            
        r1cs_file = str(config.BUILD_DIR / circuit_name / f"{circuit_name}.r1cs")
        
        print(f"[Setup] Generating final {algorithm} keys for {circuit_name}...")
        self._run_command(["snarkjs", algorithm, "setup", r1cs_file, str(config.PTAU_FILE), zkey_path])

        print(f"[Setup] Exporting verification key...")
        self._run_command(["snarkjs", "zkey", "export", "verificationkey", zkey_path, vkey_path])
        
        return {"proving_key": zkey_path, "verification_key": vkey_path}