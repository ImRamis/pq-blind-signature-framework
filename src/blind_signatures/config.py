"""
Central configuration for the blind signature project.
Loads settings from a .env file and defines key project paths.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from a .env file in the project root
PROJECT_ROOT = Path(__file__).parent.parent.parent.resolve()
load_dotenv(dotenv_path=PROJECT_ROOT / '.env')

# --- Primary Backend Selection ---
ZK_BACKEND = os.getenv('ZK_BACKEND', 'snarkjs').lower()

# --- SNARKJS Backend Settings ---
SNARKJS_PROOF_SYSTEM = os.getenv('SNARKJS_PROOF_SYSTEM', 'groth16').lower()
SNARKJS_ENGINE_HOST = os.getenv('SNARKJS_ENGINE_HOST', '127.0.0.1')
SNARKJS_ENGINE_PORT = int(os.getenv('SNARK_ENGINE_PORT', 4001))

# --- SONIC-UCSE (Rust) Backend Settings ---
SONIC_UCSE_INTERFACE = os.getenv('SONIC_UCSE_INTERFACE', 'http').lower()
SONIC_UCSE_SCHEME = os.getenv('SONIC_UCSE_SCHEME', 'bb-lamassu').lower()
SONIC_UCSE_CIRCUIT = os.getenv('SONIC_UCSE_CIRCUIT', 'pedersen').lower()
SONIC_UCSE_HTTP_HOST = os.getenv('SONIC_UCSE_HTTP_HOST', '127.0.0.1')
SONIC_UCSE_HTTP_PORT = int(os.getenv('SONIC_UCSE_HTTP_PORT', 4000))
SONIC_UCSE_CLI_PATH = os.getenv('SONIC_UCSE_CLI_PATH', 'sonic-cli/sonic-cli')

# SRS Settings
SONIC_UCSE_USE_DUMMY_SRS = os.getenv('SONIC_UCSE_USE_DUMMY_SRS', '1').lower() in ('true', '1')
SONIC_UCSE_DUMMY_PREIMAGE_BITS = int(os.getenv('SONIC_UCSE_DUMMY_PREIMAGE_BITS', 48))
SONIC_UCSE_REAL_SRS_DEGREE = int(os.getenv('SONIC_UCSE_REAL_SRS_DEGREE', 830564))

# --- Common File Paths ---
CIRCUITS_DIR = PROJECT_ROOT / 'circuits'
BUILD_DIR = CIRCUITS_DIR / 'build'
KEYS_DIR = CIRCUITS_DIR / 'keys'
PTAU_FILE = CIRCUITS_DIR / 'powersOfTau28_hez_final_15.ptau'
SNARK_ENGINE_DIR = PROJECT_ROOT / 'snarkjs_engine'


def display_config():
    """Prints the current project configuration in a structured way."""
    print("=" * 70)
    print("Blind Signature Library Configuration:")
    print("-" * 70)
    print(f"  ZK_BACKEND: {ZK_BACKEND.upper()}")
    print("-" * 70)

    if ZK_BACKEND == 'snarkjs':
        print("  snarkjs Settings:")
        print(f"    -> Proof System: {SNARKJS_PROOF_SYSTEM.upper()}")
        print(f"    -> Engine URL:   http://{SNARKJS_ENGINE_HOST}:{SNARKJS_ENGINE_PORT}")
    elif ZK_BACKEND == 'sonic-ucse':
        print("  sonic-ucse (Rust) Settings:")
        print(f"    -> Interface:    {SONIC_UCSE_INTERFACE.upper()}")
        print(f"    -> Scheme:       {SONIC_UCSE_SCHEME.upper()}")
        print(f"    -> Circuit:      {SONIC_UCSE_CIRCUIT.upper()}")
        if SONIC_UCSE_INTERFACE == 'http':
            print(f"    -> Server URL:   http://{SONIC_UCSE_HTTP_HOST}:{SONIC_UCSE_HTTP_PORT}")
        else:
            print(f"    -> CLI Path:     {SONIC_UCSE_CLI_PATH}")
        print("    SRS Settings:")
        print(f"      -> Use Dummy:    {SONIC_UCSE_USE_DUMMY_SRS}")
        if SONIC_UCSE_USE_DUMMY_SRS:
            print(f"      -> Dummy Bits:   {SONIC_UCSE_DUMMY_PREIMAGE_BITS}")
        else:
            print(f"      -> Real Degree:  {SONIC_UCSE_REAL_SRS_DEGREE}")
    else:
        print("  WARNING: Unknown ZK_BACKEND configured.")

    print("=" * 70)