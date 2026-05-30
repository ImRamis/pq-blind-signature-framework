"""
Factory for creating ZK-SNARK prover backend instances.
"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import src.blind_signatures.config as config

from .backends.snarkjs_engine_backend import SnarkjsEngineBackend
from .backends.bb_lamassu_cli_backend import BBLamassuCliBackend 
from .backends.bb_lamassu_http_backend import BBLamassuHttpBackend

def get_prover():
    """
    Selects and returns the appropriate ZK prover backend based on the
    global configuration specified in the .env file.
    """
    backend_choice = config.ZK_BACKEND
    
    if backend_choice == 'sonic-ucse':
        interface = config.SONIC_UCSE_INTERFACE
        print(f"[Prover Factory] Using sonic-ucse backend with interface: {interface.upper()}")
        if interface == 'http':
            return BBLamassuHttpBackend()
        elif interface == 'cli':
            return BBLamassuCliBackend()
        else:
            raise ValueError(f"Unsupported SONIC_UCSE_INTERFACE: {interface}")

    elif backend_choice == 'snarkjs':
        print(f"[Prover Factory] Using snarkjs (Node.js Engine) backend with system: {config.SNARKJS_PROOF_SYSTEM.upper()}")
        return SnarkjsEngineBackend()
        
    else:
        raise ValueError(f"Unsupported ZK_BACKEND: {backend_choice}")