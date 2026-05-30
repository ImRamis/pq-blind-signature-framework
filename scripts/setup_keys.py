#!/usr/bin/env python3
"""
Setup script for generating ZK-SNARK proving and verification keys.

This script initializes the NIZK prover from the `blind_signatures` library and
runs the key setup for the required circuits.
"""
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

from src.blind_signatures.config import display_config
from src.blind_signatures.nizk.prover_factory import get_prover

def main():
    """Main setup process."""
    print("--- ZK-SNARK Key Generation Setup ---")
    display_config()

    try:
        # Get the configured SNARK prover backend from the library
        prover = get_prover()
    except Exception as e:
        print(f"\nERROR: Failed to initialize the SNARK backend: {e}")
        print("Please ensure that the Node.js snarkjs engine is working correctly.")
        return 1

    # Define all circuits that require key setup
    circuits_to_setup = ["commitment_consistency","signature_consistency"]

    for circuit in circuits_to_setup:
        try:
            print(f"\n--- Setting up keys for '{circuit}' circuit ---")
            prover.setup_keys(circuit)
        except Exception as e:
            print(f"\nERROR: Failed to set up keys for '{circuit}': {e}")
            print("Please check the output from the circom and snarkjs tools for details.")
            return 1

    print("\n✓ SNARK key setup completed successfully!")
    return 0

if __name__ == "__main__":
    sys.exit(main())