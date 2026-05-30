#!/bin/bash
#
# Quick Start Script for the Blind Signature Project
# This script checks for prerequisites, installs dependencies, and generates
# the necessary ZK-SNARK keys for the project to run.
#
set -e # Exit immediately if a command exits with a non-zero status.

echo "--- Quick Start for Blind Signature Project ---"

# --- 1. Check Prerequisites ---
echo -e "\n1. Checking for required tools..."

# Helper function to check if a command exists
command_exists () {
    command -v "$1" &> /dev/null
}

# Check for essential build tools
for cmd in python3 pip3 node npm git cargo; do
    if command_exists $cmd; then
        echo "✓ $cmd is installed."
    else
        echo "✗ $cmd not found. Please install it to continue."
        exit 1
    fi
done

# Check for Circom
if command_exists circom; then
    echo "✓ Circom compiler is already installed."
else
    echo "-> Circom not found. Cloning and building from source..."
    if [ -d "circom" ]; then
        echo "-> 'circom' directory already exists. Skipping clone."
    else
        git clone https://github.com/iden3/circom.git
    fi
    cd circom
    cargo build --release
    # Temporarily add the new circom binary to the PATH for this script
    export PATH="$PATH:$(pwd)/target/release"
    cd ..
    
    if command_exists circom; then
        echo "✓ Circom successfully built."
        echo "NOTE: You may need to add the circom binary to your system's PATH permanently."
        echo "You can do this by adding 'export PATH=\"\$PATH:$(pwd)/circom/target/release\"' to your ~/.bashrc or ~/.zshrc file."
    else
        echo "✗ Failed to build or find circom after compilation. Please check your Rust environment."
        exit 1
    fi
fi

# --- 2. Install Dependencies ---
echo -e "\n2. Installing project dependencies..."
# Install Python packages in editable mode, including optional deps for examples/benchmarks
pip3 install -e .[examples,benchmarks]
# Install Node.js packages for the SNARK engine
(cd snarkjs_engine && npm install)


# --- 3. Download Powers of Tau ---
PTAU_FILE="circuits/powersOfTau28_hez_final_15.ptau"
echo -e "\n3. Checking for Powers of Tau file..."
if [ ! -f "$PTAU_FILE" ]; then
    echo "-> Powers of Tau file not found. Downloading (28MB)..."
    mkdir -p circuits
    # Use the reliable link for the ptau file you provided
    curl -L "https://raw.githubusercontent.com/scaffold-eth/scaffold-eth-examples/refs/heads/zk-prove-membership/packages/hardhat/circuits/powersOfTau28_hez_final_15.ptau" -o "$PTAU_FILE"
    if [ $? -ne 0 ]; then
        echo "✗ Download failed. Please check your internet connection."
        exit 1
    fi
    echo "✓ Powers of Tau file downloaded."
else
    echo "✓ Powers of Tau file already exists."
fi

# --- 4. Generate SNARK Keys ---
echo -e "\n4. Generating ZK-SNARK keys..."
# Execute the Python script from the scripts directory to handle key setup
python3 scripts/setup_keys.py
if [ $? -ne 0 ]; then
    echo "✗ SNARK key setup failed. Please check the Python script output."
    exit 1
fi

echo -e "\n\n--- SETUP COMPLETE ---"
echo "The environment is ready."
echo "You can now run the examples, for example:"
echo "python3 examples/bank_demo.py"