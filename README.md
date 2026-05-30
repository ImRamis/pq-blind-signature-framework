# A Comparative Framework for Modern Blind Signature Schemes
 This repository contains the complete implementation and benchmarking framework for the dissertation "A Comparative Analysis of Modern Blind Signature Schemes: Implementation, Security, and Performance". It provides a unified Python library for evaluating three distinct families of modern blind signatures, each representing a different point on the security-performance-architecture spectrum.
 The primary contribution of this work is a fair, "apples-to-apples" comparison enabled by a unified API and a pluggable backend system for zero-knowledge proofs.
 ## Table of Contents
1.  Overview
2.  Features
3.  Schemes Implemented
4.  Project Structure
5.  Installation and Setup
    - Prerequisites
    - Installation Steps
    - Configuration
6.  How to Use the Library (API Examples)
    - Example 1: Fischlin (Composable Framework)
    - Example 2: Practical Pairing-Free (KRW)
    - Example 3: Hanzlik (Non-Interactive)
7.  Running the Benchmarks
8.  Running the Demonstrations
9.  Citing This Work
10. License
 ## Overview
 Blind signatures are a powerful cryptographic tool that allows a signer to issue a signature on a message without ever seeing its content. This provides a strong guarantee of privacy for the user. While the theory is well-established, practical implementations face a critical trade-off between formal security guarantees, real-world performance (speed, throughput), and architectural design (interactive vs. non-interactive).
 This project provides the tools to explore that trade-off directly. It contains:
-   A unified Python library implementing three state-of-the-art schemes.
-   A pluggable backend system for Zero-Knowledge proofs, allowing for a direct comparison between a standard high-performance prover (Groth16) and a high-assurance, universally composable prover (BB-Lamassu).
-   A comprehensive benchmarking suite to generate the performance data analyzed in the dissertation.
-   Practical demonstration applications for e-cash and anonymous voting.
 ## Features
 -   Three State-of-the-Art Schemes: Implementations of the Fischlin, Klooß-Reichle-Wagner (KRW), and Hanzlik blind signature schemes.
-   Pluggable ZK-SNARK Backends: Easily switch between snarkjs (for Groth16 proofs) and sonic-ucse (for UC-secure BB-Lamassu proofs) for the Fischlin scheme via a simple configuration file.
-   Unified API: All schemes are exposed through a consistent API for key generation, signing (obtain), and verification, simplifying comparative analysis.
-   Comprehensive Benchmarking: A powerful command-line tool (benchmarks/runner.py) to measure latency, throughput, data sizes, and the performance impact of witness scaling.
-   Clear Demonstrations: Ready-to-run examples for anonymous e-cash and e-voting that illustrate the practical application of each scheme.
 ## Schemes Implemented
 1.  Fischlin (2006): A round-optimal, two-move framework in the Common Reference String (CRS) model designed for provable, composable security. Its security is heavily reliant on a Non-Interactive Zero-Knowledge (NIZK) proof component.
2.  Klooß-Reichle-Wagner (2024): A practical, four-move interactive protocol designed for high efficiency in standard pairing-free elliptic curve groups.
3.  Hanzlik (2023): A non-interactive paradigm (NIBS) where a signer issues a "presignature" that a user can later convert into a final signature offline. It is built upon Signatures on Equivalence Classes (SPS-EQ) and requires pairing-based cryptography.
 ## Project Structure
 The repository is organized to separate the core library logic from the benchmarking and demonstration code.
## Project Structure

The repository is organized to separate the core library logic from the benchmarking and demonstration code.

```
├── benchmarks/           # Benchmark runner, suite logic, and visualization
├── circuits/             # Circom circuits for the snarkjs (Groth16) backend
├── examples/             # Demonstration scripts (e-cash, e-voting)
├── snarkjs_engine/       # Node.js wrapper for snarkjs
├── sonic-cli/            # Rust wrapper for the sonic-ucse (BB-Lamassu) backend
├── sonic-ucse-cli-src/   # Rust source code for the sonic-ucse (BB-Lamassu/Sonic) backend
├── scripts/
├── src/
│   └── blind_signatures/ # The core Python library
│       ├── core/         # Implementations of the three schemes
│       ├── crypto/       # Low-level crypto primitives
│       └── nizk/         # Pluggable ZK-SNARK backend abstraction and adapters
├── .env.example          # Example configuration file
└── pyproject.toml        # Project dependencies and metadata
```
 ## Installation and Setup
 ### Prerequisites
 -   Python 3.9+
-   Node.js 16+ and npm
-   Rust and Cargo (if you want to re-compile the sonic-ucse backend)
 ### Installation Steps
 1.  Clone the repository:
    bash |     git clone [https://github.com/imramis/blind-signatures-comparisons.git](https://github.com/imramis/blind-signatures-comparisons.git) |     cd blind-signatures-comparisons |     
 2.  Create a Python virtual environment and install dependencies:
    bash |     python -m venv venv |     source venv/bin/activate |     pip install -e . |     
 3.  Set up the snarkjs Node.js engine:
    bash |     cd snarkjs_engine |     npm install |     cd .. |     
 4.  Set up the sonic-ucse Rust backend:
    A pre-compiled binary is included at sonic-rust/target/release/sonic-cli. If you need to recompile it:
    bash |     cd sonic-rust |     cargo build --release |     cd .. |     
 ### Configuration
 The framework is configured using a .env file in the project root.
 1.  Create a configuration file:
    bash |     cp .env.example .env |     
 2.  Edit the .env file: Open the .env file in a text editor. The most important variable is ZK_BACKEND, which controls the proof system used by the Fischlin scheme.
    -   To use the fast Groth16 backend, set ZK_BACKEND="snarkjs".
    -   To use the UC-secure BB-Lamassu backend, set ZK_BACKEND="sonic-ucse".
     You can also configure the interfaces, ports, and other parameters for the backends.
 ## How to Use the Library (API Examples)
 The library is designed for easy use. Here are simple examples for each scheme.
 ### Example 1: Fischlin (Composable Framework)
 This example uses the ZK-SNARK backend selected in your .env file.
 python | from blind_signatures.core.fischlin_protocol import FischlinBlindSignature |  | # 1. Initialize the scheme | # The prover factory automatically loads the backend from your .env config | fischlin = FischlinBlindSignature() |  | # 2. Signer generates keys | signer_state = fischlin.keygen() | fischlin.set_signer_state(signer_state) |  | # 3. User obtains a blind signature for a message | message = b"This is a secret message for an anonymous credential" | signature = fischlin.obtain(message) |  | print(f"Fischlin Signature successful!") |  | # 4. A third party can verify the signature | is_valid = fischlin.verify(message, signature) | assert is_valid | print(f"Fischlin Signature is valid: {is_valid}") | 
 ### Example 2: Practical Pairing-Free (KRW)
 python | from blind_signatures.core.practical_protocol import KlooReichleWagnerSignature |  | # 1. Initialize | krw = KlooReichleWagnerSignature() |  | # 2. Signer generates keys | signer_state = krw.keygen() | krw.set_signer_state(signer_state) |  | # 3. User obtains a blind signature | message = b"This is for a high-speed, anonymous web token" | signature = krw.obtain(message) |  | print(f"KRW Signature successful!") |  | # 4. Verification | is_valid = krw.verify(message, signature) | assert is_valid | print(f"KRW Signature is valid: {is_valid}") | 
 ### Example 3: Hanzlik (Non-Interactive)
 python | from blind_signatures.core.hanzlik_protocol import HanzlikNIBS |  | # 1. Initialize | nibs = HanzlikNIBS() |  | # 2. Signer and User generate keys | signer_state = nibs.keygen() | nibs.set_signer_state(signer_state) | user_pk, user_sk = nibs.user_keygen() |  | # 3. Signer issues a presignature for the user (can be done offline) | presignature, nonce = nibs.issue(user_pk) | print("Signer issued a presignature.") |  | # 4. User converts the presignature into a final signature (offline) | final_signature = nibs.obtain(user_sk, presignature, nonce) | print("User obtained the final signature.") |  | # 5. Verification | is_valid = nibs.verify(final_signature) | assert is_valid | print(f"Hanzlik NIBS Signature is valid: {is_valid}") | 
 ## Running the Benchmarks
 The full performance evaluation suite can be run from the command line.
 bash | # Example: Run 50 iterations for latency and a batch size of 100 for throughput, then generate charts | python benchmarks/runner.py --iterations 50 --batch_size 100 --visualize | 
 -   Arguments:
    -   --iterations, -i: Number of runs for latency tests.
    -   --batch_size, -b: Number of operations for throughput tests.
    -   --visualize, -v: Flag to generate and save all charts from the dissertation.
    -   --output_dir, -o: Directory to save the raw JSON results and charts.
 The script will print the active configuration, run the benchmarks for all schemes, and save the results to a timestamped JSON file in the output/ directory.
 ## Running the Demonstrations
 Two practical use cases are included in the examples/ directory.
 1.  Anonymous E-Cash:
    bash |     python examples/bank_demo.py |     
    This script simulates a user anonymously withdrawing a digital "coin" from a bank and correctly detects a forgery attempt.
 2.  Privacy-Preserving E-Voting:
    bash |     python examples/anonymous_voting_demo.py |     
    This script simulates an eligible voter getting a ballot blindly signed and casting it anonymously, while the system prevents double-voting.
 ## Citing This Work
 If you use this library or the findings from the dissertation in your research, please cite it as follows:
 bibtex | @mastersthesis{Ramis2025BlindSigs, |   author  = {Muhammad Ramis}, |   title   = {A Comparative Analysis of Modern Blind Signature Schemes: Implementation, Security, and Performance}, |   school  = {University of Sheffield}, |   year    = {2025}, |   address = {Sheffield, UK}, |   month   = {August} | } | 
 ## License
 This project is licensed under the MIT License. See the LICENSE file for details.
