# Post-Quantum Blind Signature Framework

> **DISCLAIMER**: This repository contains sanitized code samples and architecture documentation. Sensitive implementation details, proprietary algorithms, and internal APIs have been removed for security reasons. This repository is not open for contributions yet.

## Overview
A research-focused framework for analyzing and implementing post-quantum secure blind signature schemes. Provides:
- Rust core library for cryptographic operations
- gRPC interfaces for cross-language compatibility
- Client implementations in Python, Node.js, and Rust
- Benchmarking suite for performance analysis

## Features
- Support for multiple PQ signature schemes (Dilithium, Falcon, SPHINCS+)
- Zero-knowledge proof implementations for blind signature protocols
- Hardware acceleration support (CUDA/OpenCL)
- Comprehensive test coverage (95%+)

## Getting Started
```bash
# Clone repository
git clone https://github.com/ImRamis/pq-blind-signature-framework.git
cd pq-blind-signature-framework

# Build core library
cargo build --release

# Generate gRPC stubs
./scripts/generate_protos.sh
```

## Research Paper
This implementation accompanies our paper "Practical Post-Quantum Blind Signatures" (submitted to IEEE S&P 2025). Preprint available at [arXiv link].