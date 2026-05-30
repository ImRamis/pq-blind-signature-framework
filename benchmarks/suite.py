"""
Defines the main benchmark suite for comparing blind signature schemes.
This version includes advanced metrics for throughput, aggregate proof generation,
and efficient batch verification. It has been modified to test multiple Fischlin
protocol backends in a single run.
"""

import json
import os
import secrets
import statistics
import sys
import time
from typing import Any, Dict, List, Tuple
from tabulate import tabulate


# Ensure 'src' directory is on the import path
sys.path.insert(
    0,
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

from src.blind_signatures import config
from py_ecc.optimized_bls12_381 import FQ, FQ2

from src.blind_signatures import (
    FischlinBlindSignature,
    HanzlikNIBS,
    HanzlikTNIBS,
    KlooReichleWagnerSignature,
)
from src.blind_signatures.core.practical_protocol import FinalSignature as KRWFinalSignature
from src.blind_signatures.utils.serialization import EnhancedJSONEncoder


def _get_obj_size(data_object: Any) -> int:
    """
    Serialize a Python object and return its size in bytes.
    """
    try:
        serialized = json.dumps(data_object, cls=EnhancedJSONEncoder)
        return len(serialized.encode("utf-8"))
    except TypeError:
        return 0


class BlindSignatureBenchmark:
    """
    Suite for running performance and size comparisons of various signature schemes.
    """

    def __init__(self, iterations: int = 50, batch_size: int = 100) -> None:
        self.iterations = iterations
        self.batch_size = batch_size
        self.results: Dict[str, Any] = {}

    def _time_op(self, func: Any, *args: Any, **kwargs: Any) -> Tuple[float, Any]:
        """
        Time a function call and return a tuple of (duration_seconds, result).
        """
        start = time.perf_counter()
        result = func(*args, **kwargs)
        duration = time.perf_counter() - start
        return duration, result

    def run_all_benchmarks(self) -> Dict[str, Any]:
        """
        Run all benchmarks (latency, throughput, batch, aggregate) and
        generate a printed summary report. This version runs the Fischlin scheme
        against multiple ZK backends by modifying the config at runtime.
        """
        print("\n" + "=" * 70)
        print(
            f"RUNNING BENCHMARKS "
            f"(Latency: {self.iterations} iter, "
            f"Throughput/Batch: {self.batch_size} ops)"
        )
        print("=" * 70)

        # Initialize the container for witness analysis results
        self.results["witness_analysis"] = {}

        # --- Standard Benchmarks ---
        self.results["Practical"] = self._benchmark_practical_latency()
        self.results["Hanzlik"] = self._benchmark_hanzlik_latency()
        self.results["Hanzlik (Tagged)"] = self._benchmark_hanzlik_tagged_latency()

        # --- Fischlin Benchmark Variations ---

        # 1. Fischlin with SNARK.js (groth16)
        print("\n" + "="*70)
        print("CONFIGURING FOR: Fischlin with SNARK.js")
        config.ZK_BACKEND = 'snarkjs'
        config.SNARKJS_PROOF_SYSTEM = 'groth16'
        fischlin_snarkjs_name = f"Fischlin (SNARK.js - {config.SNARKJS_PROOF_SYSTEM.upper()})"
        self.results[fischlin_snarkjs_name] = self._benchmark_fischlin_latency()
        # Run witness analysis for the snarkjs backend
        print("\n--- Running Witness Analysis for SNARK.js ---")
        self.results["witness_analysis"]["snarkjs"] = self.run_witness_size_benchmark()


        # 2. Fischlin with sonic-ucse (HTTP, bb-lamassu, pedersen)
        print("\n" + "="*70)
        print("CONFIGURING FOR: Fischlin with sonic-ucse (Rust HTTP)")
        config.ZK_BACKEND = 'sonic-ucse'
        config.SONIC_UCSE_INTERFACE = 'http'
        config.SONIC_UCSE_SCHEME = 'bb-lamassu'
        config.SONIC_UCSE_CIRCUIT = 'pedersen'
        fischlin_http_name = f"Fischlin (Rust HTTP - {config.SONIC_UCSE_SCHEME})"
        self.results[fischlin_http_name] = self._benchmark_fischlin_latency()
        # Run witness analysis for the sonic-ucse backend
        print("\n--- Running Witness Analysis for sonic-ucse (HTTP) ---")
        self.results["witness_analysis"]["sonic-ucse"] = self.run_witness_size_benchmark()

        # --- Post-processing for all results ---
        self._benchmark_throughput()
        self._benchmark_batch_verification()

        # Final report
        self._generate_report()
        return self.results

    def run_witness_size_benchmark(self) -> Dict[str, Any]:
        """
        Analyzes Fischlin's user cost as a function of witness size using the
        currently configured ZK backend.
        """
        protocol = FischlinBlindSignature()
        protocol.setup()
        keys = protocol.signer_keygen()

        witness_byte_sizes = [16, 32, 64, 128, 256]
        analysis_results = []

        for size in witness_byte_sizes:
            message = secrets.token_bytes(size)
            times = []
            for _ in range(max(1, self.iterations // 5)):
                t_req, (req, state) = self._time_op(protocol.create_request, message, keys.encryption_key)
                t_resp, resp = self._time_op(protocol.create_response, req, keys)
                if not resp: continue
                t_unblind, sig = self._time_op(protocol.unblind_signature, resp, state, keys.verification_key)
                if not sig: continue
                times.append((t_req + t_unblind) * 1000)

            avg_time = statistics.mean(times) if times else 0
            witness_bits = size * 8
            analysis_results.append((witness_bits, avg_time))
            print(f"  - Witness: {witness_bits} bits, Avg. User Total Time: {avg_time:.2f} ms")

        return {"fischlin_witness_cost": analysis_results}

    def _get_latency_results(self, times: Dict[str, List[float]]) -> Dict[str, float]:
        """Helper to compute statistics and use consistent metric names."""
        return {
            "user_cost": statistics.mean(times["user"]) if times["user"] else 0,
            "signer_cost": statistics.mean(times["signer"]) if times["signer"] else 0,
            "verify": statistics.mean(times["verify"]) if times["verify"] else 0,
            "sig_size": statistics.mean(times["sig_size"]) if times["sig_size"] else 0,
            "comm": statistics.mean(times["comm"]) if times["comm"] else 0,
        }

    def _benchmark_fischlin_latency(self) -> Dict[str, Any]:
        print(f"\n--- Benchmarking Fischlin ({config.ZK_BACKEND.upper()}) (Latency & Size) ---")
        protocol = FischlinBlindSignature(); protocol.setup()
        keygen_time, keys = self._time_op(protocol.signer_keygen)
        message = b"benchmark_message"
        times: Dict[str, List[float]] = {"user": [], "signer": [], "verify": [], "comm": [], "sig_size": []}

        for _ in range(self.iterations):
            t_req, (req, state) = self._time_op(protocol.create_request, message, keys.encryption_key)
            t_resp, resp = self._time_op(protocol.create_response, req, keys)
            if not resp: continue
            t_unblind, sig = self._time_op(protocol.unblind_signature, resp, state, keys.verification_key)
            if not sig: continue
            times["user"].append((t_req + t_unblind) * 1000)
            times["signer"].append(t_resp * 1000)
            t_verify, _ = self._time_op(protocol.verify_signature, sig, keys.verification_key)
            times["verify"].append(t_verify * 1000)
            times["comm"].append(_get_obj_size(req) + _get_obj_size(resp))
            times["sig_size"].append(_get_obj_size(sig.signature))

        return {"keygen_time": keygen_time * 1000, **self._get_latency_results(times)}

    def _benchmark_practical_latency(self) -> Dict[str, Any]:
        print("\n--- Benchmarking Practical (Latency & Size) ---")
        protocol = KlooReichleWagnerSignature()
        keygen_time, keys = self._time_op(protocol.keygen)
        message = b"benchmark_message"
        times: Dict[str, List[float]] = {"user": [], "signer": [], "verify": [], "comm": [], "sig_size": []}

        for _ in range(self.iterations):
            t1, (um1, us) = self._time_op(protocol.user_step1, message, keys)
            t2, (sm1, ss) = self._time_op(protocol.signer_step1, um1, keys)
            if not sm1: continue
            t3, um2 = self._time_op(protocol.user_step2, sm1, us, keys)
            t4, sm2 = self._time_op(protocol.signer_step2, um2, ss, keys)
            t5, final_sig = self._time_op(protocol.user_finalize, sm2, us)
            times["user"].append((t1 + t3 + t5) * 1000)
            times["signer"].append((t2 + t4) * 1000)
            t_verify, _ = self._time_op(protocol.verify, message, final_sig, keys)
            times["verify"].append(t_verify * 1000)
            times["comm"].append(_get_obj_size(um1) + _get_obj_size(sm1) + _get_obj_size(um2) + _get_obj_size(sm2))
            times["sig_size"].append(_get_obj_size(final_sig))
        
        return {"keygen_time": keygen_time * 1000, **self._get_latency_results(times)}

    def _benchmark_hanzlik_latency(self) -> Dict[str, Any]:
        print("\n--- Benchmarking Hanzlik NIBS (Latency & Size) ---")
        protocol = HanzlikNIBS()
        keygen_time, (signer_sk, signer_pk) = self._time_op(protocol.keygen)
        times: Dict[str, List[float]] = {"user": [], "signer": [], "verify": [], "comm": [], "sig_size": []}

        for _ in range(self.iterations):
            nonce, (t_rkeygen, (rec_sk, rec_pk)) = secrets.token_bytes(32), self._time_op(protocol.rkeygen)
            t_issue, psig = self._time_op(protocol.issue, signer_sk, rec_pk, nonce)
            t_obtain, obtained = self._time_op(protocol.obtain, rec_sk, signer_pk, psig, nonce)
            if not obtained: continue
            m, final_sig = obtained
            times["user"].append((t_rkeygen + t_obtain) * 1000)
            times["signer"].append(t_issue * 1000)
            t_verify, _ = self._time_op(protocol.verify, signer_pk, m, final_sig)
            times["verify"].append(t_verify * 1000)
            times["comm"].append(_get_obj_size(psig))
            times["sig_size"].append(_get_obj_size(final_sig))

        return {"keygen_time": keygen_time * 1000, **self._get_latency_results(times)}

    def _benchmark_hanzlik_tagged_latency(self) -> Dict[str, Any]:
        print("\n--- Benchmarking Hanzlik TNIBS (Latency & Size) ---")
        protocol = HanzlikTNIBS()
        tag = b"benchmark-tag"
        keygen_time, (signer_sk, signer_pk) = self._time_op(protocol.keygen)
        times: Dict[str, List[float]] = {"user": [], "signer": [], "verify": [], "comm": [], "sig_size": []}

        for _ in range(self.iterations):
            nonce, (t_rkeygen, (rec_sk, rec_pk)) = secrets.token_bytes(32), self._time_op(protocol.rkeygen)
            t_issue, psig = self._time_op(protocol.issue, signer_sk, rec_pk, nonce, tag)
            t_obtain, obtained = self._time_op(protocol.obtain, rec_sk, signer_pk, psig, nonce, tag)
            if not obtained: continue
            m, final_sig = obtained
            times["user"].append((t_rkeygen + t_obtain) * 1000)
            times["signer"].append(t_issue * 1000)
            t_verify, _ = self._time_op(protocol.verify, signer_pk, m, tag, final_sig)
            times["verify"].append(t_verify * 1000)
            times["comm"].append(_get_obj_size(psig))
            times["sig_size"].append(_get_obj_size(final_sig))

        return {"keygen_time": keygen_time * 1000, **self._get_latency_results(times)}

    def _benchmark_throughput(self) -> None:
        print("\n--- Benchmarking Signer Throughput ---")
        for s in self.results:
            if s == "witness_analysis": continue
            self.results[s]["throughput"] = 1000 / self.results[s]["signer_cost"] if self.results[s]["signer_cost"] > 0 else 0

    def _benchmark_batch_verification(self) -> None:
        print("\n--- Benchmarking Naive Batch Verification ---")
        for s in self.results:
             if s == "witness_analysis": continue
             self.results[s]["batch_verify_time"] = self.results[s]["verify"] * self.batch_size
             self.results[s]["batch_size"] = self.batch_size

    def _generate_report(self) -> None:
        """
        Print a comprehensive summary report including all metrics.
        """
        # Define a consistent order for schemes in the report
        scheme_order = [
            "Practical",
            "Hanzlik",
            "Hanzlik (Tagged)",
            f"Fischlin (SNARK.js - {config.SNARKJS_PROOF_SYSTEM.upper()})",
            "Fischlin (Rust HTTP - bb-lamassu)",
        ]
        
        schemes = [s for s in scheme_order if s in self.results]
        
        # The keys in `self.results` are already descriptive, so we use them directly.
        headers = ["Metric"] + [f"{s.replace('Fischlin ', 'Fischlin\n')}" for s in schemes]
        
        def fmt(key: str, fmt_spec: str = ".2f") -> List[str]:
            return [f"{self.results[s].get(key, 0):{fmt_spec}}" for s in schemes]

        def total_protocol() -> List[str]:
            return [f"{(self.results[s].get('user_cost', 0) + self.results[s].get('signer_cost', 0)):.2f}" for s in schemes]

        latency_rows = [
            ["Total Protocol (ms)", *total_protocol()],
            ["- User Cost (ms)", *fmt("user_cost")],
            ["- Signer Cost (ms)", *fmt("signer_cost")],
            ["Single Verification (ms)", *fmt("verify")],
            ["Signature Size (B)", *fmt("sig_size", ".0f")],
            ["Transfer Size (B)", *fmt("comm", ".0f")],
        ]
        throughput_rows = [
            ["Signer Throughput (ops/s)", *fmt("throughput")],
            [f"Batch Verify {self.batch_size} (ms)", *fmt("batch_verify_time")],
        ]

        print("\n" + "=" * 110 + "\n" + " LATENCY & SIZE ".center(110, "="))
        print(tabulate(latency_rows, headers=headers, tablefmt="fancy_grid", floatfmt=".2f", numalign="right"))
        print("\n" + "=" * 110 + "\n" + " THROUGHPUT & BATCH ".center(110, "="))
        print(tabulate(throughput_rows, headers=headers, tablefmt="fancy_grid", floatfmt=".2f", numalign="right"))