#!/usr/bin/env python3
"""
Main runner for executing the blind signature benchmark suite.
"""
import sys
import os
import argparse
import json
from datetime import datetime

# Make the 'src' directory available for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.blind_signatures.config import display_config, PROJECT_ROOT
from benchmarks.suite import BlindSignatureBenchmark
from benchmarks.visualization import create_all_visualizations

def main():
    """Parses arguments, runs the benchmarks, and generates output."""
    parser = argparse.ArgumentParser(
        description='Run performance benchmarks for blind signature schemes.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '-i', '--iterations', type=int, default=50,
        help='Number of iterations for single-operation latency tests.'
    )
    parser.add_argument(
        '-b', '--batch_size', type=int, default=100,
        help='Number of operations for throughput and batch verification tests.'
    )
    parser.add_argument(
        '-v', '--visualize', action='store_true',
        help='Generate and save visualization charts from the results.'
    )
    parser.add_argument(
        '-o', '--output_dir', type=str, default='output',
        help='Directory to save benchmark results and visualizations.'
    )
    args = parser.parse_args()

    display_config()
    
    # --- Create Output Directory ---
    output_path = PROJECT_ROOT / args.output_dir
    os.makedirs(output_path, exist_ok=True)
    
    # --- Run Benchmarks ---
    benchmark_suite = BlindSignatureBenchmark(
        iterations=args.iterations,
        batch_size=args.batch_size
    )
    results = benchmark_suite.run_all_benchmarks()

    # --- Save Results ---
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    json_filename = f"benchmark_results_{timestamp}.json"
    json_filepath = output_path / json_filename
    
    with open(json_filepath, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"\nDetailed results saved to {json_filepath}")
    
    # --- Generate Visualizations ---
    if args.visualize:
        try:
            create_all_visualizations(results, str(output_path))
        except Exception as e:
            print(f"\nWarning: Visualization failed: {e}")
            print("  (This may be due to a missing dependency: pip install matplotlib)")
    
    print("\n" + "="*70)
    print("BENCHMARKING COMPLETE")
    print("="*70)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())