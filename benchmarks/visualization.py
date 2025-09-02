"""
Visualization of performance comparison between blind signature schemes.
This module generates multiple professional charts for detailed analysis, including
bar charts, line plots, and radar charts for a holistic view.
"""
import matplotlib.pyplot as plt
import numpy as np
import os
from typing import Dict, Any, List

from src.blind_signatures import config

# Apply a professional and clean style for the plots
plt.style.use('seaborn-v0_8-whitegrid')
# Define a color palette for consistency across charts
COLOR_PALETTE = ['#4285F4', '#34A853', '#EA4335', '#FBBC05', '#7E57C2', '#FF6D00', '#9E9D24']


def _save_figure(fig, output_dir: str, filename: str):
    """Helper function to save a figure to the output directory."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    fig.savefig(path, dpi=300, bbox_inches='tight')
    print(f"✓ Visualization saved to: {path}")
    plt.close(fig)

def _add_better_indicator(ax, text: str, location: str = 'top right'):
    """Adds a 'lower/higher is better' text indicator to the plot."""
    props = dict(boxstyle='round,pad=0.3', facecolor='lightgrey', alpha=0.5)
    ha = 'right' if location == 'top right' else 'left'
    x_pos = 0.97 if location == 'top right' else 0.03
    ax.text(x_pos, 0.97, text, transform=ax.transAxes, fontsize=10,
            verticalalignment='top', horizontalalignment=ha, bbox=props)

def _get_display_names(schemes: List[str]) -> List[str]:
    """Generates clean display names for schemes, breaking lines for readability."""
    # The scheme names from the results dict are already descriptive.
    # We just add line breaks for better chart formatting.
    return [s.replace(' - ', '\n').replace(' (', '\n(') for s in schemes]

def plot_qualitative_radar(results: Dict[str, Any], output_dir: str):
    schemes_raw = [s for s in results if s != "witness_analysis"]
    if not schemes_raw: return
    
    display_names = _get_display_names(schemes_raw)
    categories = ['Efficiency', 'Security', 'Low Rounds', 'Low Sig Size', 'Low Transfer']
    
    # Base scores for the fundamental scheme types
    security_scores = {'Fischlin': 5, 'Practical': 4, 'Hanzlik': 4}
    round_scores = {'Fischlin': 5, 'Practical': 3, 'Hanzlik': 5}
    
    max_vals = {
        'time': max(r.get('user_cost', 0) + r.get('signer_cost', 0) for r in results.values() if isinstance(r, dict)) or 1,
        'sig': max(r.get('sig_size', 1) for r in results.values() if isinstance(r, dict)) or 1,
        'comm': max(r.get('comm', 1) for r in results.values() if isinstance(r, dict)) or 1,
    }

    data = []
    for s in schemes_raw:
        r = results[s]
        # Get the base scheme name (e.g., 'Fischlin' from 'Fischlin (SNARK.js...)')
        base_scheme = s.split(' ')[0]
        if '(Tagged)' in s:
            base_scheme = 'Hanzlik' # Treat tagged as Hanzlik for scoring

        total_time = r.get('user_cost', 0) + r.get('signer_cost', 0)
        data.append([
            5 * (1 - total_time / max_vals['time']),
            security_scores.get(base_scheme, 3),
            round_scores.get(base_scheme, 3),
            5 * (1 - r.get('sig_size', 0) / max_vals['sig']),
            5 * (1 - r.get('comm', 0) / max_vals['comm']),
        ])

    num_vars = len(categories)
    angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist() + [0]

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))
    for i, (row, name) in enumerate(zip(data, display_names)):
        ax.plot(angles, row + row[:1], color=COLOR_PALETTE[i % len(COLOR_PALETTE)], lw=2, label=name)
        ax.fill(angles, row + row[:1], color=COLOR_PALETTE[i % len(COLOR_PALETTE)], alpha=0.2)

    ax.set_yticklabels([]); ax.set_xticks(angles[:-1]); ax.set_xticklabels(categories)
    ax.set_title('Scheme Comparison Radar Chart', size=16, y=1.1)
    ax.legend(loc='upper right', bbox_to_anchor=(1.45, 1.1))
    _save_figure(fig, output_dir, "0_radar_comparison.png")

def plot_performance_breakdown(results: Dict[str, Any], output_dir: str):
    schemes_raw = [s for s in results if s != "witness_analysis"]
    if not schemes_raw: return
    display_names = _get_display_names(schemes_raw)
    
    user_costs = np.array([results[s].get('user_cost', 0) for s in schemes_raw])
    signer_costs = np.array([results[s].get('signer_cost', 0) for s in schemes_raw])
    verify_costs = np.array([results[s].get('verify', 0) for s in schemes_raw])
    x = np.arange(len(schemes_raw))

    fig, ax = plt.subplots(figsize=(12, 7))
    ax.bar(x, user_costs, width=0.5, label='User Cost', color=COLOR_PALETTE[0])
    ax.bar(x, signer_costs, width=0.5, bottom=user_costs, label='Signer Cost', color=COLOR_PALETTE[1])
    
    ax.set_ylabel('Protocol Time (ms) - Log Scale'); ax.set_title('Performance: Protocol vs. Verification', fontsize=16, pad=20)
    ax.set_xticks(x, display_names, rotation=25, ha="right"); ax.set_yscale('log'); ax.legend(title="Protocol Cost")
    _add_better_indicator(ax, "Lower is Better", 'top left')

    ax2 = ax.twinx()
    ax2.plot(x, verify_costs, color=COLOR_PALETTE[2], marker='D', ls='--', label='Verification Cost')
    ax2.set_ylabel('Verification Time (ms)', color=COLOR_PALETTE[2]); ax2.tick_params(axis='y', labelcolor=COLOR_PALETTE[2])
    ax2.legend(loc='upper right')

    fig.tight_layout()
    _save_figure(fig, output_dir, "1_performance_breakdown.png")

def plot_data_sizes(results: Dict[str, Any], output_dir: str):
    schemes_raw = [s for s in results if s != "witness_analysis"]; display_names = _get_display_names(schemes_raw)
    sig_sizes = [results[s].get('sig_size', 0) for s in schemes_raw]
    transfer_sizes = [results[s].get('comm', 0) for s in schemes_raw]
    x = np.arange(len(schemes_raw))

    fig, ax = plt.subplots(figsize=(12, 7))
    ax.bar(x - 0.2, sig_sizes, 0.4, label='Final Signature Size', color=COLOR_PALETTE[3])
    ax.bar(x + 0.2, transfer_sizes, 0.4, label='Total Transfer Size (Protocol)', color=COLOR_PALETTE[4])
    ax.set_ylabel('Size (Bytes)'); ax.set_title('Data Overhead: Signature vs. Transfer Size', fontsize=16, pad=20)
    ax.set_xticks(x, display_names, rotation=25, ha="right"); ax.legend(loc='upper left')
    _add_better_indicator(ax, "Lower is Better", 'top right')
    for i in range(len(schemes_raw)):
        ax.text(i - 0.2, sig_sizes[i], f'{sig_sizes[i]:.0f} B', ha='center', va='bottom')
        ax.text(i + 0.2, transfer_sizes[i], f'{transfer_sizes[i]:.0f} B', ha='center', va='bottom')
    
    fig.tight_layout()
    _save_figure(fig, output_dir, "2_data_sizes.png")

def plot_throughput(results: Dict[str, Any], output_dir: str):
    schemes_raw = [s for s in results if s != "witness_analysis"]; display_names = _get_display_names(schemes_raw)
    throughputs = [results[s].get('throughput', 0) for s in schemes_raw]

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(display_names, throughputs, color=COLOR_PALETTE[:len(schemes_raw)])
    ax.set_ylabel('Signatures per Second (ops/s)'); ax.set_title('Server Capacity: Signer Throughput', fontsize=16, pad=20)
    _add_better_indicator(ax, "Higher is Better"); ax.bar_label(bars, fmt='%.1f ops/s')
    plt.xticks(rotation=25, ha="right")
    
    fig.tight_layout()
    _save_figure(fig, output_dir, "3_signer_throughput.png")

def plot_batch_verification(results: Dict[str, Any], output_dir: str):
    schemes_raw = [s for s in results if s != "witness_analysis"]; display_names = _get_display_names(schemes_raw)
    
    if not schemes_raw: return
    batch_size = results.get(schemes_raw[0], {}).get('batch_size', 100)
    batch_times = [results[s].get('batch_verify_time', 0) for s in schemes_raw]
    single_times = [results[s].get('verify', 0) * batch_size for s in schemes_raw]
    x = np.arange(len(schemes_raw))

    fig, ax = plt.subplots(figsize=(12, 7))
    ax.bar(x - 0.2, single_times, 0.4, label=f'Naive Single x {batch_size} (Est.)', color='#FFA07A')
    ax.bar(x + 0.2, batch_times, 0.4, label=f'Batch Emulation ({batch_size} ops)', color='#20B2AA')
    ax.set_ylabel('Time (ms) - Log Scale'); ax.set_title('Verification Efficiency: Emulated Batch vs. Naive', fontsize=16, pad=20)
    ax.set_xticks(x, display_names, rotation=25, ha="right"); ax.set_yscale('log'); ax.legend()
    _add_better_indicator(ax, "Lower is Better", 'top left')
    
    fig.tight_layout()
    _save_figure(fig, output_dir, "4_batch_verification.png")

def plot_witness_size_analysis(results: Dict[str, Any], output_dir: str):
    analysis_data = results.get("witness_analysis", {})
    if not analysis_data: return

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.set_xlabel('Witness Size (bits)')
    ax.set_ylabel('Time (ms)')
    ax.set_title("Fischlin Scheme: User Cost vs. Witness Size", fontsize=16, pad=20)
    _add_better_indicator(ax, "Lower is Better", 'top left')

    backend_map = {
        "snarkjs": {"label": "SNARK.js Backend", "color": COLOR_PALETTE[0]},
        "sonic-ucse": {"label": "Rust (HTTP) Backend", "color": COLOR_PALETTE[1]},
    }

    for i, (backend, data) in enumerate(analysis_data.items()):
        witness_cost_data = data.get("fischlin_witness_cost", [])
        if not witness_cost_data: continue

        bits, times = zip(*witness_cost_data)
        plot_config = backend_map.get(backend, {"label": backend.upper(), "color": COLOR_PALETTE[i]})

        ax.plot(bits, times, marker='o', ls='--', color=plot_config["color"], label=plot_config["label"])
        for (bit, time) in witness_cost_data:
            # Alternate text position to avoid overlap
            va = 'bottom' if i == 0 else 'top'
            ax.text(bit, time, f' {time:.1f} ms', va=va)

    ax.legend()
    fig.tight_layout()
    _save_figure(fig, output_dir, "5_fischlin_witness_scaling.png")

def create_all_visualizations(results: Dict[str, Any], output_dir: str):
    """Runs all plotting functions to generate a full suite of visualizations."""
    print("\n--- Generating Benchmark Visualizations ---")
    plot_qualitative_radar(results, output_dir)
    plot_performance_breakdown(results, output_dir)
    plot_data_sizes(results, output_dir)
    plot_throughput(results, output_dir)
    plot_batch_verification(results, output_dir)
    plot_witness_size_analysis(results, output_dir)