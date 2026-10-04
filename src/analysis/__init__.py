"""Phase 5-6 analysis package (per design.md §3)."""
from .decompose import decompose_cost, figure_a, figure_b, figure_c, figure_d
from .loader import load_raw, trial_valid

__all__ = [
    "decompose_cost", "figure_a", "figure_b", "figure_c", "figure_d",
    "load_raw", "trial_valid",
]
