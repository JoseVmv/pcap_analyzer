"""Small statistical helpers shared by analysers and detectors.

Named ``stats`` (not ``statistics``) to avoid shadowing the stdlib module
inside the package.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence


def shannon_entropy(text: str) -> float:
    """Shannon entropy of a string in bits per character (0.0 for empty).

    Random/encoded data approaches log2(alphabet size); English-like text
    sits around 3-4 bits; DGA/base32-style labels usually score higher than
    human-chosen names of the same length.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum(
        (count / total) * math.log2(count / total) for count in counts.values()
    )


def mean(values: Sequence[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def stdev(values: Sequence[float]) -> float:
    """Population standard deviation (0.0 for fewer than 2 values)."""
    if len(values) < 2:
        return 0.0
    mu = mean(values)
    return math.sqrt(sum((v - mu) ** 2 for v in values) / len(values))


def median(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def median_absolute_deviation(values: Sequence[float]) -> float:
    """MAD: robust spread measure, far less sensitive to outliers than the
    standard deviation (one huge gap should not hide an otherwise regular
    beacon)."""
    if not values:
        return 0.0
    med = median(values)
    return median([abs(v - med) for v in values])


def coefficient_of_variation(values: Sequence[float]) -> float:
    """stdev/mean - scale-free regularity measure (lower = more regular).

    Returns ``inf`` when the mean is 0 (undefined regularity).
    """
    mu = mean(values)
    if mu == 0:
        return math.inf
    return stdev(values) / mu
