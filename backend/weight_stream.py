"""Decode numeric buffers and calculate full statistics in bounded memory."""
from __future__ import annotations

import array
from dataclasses import dataclass, field
import math
import struct
import sys
from typing import BinaryIO
from collections.abc import Iterator

FLOAT_FORMATS = {"F16": ("e", 2), "BF16": ("f", 2), "F32": ("f", 4), "F64": ("d", 8)}
BLOCK_VALUES = 16384
STAT_SAMPLE_SIZE = 100_000
MAX_FLOAT_BYTES = 2 * 1024**3


def read_floats(stream: BinaryIO, dtype: str, count: int):
    symbol, width = FLOAT_FORMATS[dtype]
    raw = stream.read(count * width)
    if len(raw) != count * width:
        raise ValueError("Тензор обрезан во время чтения.")
    if dtype == "F16":
        return struct.unpack(f"<{count}e", raw)
    if dtype == "BF16":
        widened = bytearray(count * 4)
        widened[2::4] = raw[::2]
        widened[3::4] = raw[1::2]
        raw = widened
    values = array.array(symbol)
    values.frombytes(raw)
    if sys.byteorder != "little":
        values.byteswap()
    return values


class FloatTensorValues:
    """Reiterable tensor view; every pass reads the entire buffer in bounded chunks."""

    def __init__(self, stream: BinaryIO, offset: int, count: int, dtype: str):
        self.stream, self.offset, self.count, self.dtype = stream, offset, count, dtype

    def __len__(self) -> int:
        return self.count

    def __iter__(self) -> Iterator[float]:
        self.stream.seek(self.offset)
        remaining = self.count
        while remaining:
            count = min(remaining, BLOCK_VALUES)
            yield from read_floats(self.stream, self.dtype, count)
            remaining -= count


@dataclass
class WeightStatistics:
    count: int
    nonfinite_count: int = 0
    nonfinite_index: int = 0
    nonfinite_value: float = 0.0
    total: float = 0.0
    mean: float = 0.0
    variance: float = 0.0
    std: float = 0.0
    peak_index: int = 0
    peak_value: float = 0.0
    maximum_index: int = 0
    maximum: float = -math.inf
    minimum: float = math.inf
    z_max: float = 0.0
    kurtosis: float = 0.0
    sample: list[float] = field(default_factory=list)
    row_norms: list[float] = field(default_factory=list)
    row_count: int = 0
    max_row_norm: float = 0.0
    max_row_index: int = 0


def weight_statistics(values: list[float] | FloatTensorValues, shape: list[int]) -> WeightStatistics:
    """Full moments, extrema and row norms; only quantiles use a bounded sample.

    Two sequential passes avoid retaining a full model tensor or sorting its values.
    The sample spans the entire tensor, including both endpoints.
    """
    n = len(values)
    stats = WeightStatistics(n)
    sample_size = min(n, STAT_SAMPLE_SIZE)
    next_sample = 0
    for index, value in enumerate(values):
        if index == next_sample:
            stats.sample.append(value)
            next_sample = (len(stats.sample) * (n - 1) // (sample_size - 1)
                           if sample_size > 1 else n)
        if not math.isfinite(value):
            if not stats.nonfinite_count:
                stats.nonfinite_index, stats.nonfinite_value = index, value
            stats.nonfinite_count += 1
            continue
        stats.total += value
        if abs(value) > abs(stats.peak_value):
            stats.peak_index, stats.peak_value = index, value
        if value > stats.maximum:
            stats.maximum, stats.maximum_index = value, index
        stats.minimum = min(stats.minimum, value)

    if stats.nonfinite_count or n < 3 or abs(stats.peak_value) > 1e150:
        return stats
    stats.mean = stats.total / n
    scale = max(abs(stats.maximum - stats.mean), abs(stats.minimum - stats.mean))
    has_rows = (len(shape) >= 2 and all(type(size) is int and size > 0 for size in shape)
                and shape[0] >= 4 and math.prod(shape) == n and n // shape[0] >= 4)
    cols = n // shape[0] if has_rows else 0
    stats.row_count = shape[0] if has_rows else 0
    row_sample_size = min(stats.row_count, STAT_SAMPLE_SIZE)
    next_row_sample = 0
    second = fourth = row_squares = 0.0
    for index, value in enumerate(values):
        if scale:
            normalized = (value - stats.mean) / scale
            squared = normalized * normalized
            second += squared
            fourth += squared * squared
        if has_rows:
            row_squares += value * value
            if (index + 1) % cols == 0:
                row_norm, row_index = math.sqrt(row_squares), index // cols
                if row_norm > stats.max_row_norm:
                    stats.max_row_norm, stats.max_row_index = row_norm, row_index
                if row_index == next_row_sample:
                    stats.row_norms.append(row_norm)
                    next_row_sample = (len(stats.row_norms) * (stats.row_count - 1) // (row_sample_size - 1)
                                       if row_sample_size > 1 else stats.row_count)
                row_squares = 0.0
    scaled_variance = second / n
    stats.std = scale * math.sqrt(scaled_variance)
    stats.variance = stats.std * stats.std
    if stats.std > 1e-6:
        stats.z_max = scale / stats.std
        stats.kurtosis = (fourth / n) / (scaled_variance * scaled_variance) - 3.0
    return stats
