"""Read floating-point SafeTensors in bounded blocks without loading a model."""
from __future__ import annotations

import array
from dataclasses import dataclass, field
import math
import struct
import sys
from typing import BinaryIO

FLOAT_FORMATS = {"F16": ("e", 2), "BF16": ("f", 2), "F32": ("f", 4), "F64": ("d", 8)}
BLOCK_VALUES = 65536
SAMPLE_VALUES = 16384
SAMPLE_ROWS = 65536
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


def _squared_sum(values) -> float:
    if hasattr(math, "sumprod"):
        return math.sumprod(values, values)
    return math.fsum(value * value for value in values)


def _blocks(stream, dtype, start, count):
    stream.seek(start)
    for offset in range(0, count, BLOCK_VALUES):
        yield offset, read_floats(stream, dtype, min(BLOCK_VALUES, count - offset))


@dataclass
class WeightStats:
    sample: list[float] = field(default_factory=list)
    nonfinite_count: int = 0
    first_nonfinite: tuple[int, float] | None = None
    out_of_range: bool = False
    mean: float = 0.0
    variance: float = 0.0
    minimum: float = math.inf
    maximum: float = -math.inf
    maximum_index: int = 0
    peak_value: float = 0.0
    peak_index: int = 0
    row_peak: float = 0.0
    row_peak_index: int = 0
    row_median: float = 0.0
    kurtosis: float | None = None


def analyze_float_stream(stream: BinaryIO, dtype: str, start: int, shape: list[int]) -> WeightStats:
    count = math.prod(shape)
    stats = WeightStats()
    sample_stride = math.ceil(count / SAMPLE_VALUES)
    rows = shape[0] if len(shape) >= 2 else 0
    columns = count // rows if rows >= 4 else 0
    row_stride = math.ceil(rows / SAMPLE_ROWS) if columns >= 4 else 1
    row_norms = []
    row_square_sum = 0.0
    total, square_sum = 0.0, 0.0

    for offset, block in _blocks(stream, dtype, start, count):
        if not all(map(math.isfinite, block)):
            for index, value in enumerate(block, offset):
                if not math.isfinite(value):
                    stats.nonfinite_count += 1
                    if stats.first_nonfinite is None:
                        stats.first_nonfinite = (index, value)
            continue
        if stats.first_nonfinite is not None:
            continue

        high, low = max(block), min(block)
        if high > stats.maximum:
            stats.maximum = high
            stats.maximum_index = offset + block.index(high)
        stats.minimum = min(stats.minimum, low)
        peak = high if abs(high) >= abs(low) else low
        if abs(peak) > abs(stats.peak_value):
            stats.peak_value = peak
            stats.peak_index = offset + block.index(peak)

        # Bound the unscaled second moment even at the largest supported file size.
        stats.out_of_range |= abs(peak) > 1e140
        if stats.out_of_range:
            continue
        total += math.fsum(block)
        stats.sample.extend(block[(-offset) % sample_stride :: sample_stride])
        if columns < 4:
            square_sum += _squared_sum(block)
            continue

        cursor = 0
        while cursor < len(block):
            row, within_row = divmod(offset + cursor, columns)
            length = min(columns - within_row, len(block) - cursor)
            row_square_sum += _squared_sum(block[cursor : cursor + length])
            cursor += length
            if within_row + length == columns:
                square_sum += row_square_sum
                norm = math.sqrt(row_square_sum)
                if norm > stats.row_peak:
                    stats.row_peak, stats.row_peak_index = norm, row
                if row % row_stride == 0:
                    row_norms.append(norm)
                row_square_sum = 0.0

    if stats.first_nonfinite is not None or stats.out_of_range:
        return stats
    stats.mean = total / count
    stats.variance = max(square_sum / count - stats.mean**2, 0.0)
    if row_norms:
        row_norms.sort()
        stats.row_median = row_norms[len(row_norms) // 2]
    if abs(stats.peak_value) > 8 and stats.variance > 1e-12:
        std = math.sqrt(stats.variance)
        fourth = math.fsum(
            math.fsum(((value - stats.mean) / std)**4 for value in block)
            for _, block in _blocks(stream, dtype, start, count)
        )
        stats.kurtosis = fourth / count - 3.0
    return stats
