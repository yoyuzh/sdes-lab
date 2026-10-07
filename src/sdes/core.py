"""Pure S-DES functions; the second subkey uses direct LS2 from the P10 result."""

from dataclasses import dataclass
from functools import lru_cache
from typing import Literal

from .constants import EP, IP, IP_INVERSE, P4, P8, P10, S0, S1


def validate_int(value: int, width: int, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < (1 << width):
        raise ValueError(f"{label}必须是 {width} 位整数（0–{(1 << width) - 1}）")


def permute(value: int, width: int, positions: tuple[int, ...]) -> int:
    """Select MSB-first positions from a fixed-width integer."""
    result = 0
    for position in positions:
        result = (result << 1) | ((value >> (width - position)) & 1)
    return result


def sbox_lookup(value: int, box: tuple[tuple[int, ...], ...]) -> int:
    """Outer bits select the row, inner bits the column."""
    row = ((value & 8) >> 2) | (value & 1)
    return box[row][(value >> 1) & 3]


def _rotate5(value: int, count: int) -> int:
    return ((value << count) | (value >> (5 - count))) & 31


@lru_cache(maxsize=1024)
def _subkeys(key: int) -> tuple[int, int]:
    permuted = permute(key, 10, P10)
    left, right = permuted >> 5, permuted & 31
    return tuple(permute((_rotate5(left, n) << 5) | _rotate5(right, n), 10, P8) for n in (1, 2))


def derive_subkeys(key: int) -> tuple[int, int]:
    """Return K1/K2 using independent one- and two-bit rotations."""
    validate_int(key, 10, "密钥")
    return _subkeys(key)


@dataclass(frozen=True)
class RoundTrace:
    subkey: int
    input: int
    expanded: int
    mixed: int
    s0: int
    s1: int
    p4: int
    output: int


def _round(value: int, subkey: int) -> RoundTrace:
    left, right = value >> 4, value & 15
    expanded = permute(right, 4, EP)
    mixed = expanded ^ subkey
    s0, s1 = sbox_lookup(mixed >> 4, S0), sbox_lookup(mixed & 15, S1)
    p4 = permute((s0 << 2) | s1, 4, P4)
    return RoundTrace(subkey, value, expanded, mixed, s0, s1, p4, ((left ^ p4) << 4) | right)


# Tables are computed by the same round function used for educational traces.
_ROUND_F = tuple(tuple(_round(right, subkey).p4 for right in range(16)) for subkey in range(256))
_IP = tuple(permute(block, 8, IP) for block in range(256))
_INVERSE = tuple(permute(block, 8, IP_INVERSE) for block in range(256))


def _encrypt_with_subkeys(block: int, subkeys: tuple[int, int]) -> int:
    value = _IP[block]
    left, right = value >> 4, value & 15
    left ^= _ROUND_F[subkeys[0]][right]
    left, right = right, left
    left ^= _ROUND_F[subkeys[1]][right]
    return _INVERSE[(left << 4) | right]


def encrypt_block(block: int, key: int) -> int:
    """Encrypt one 8-bit block with a 10-bit key."""
    validate_int(block, 8, "分组")
    return _encrypt_with_subkeys(block, derive_subkeys(key))


def decrypt_block(block: int, key: int) -> int:
    """Decrypt one block by reversing the subkey order."""
    validate_int(block, 8, "分组")
    first, second = derive_subkeys(key)
    return _encrypt_with_subkeys(block, (second, first))


def encrypt_bytes(data: bytes, key: int) -> bytes:
    """Encrypt independently, preserving length and all byte values."""
    subkeys = derive_subkeys(key)
    return bytes(_encrypt_with_subkeys(block, subkeys) for block in data)


def decrypt_bytes(data: bytes, key: int) -> bytes:
    """Decrypt independently; empty data is valid."""
    first, second = derive_subkeys(key)
    return bytes(_encrypt_with_subkeys(block, (second, first)) for block in data)


@dataclass(frozen=True)
class BlockTrace:
    operation: str
    input: int
    key: int
    subkeys: tuple[int, int]
    initial: int
    rounds: tuple[RoundTrace, RoundTrace]
    swapped: int
    output: int


def trace_block(block: int, key: int, operation: Literal["encrypt", "decrypt"]) -> BlockTrace:
    """Calculate each round and return its actual intermediate values."""
    validate_int(block, 8, "分组")
    keys = derive_subkeys(key)
    if operation not in ("encrypt", "decrypt"):
        raise ValueError("操作必须为 encrypt 或 decrypt")
    ordered = keys if operation == "encrypt" else keys[::-1]
    initial = _IP[block]
    first = _round(initial, ordered[0])
    swapped = ((first.output & 15) << 4) | (first.output >> 4)
    second = _round(swapped, ordered[1])
    return BlockTrace(
        operation, block, key, keys, initial, (first, second), swapped, _INVERSE[second.output]
    )
