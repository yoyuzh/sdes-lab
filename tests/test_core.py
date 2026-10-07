import pytest

from sdes.constants import IP, IP_INVERSE, S0, S1
from sdes.core import (
    decrypt_block,
    decrypt_bytes,
    derive_subkeys,
    encrypt_block,
    encrypt_bytes,
    permute,
    sbox_lookup,
    trace_block,
)


def test_hand_calculated_subkeys():
    # P10=10000|01100, LS1=00001|11000, direct LS2=00010|10001.
    assert derive_subkeys(0b1010000010) == (0b10100100, 0b10010010)


def test_hand_calculated_block():
    # IP=11011101; first round=00101101; SW=11010010;
    # second round=10110010; inverse IP=11101000 (direct LS2 profile).
    assert encrypt_block(0b11010111, 0b1010000010) == 0b11101000
    assert decrypt_block(0b11101000, 0b1010000010) == 0b11010111
    trace = trace_block(0b11010111, 0b1010000010, "encrypt")
    assert trace.initial == 0b11011101
    assert trace.swapped == 0b11010010
    assert trace.output == 0b11101000


def test_inverse_permutation():
    for block in range(256):
        assert permute(permute(block, 8, IP), 8, IP_INVERSE) == block


@pytest.mark.parametrize("box", [S0, S1])
def test_every_sbox_entry(box):
    for row in range(4):
        for column in range(4):
            bits = ((row >> 1) << 3) | (column << 1) | (row & 1)
            assert sbox_lookup(bits, box) == box[row][column]
    assert S1[3] == (2, 1, 0, 3)
    assert S1[2] == (3, 0, 1, 2)  # Assignment-specific row 10, column 11 = 2.


def test_all_keys_and_blocks_are_invertible():
    data = bytes(range(256))
    for key in range(1024):
        encrypted = encrypt_bytes(data, key)
        assert len(set(encrypted)) == 256
        assert decrypt_bytes(encrypted, key) == data


@pytest.mark.parametrize("block,key", [(-1, 0), (256, 0), (0, -1), (0, 1024), (True, 0)])
def test_invalid_parameters(block, key):
    with pytest.raises(ValueError):
        encrypt_block(block, key)


def test_empty_and_bad_operation():
    assert encrypt_bytes(b"", 0) == b""
    assert decrypt_bytes(b"", 0) == b""
    with pytest.raises(ValueError):
        trace_block(0, 0, "other")


def test_direct_ls2_has_equivalent_key_pairs():
    # Under the assignment-formula profile, master-key bit 2 never enters P8.
    for key in range(512):
        assert derive_subkeys(key) == derive_subkeys(key ^ 256)
