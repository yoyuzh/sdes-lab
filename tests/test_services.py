import json

import pytest

from sdes.analysis import analyze_all_plaintexts, analyze_plaintext, brute_force
from sdes.codecs import ascii_bytes, parse_bits, parse_hex, preview_bytes
from sdes.core import encrypt_block
from sdes.export import export_csv, export_json


def test_formats():
    assert parse_bits(" 00000001 ", 8) == 1
    assert parse_hex("00 7f\nFF") == bytes([0, 127, 255])
    assert parse_hex("") == b""
    assert ascii_bytes("Hi\n") == b"Hi\n"
    assert preview_bytes(b"A\x00\xff") == "A\\x00\\xff"


@pytest.mark.parametrize("value", ["1", "0000000x", "0000 0000"])
def test_bad_bits(value):
    with pytest.raises(ValueError):
        parse_bits(value, 8)


@pytest.mark.parametrize("value", ["0", "GG", "A B", "０１"])
def test_bad_hex(value):
    with pytest.raises(ValueError):
        parse_hex(value)


def test_ascii_error():
    with pytest.raises(ValueError, match="ASCII"):
        ascii_bytes("中文")


def test_search_returns_all_candidates_and_multiple_pairs():
    pair = (0b11010111, 0b11101000)
    result = brute_force([pair])
    assert result.status == "complete" and result.checked == 1024
    assert 0b1010000010 in result.candidates
    assert result.candidates == tuple(
        k for k in range(1024) if encrypt_block(pair[0], k) == pair[1]
    )
    pairs = [(p, encrypt_block(p, 642)) for p in range(16)]
    narrowed = brute_force(pairs)
    assert 642 in narrowed.candidates
    assert all(all(encrypt_block(p, k) == c for p, c in pairs) for k in narrowed.candidates)


def test_input_pairs_and_cancellation():
    for pairs in ([], [(0, 0), (0, 1)], [(256, 0)]):
        with pytest.raises(ValueError):
            brute_force(pairs)
    assert brute_force([(0, 0)], cancelled=lambda: True).status == "cancelled"
    assert analyze_plaintext(0, cancelled=lambda: True).checked == 0
    assert analyze_all_plaintexts(cancelled=lambda: True).status == "cancelled"


def test_collision_counts_and_instances():
    result = analyze_plaintext(215)
    assert result.checked == 1024
    assert sum(len(keys) for keys in result.buckets.values()) == 1024
    assert sorted(k for keys in result.buckets.values() for k in keys) == list(range(1024))
    assert result.collision_buckets > 0
    for cipher, keys in result.buckets.items():
        assert all(encrypt_block(215, key) == cipher for key in keys)


def test_all_plaintext_statistics():
    result = analyze_all_plaintexts()
    assert result.status == "complete" and len(result.rows) == 256
    assert [row["plaintext"] for row in result.rows] == list(range(256))
    assert all(row["collision_buckets"] > 0 for row in result.rows)


def test_exports_keep_exact_data(tmp_path):
    result = brute_force([(215, 232)])
    path = tmp_path / "result.json"
    export_json(result, path)
    data = json.loads(path.read_text())
    assert data["result"]["checked"] == 1024
    assert data["algorithm"] == "shimo-direct-ls2-v1"
    csv_path = tmp_path / "result.csv"
    export_csv(result, csv_path)
    assert "1010000010" in csv_path.read_text()
    assert "11010111:11101000" in csv_path.read_text()
    assert result.started_at.endswith("+08:00")
    with pytest.raises(OSError):
        export_json(result, tmp_path / "missing" / "result.json")


def test_collision_csv_and_cancelled_exports(tmp_path):
    from sdes.analysis import RunResult

    for result in (
        analyze_plaintext(0),
        analyze_all_plaintexts(),
        analyze_plaintext(0, cancelled=lambda: True),
        analyze_all_plaintexts(cancelled=lambda: True),
        brute_force([(0, 0)], cancelled=lambda: True),
    ):
        export_csv(result, tmp_path / "out.csv")
        assert result.status in (tmp_path / "out.csv").read_text()
    with pytest.raises(ValueError):
        export_csv(RunResult("complete", "start", "end", 0.0), tmp_path / "out.csv")
