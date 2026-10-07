"""Reproduce numerical evidence without claiming another group's cross-test."""

import json
import platform
from dataclasses import asdict
from pathlib import Path
from time import perf_counter

from PySide6 import __version__ as qt_version

from sdes.analysis import analyze_all_plaintexts, analyze_plaintext, brute_force
from sdes.constants import ALGORITHM
from sdes.core import decrypt_bytes, encrypt_block, encrypt_bytes, trace_block
from sdes.export import export_csv, export_json


def main() -> None:
    root = Path(__file__).resolve().parent / "evidence"
    for section in ("basic", "text", "bruteforce", "collision", "cross"):
        (root / section).mkdir(parents=True, exist_ok=True)

    timer = perf_counter()
    data = bytes(range(256))
    for key in range(1024):
        ciphertext = encrypt_bytes(data, key)
        assert len(set(ciphertext)) == 256
        assert decrypt_bytes(ciphertext, key) == data
    exhaustive_s = perf_counter() - timer
    trace = trace_block(215, 642, "encrypt")
    assert trace.output == 232
    basic = dict(
        algorithm=ALGORITHM,
        environment=dict(
            os=platform.platform(), python=platform.python_version(), pyside6=qt_version
        ),
        checked_combinations=1024 * 256,
        roundtrip_passed=True,
        permutation_passed=True,
        elapsed_s=exhaustive_s,
        trace=asdict(trace),
    )
    (root / "basic" / "exhaustive.json").write_text(
        json.dumps(basic, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    plain = "Hello, S-DES!"
    ciphertext = encrypt_bytes(plain.encode("ascii"), 642)
    restored = decrypt_bytes(ciphertext, 642).decode("ascii")
    assert encrypt_bytes(data, 642) == encrypt_bytes(data, 898)
    assert restored == plain
    (root / "text" / "roundtrip.json").write_text(
        json.dumps(
            dict(
                algorithm=ALGORITHM,
                key="1010000010",
                plaintext=plain,
                ciphertext_hex=ciphertext.hex(" ").upper(),
                restored=restored,
            ),
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    single = brute_force([(215, 232)])
    multiple = brute_force([(p, encrypt_block(p, 642)) for p in range(16)])
    collision = analyze_plaintext(215)
    full = analyze_all_plaintexts()
    for result, section, name in (
        (single, "bruteforce", "single-pair"),
        (multiple, "bruteforce", "multiple-pairs"),
        (collision, "collision", "single-plaintext"),
        (full, "collision", "all-plaintexts"),
    ):
        export_json(result, root / section / f"{name}.json")
        export_csv(result, root / section / f"{name}.csv")
    summary = dict(
        algorithm=ALGORITHM,
        exhaustive_s=exhaustive_s,
        single_candidates=list(single.candidates),
        multiple_candidates=list(multiple.candidates),
        equivalent_keys_642_898_on_all_plaintexts=True,
        reachable_min=min(row["reachable"] for row in full.rows),
        reachable_max=max(row["reachable"] for row in full.rows),
        max_bucket=max(row["max_bucket"] for row in full.rows),
        all_plaintexts_have_collisions=all(row["collision_buckets"] > 0 for row in full.rows),
        full_analysis_s=full.elapsed_s,
    )
    (root / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
