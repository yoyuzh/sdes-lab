"""Lossless, atomic JSON/CSV result export."""

import csv
import json
import os
import platform
import tempfile
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import TextIO

from . import __version__
from .analysis import CollisionResult, FullAnalysisResult, RunResult, SearchResult
from .constants import ALGORITHM


def _write_atomic(path: Path, writer: Callable[[TextIO], None]) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", dir=path.parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
            writer(stream)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def export_json(result: RunResult, path: Path) -> None:
    """Write precise inputs, result state, algorithm identity and environment."""
    from PySide6 import __version__ as qt_version

    payload = dict(
        algorithm=ALGORITHM,
        app_version=__version__,
        kind=type(result).__name__,
        environment=dict(
            os=platform.platform(), python=platform.python_version(), pyside6=qt_version
        ),
        result=asdict(result),
    )
    _write_atomic(
        Path(path), lambda stream: json.dump(payload, stream, ensure_ascii=False, indent=2)
    )


def export_csv(result: RunResult, path: Path) -> None:
    """Export rows and run metadata; binary values are zero-padded text."""
    metadata = dict(
        algorithm=ALGORITHM,
        status=result.status,
        elapsed_s=result.elapsed_s,
        started_at=result.started_at,
        finished_at=result.finished_at,
    )
    if isinstance(result, SearchResult):
        metadata["pairs"] = ";".join(f"{p:08b}:{c:08b}" for p, c in result.pairs)
        rows = [dict(key=f"{key:010b}", checked=result.checked) for key in result.candidates]
        if not rows:
            rows = [dict(key="", checked=result.checked)]
    elif isinstance(result, CollisionResult):
        rows = [
            dict(
                plaintext=f"{result.plaintext:08b}",
                ciphertext=f"{cipher:08b}",
                key_count=len(keys),
                keys=" ".join(f"{key:010b}" for key in keys),
                checked=result.checked,
            )
            for cipher, keys in result.buckets.items()
        ]
        if not rows:
            rows = [dict(plaintext=f"{result.plaintext:08b}", checked=result.checked)]
    elif isinstance(result, FullAnalysisResult):
        rows = [
            dict(
                row,
                plaintext=f"{row['plaintext']:08b}",
                sample_cipher=f"{row['sample_cipher']:08b}",
                sample_keys=" ".join(f"{key:010b}" for key in row["sample_keys"]),
                checked=result.checked,
            )
            for row in result.rows
        ]
        if not rows:
            rows = [dict(checked=result.checked)]
    else:
        raise ValueError("不支持该结果类型")
    records = [dict(metadata, **row) for row in rows]

    def write(stream: TextIO) -> None:
        writer = csv.DictWriter(stream, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)

    _write_atomic(Path(path), write)
