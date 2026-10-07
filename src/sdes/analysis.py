"""Complete key search and collision statistics with cooperative cancellation."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from time import perf_counter
from typing import Protocol, TypedDict

from .core import _encrypt_with_subkeys, derive_subkeys, validate_int

Progress = Callable[[int, int], None]
Cancelled = Callable[[], bool]


class CollisionRow(TypedDict):
    plaintext: int
    reachable: int
    collision_buckets: int
    max_bucket: int
    sample_cipher: int
    sample_keys: tuple[int, int]


class RunMetadata(TypedDict):
    status: str
    started_at: str
    finished_at: str
    elapsed_s: float


def _now() -> str:
    return datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="milliseconds")


@dataclass(frozen=True)
class RunResult:
    status: str
    started_at: str
    finished_at: str
    elapsed_s: float


@dataclass(frozen=True)
class SearchResult(RunResult):
    pairs: tuple[tuple[int, int], ...]
    candidates: tuple[int, ...]
    checked: int


@dataclass(frozen=True)
class CollisionResult(RunResult):
    plaintext: int
    buckets: dict[int, tuple[int, ...]]
    checked: int

    @property
    def collision_buckets(self) -> int:
        return sum(len(keys) > 1 for keys in self.buckets.values())

    @property
    def max_bucket(self) -> int:
        return max((len(keys) for keys in self.buckets.values()), default=0)


@dataclass(frozen=True)
class FullAnalysisResult(RunResult):
    rows: tuple[CollisionRow, ...]
    checked: int


AnalysisResult = SearchResult | CollisionResult | FullAnalysisResult


class AnalysisTask(Protocol):
    def __call__(
        self, *, progress: Progress | None = None, cancelled: Cancelled | None = None
    ) -> AnalysisResult: ...


def _metadata(started: str, timer: float, complete: bool) -> RunMetadata:
    return dict(
        status="complete" if complete else "cancelled",
        started_at=started,
        finished_at=_now(),
        elapsed_s=perf_counter() - timer,
    )


def validate_pairs(pairs: Sequence[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    if not pairs:
        raise ValueError("请至少输入一组明文和密文")
    seen: dict[int, int] = {}
    for plain, cipher in pairs:
        validate_int(plain, 8, "明文")
        validate_int(cipher, 8, "密文")
        if plain in seen and seen[plain] != cipher:
            raise ValueError("同一个明文对应不同密文，输入存在矛盾")
        seen[plain] = cipher
    return tuple(seen.items())


def brute_force(
    pairs: Sequence[tuple[int, int]],
    progress: Progress | None = None,
    cancelled: Cancelled | None = None,
) -> SearchResult:
    """Return every key satisfying all pairs, never stopping at the first match."""
    pairs = validate_pairs(pairs)
    started, timer = _now(), perf_counter()
    candidates, checked = [], 0
    for key in range(1024):
        if cancelled and cancelled():
            break
        subkeys = derive_subkeys(key)
        if all(_encrypt_with_subkeys(plain, subkeys) == cipher for plain, cipher in pairs):
            candidates.append(key)
        checked += 1
        if progress and (checked % 32 == 0 or checked == 1024):
            progress(checked, 1024)
    return SearchResult(
        **_metadata(started, timer, checked == 1024),
        pairs=pairs,
        candidates=tuple(candidates),
        checked=checked,
    )


def analyze_plaintext(
    block: int, progress: Progress | None = None, cancelled: Cancelled | None = None
) -> CollisionResult:
    """Partition the entire keyspace by ciphertext for a single plaintext."""
    validate_int(block, 8, "明文")
    started, timer = _now(), perf_counter()
    buckets: dict[int, list[int]] = {}
    checked = 0
    for key in range(1024):
        if cancelled and cancelled():
            break
        cipher = _encrypt_with_subkeys(block, derive_subkeys(key))
        buckets.setdefault(cipher, []).append(key)
        checked += 1
        if progress and (checked % 32 == 0 or checked == 1024):
            progress(checked, 1024)
    return CollisionResult(
        **_metadata(started, timer, checked == 1024),
        plaintext=block,
        buckets={c: tuple(keys) for c, keys in sorted(buckets.items())},
        checked=checked,
    )


def analyze_all_plaintexts(
    progress: Progress | None = None, cancelled: Cancelled | None = None
) -> FullAnalysisResult:
    """Summarize all plaintexts; partial groups are not reported as complete rows."""
    started, timer = _now(), perf_counter()
    rows, checked = [], 0
    for plain in range(256):
        result = analyze_plaintext(plain, cancelled=cancelled)
        checked += result.checked
        if result.status != "complete":
            break
        cipher, keys = next((c, ks) for c, ks in result.buckets.items() if len(ks) > 1)
        rows.append(
            dict(
                plaintext=plain,
                reachable=len(result.buckets),
                collision_buckets=result.collision_buckets,
                max_bucket=result.max_bucket,
                sample_cipher=cipher,
                sample_keys=(keys[0], keys[1]),
            )
        )
        if progress:
            progress(checked, 256 * 1024)
    return FullAnalysisResult(
        **_metadata(started, timer, len(rows) == 256), rows=tuple(rows), checked=checked
    )
