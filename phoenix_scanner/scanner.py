"""Pattern scanner with chunked reads, CPU baseline, optional GPU path.

Phase 1 (PatternRegistry): pass a ``pattern_registry`` to override or extend
the built-in pattern set without touching the core package.

Phase 2 (ScanWatcher + sandboxed): pass a ``watcher`` for per-file budget
enforcement and set ``sandboxed=True`` to isolate each file's scan in a
separate worker process with OS-level resource limits.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from phoenix_scanner.config import Config
from phoenix_scanner.crawler import ManifestEntry
from phoenix_scanner.patterns import PATTERNS, Pattern, build_keyword_pattern

if TYPE_CHECKING:
    from phoenix_scanner.registry import PatternRegistry
    from phoenix_scanner.watcher import ScanWatcher

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """One pattern match inside a file."""

    file_path: str
    match_type: str
    match_text: str  # may be redacted
    byte_offset: int
    line_number: int
    timestamp: str
    pattern_description: str


_REDACT_PLACEHOLDER = "<REDACTED>"


def _scan_chunk(
    chunk: bytes,
    base_offset: int,
    base_line: int,
    patterns: list[Pattern],
    redact: bool,
    file_path: str,
) -> list[Finding]:
    """Find all pattern matches in one chunk of bytes."""
    findings: list[Finding] = []
    text = chunk.decode("utf-8", errors="replace")
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Pre-compute newline positions for line number estimation
    newlines: list[int] = []
    for i, ch in enumerate(text):
        if ch == "\n":
            newlines.append(i)

    def _line_for_pos(pos: int) -> int:
        lo, hi = 0, len(newlines)
        while lo < hi:
            mid = (lo + hi) // 2
            if newlines[mid] < pos:
                lo = mid + 1
            else:
                hi = mid
        return base_line + lo + 1

    for pattern in patterns:
        for match in pattern.regex.finditer(text):
            matched_text = match.group(0)
            byte_offset = base_offset + match.start()
            line_no = _line_for_pos(match.start())
            findings.append(
                Finding(
                    file_path=file_path,
                    match_type=pattern.name,
                    match_text=_REDACT_PLACEHOLDER if redact else matched_text,
                    byte_offset=byte_offset,
                    line_number=line_no,
                    timestamp=ts,
                    pattern_description=pattern.description,
                )
            )
    return findings


def _scan_file_cpu(
    file_path: str,
    patterns: list[Pattern],
    *,
    chunk_size: int,
    max_bytes: int,
    redact: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    bytes_read = 0
    base_offset = 0
    base_line = 0

    try:
        with open(file_path, "rb") as fh:
            while bytes_read < max_bytes:
                remaining = max_bytes - bytes_read
                chunk = fh.read(min(chunk_size, remaining))
                if not chunk:
                    break
                chunk_findings = _scan_chunk(
                    chunk,
                    base_offset,
                    base_line,
                    patterns,
                    redact,
                    file_path,
                )
                findings.extend(chunk_findings)
                newline_count = chunk.count(b"\n")
                base_line += newline_count
                base_offset += len(chunk)
                bytes_read += len(chunk)
    except (OSError, PermissionError) as exc:
        logger.warning("Cannot read %s: %s", file_path, exc)

    return findings


def _scan_file_gpu(
    file_path: str,
    patterns: list[Pattern],
    *,
    max_bytes: int,
    redact: bool,
) -> list[Finding]:
    """GPU-accelerated scan using cuDF string operations.

    Falls back to CPU if cuDF is not available.
    """
    try:
        import cudf  # type: ignore[import]
    except ImportError:
        logger.debug("cuDF not available; falling back to CPU for %s", file_path)
        return _scan_file_cpu(
            file_path,
            patterns,
            chunk_size=256 * 1024,
            max_bytes=max_bytes,
            redact=redact,
        )

    findings: list[Finding] = []
    try:
        with open(file_path, "rb") as fh:
            raw = fh.read(max_bytes)
        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines(keepends=True)
        series = cudf.Series(lines)
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        for pattern in patterns:
            mask = series.str.contains(pattern.regex.pattern, regex=True)
            matched_lines = series[mask].to_pandas()
            for line_text in matched_lines:
                for m in pattern.regex.finditer(line_text):
                    findings.append(
                        Finding(
                            file_path=file_path,
                            match_type=pattern.name,
                            match_text=_REDACT_PLACEHOLDER if redact else m.group(0),
                            byte_offset=-1,  # not tracked in GPU path
                            line_number=-1,
                            timestamp=ts,
                            pattern_description=pattern.description,
                        )
                    )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "GPU scan failed for %s (%s: %s); falling back to CPU",
            file_path,
            type(exc).__name__,
            exc,
        )
        return _scan_file_cpu(
            file_path,
            patterns,
            chunk_size=256 * 1024,
            max_bytes=max_bytes,
            redact=redact,
        )

    return findings


def _resolve_patterns(
    config: Config,
    pattern_registry: "PatternRegistry | None",
) -> list[Pattern]:
    """Return the final pattern list from the registry or built-ins."""
    if pattern_registry is not None:
        patterns: list[Pattern] = pattern_registry.get_patterns()
    else:
        patterns = list(PATTERNS)

    # Always append config.extra_keywords on top of whatever source we used.
    kw_pattern = build_keyword_pattern(config.extra_keywords)
    if kw_pattern:
        patterns = patterns + [kw_pattern]
    return patterns


def _apply_watcher(
    findings: list[Finding],
    file_path: str,
    watcher: "ScanWatcher",
) -> list[Finding]:
    """Enforce per-file caps from *watcher*; return (possibly truncated) list."""
    cap = watcher.max_findings_per_file
    if cap > 0 and len(findings) > cap:
        watcher.alert(
            "max-findings-per-file",
            f"{file_path}: {len(findings)} findings exceed cap of {cap}; truncating",
        )
        findings = findings[:cap]
        watcher.alert("threshold-exceeded", f"findings cap hit for {file_path}")
    return findings


def _scan_one_file(
    entry: ManifestEntry,
    patterns: list[Pattern],
    config: Config,
) -> list[Finding]:
    """Scan a single manifest entry and return its findings."""
    if config.use_gpu:
        return _scan_file_gpu(
            entry.path,
            patterns,
            max_bytes=config.max_bytes_per_file,
            redact=config.redact_matches,
        )
    return _scan_file_cpu(
        entry.path,
        patterns,
        chunk_size=config.chunk_size,
        max_bytes=config.max_bytes_per_file,
        redact=config.redact_matches,
    )


# ---------------------------------------------------------------------------
# Module-level worker for ProcessPoolExecutor (must be picklable)
# ---------------------------------------------------------------------------


def _scan_file_worker(
    file_path: str,
    patterns: list[Pattern],
    chunk_size: int,
    max_bytes: int,
    redact: bool,
    use_gpu: bool,
) -> list[Finding]:
    """Picklable wrapper submitted to sandboxed worker processes."""
    if use_gpu:
        return _scan_file_gpu(file_path, patterns, max_bytes=max_bytes, redact=redact)
    return _scan_file_cpu(
        file_path, patterns, chunk_size=chunk_size, max_bytes=max_bytes, redact=redact
    )


def _worker_init_with_limits(cpu_seconds: int, max_memory_bytes: int) -> None:
    """Apply OS resource limits inside a worker process (Linux/macOS only).

    Silently skips on Windows or when the requested limit exceeds the hard
    limit enforced by the OS.
    """
    try:
        import resource as _resource  # noqa: PLC0415

        if cpu_seconds > 0:
            _resource.setrlimit(
                _resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds)
            )
        if max_memory_bytes > 0:
            try:
                _resource.setrlimit(
                    _resource.RLIMIT_AS, (max_memory_bytes, max_memory_bytes)
                )
            except ValueError:
                pass  # Requested limit exceeds hard limit
    except (ImportError, AttributeError):
        pass  # Windows or other platforms without the resource module


# ---------------------------------------------------------------------------
# Inline (non-sandboxed) scan loop
# ---------------------------------------------------------------------------


def _scan_inline(
    entries: Iterable[ManifestEntry],
    patterns: list[Pattern],
    config: Config,
    watcher: "ScanWatcher | None",
) -> list[Finding]:
    all_findings: list[Finding] = []
    for entry in entries:
        file_findings = _scan_one_file(entry, patterns, config)
        if watcher is not None:
            file_findings = _apply_watcher(file_findings, entry.path, watcher)
        all_findings.extend(file_findings)
    return all_findings


# ---------------------------------------------------------------------------
# Sandboxed scan loop (ProcessPoolExecutor + resource limits)
# ---------------------------------------------------------------------------


def _scan_sandboxed(
    entries: Iterable[ManifestEntry],
    patterns: list[Pattern],
    config: Config,
    watcher: "ScanWatcher | None",
) -> list[Finding]:
    time_budget = watcher.elapsed_time_budget if watcher else 0.0
    # Derive a CPU-second limit from the wall-clock budget (round up, min 1).
    cpu_limit = max(1, int(time_budget)) if time_budget > 0 else 0
    # Allow 4× the per-file byte cap as virtual address space headroom.
    mem_limit = config.max_bytes_per_file * 4

    all_findings: list[Finding] = []
    entries_list = list(entries)
    timeout: float | None = time_budget if time_budget > 0 else None

    with ProcessPoolExecutor(
        max_workers=os.cpu_count() or 4,
        initializer=_worker_init_with_limits,
        initargs=(cpu_limit, mem_limit),
    ) as pool:
        futures = [
            (
                pool.submit(
                    _scan_file_worker,
                    entry.path,
                    patterns,
                    config.chunk_size,
                    config.max_bytes_per_file,
                    config.redact_matches,
                    config.use_gpu,
                ),
                entry,
            )
            for entry in entries_list
        ]

        for future, entry in futures:
            try:
                file_findings: list[Finding] = future.result(timeout=timeout)
            except TimeoutError:
                logger.warning("Sandboxed worker timed out scanning %s", entry.path)
                future.cancel()
                if watcher:
                    watcher.alert(
                        "elapsed-time-budget",
                        f"Worker timeout ({time_budget}s) exceeded for {entry.path}",
                    )
                file_findings = []
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Sandboxed worker failed for %s: %s", entry.path, exc
                )
                file_findings = []

            if watcher is not None:
                file_findings = _apply_watcher(file_findings, entry.path, watcher)
            all_findings.extend(file_findings)

    return all_findings


# ---------------------------------------------------------------------------
# Public scan() entry point
# ---------------------------------------------------------------------------


def scan(
    entries: Iterable[ManifestEntry],
    config: Config,
    *,
    pattern_registry: "PatternRegistry | None" = None,
    watcher: "ScanWatcher | None" = None,
    sandboxed: bool = False,
) -> list[Finding]:
    """Scan all manifest entries and return findings.

    Parameters
    ----------
    entries:
        Iterable of :class:`~phoenix_scanner.crawler.ManifestEntry` objects.
    config:
        Scanner configuration (chunk size, byte cap, redaction, etc.).
    pattern_registry:
        Optional :class:`~phoenix_scanner.registry.PatternRegistry`.  When
        provided, its patterns replace the built-in ``PATTERNS`` list while
        ``config.extra_keywords`` is still appended on top.
    watcher:
        Optional :class:`~phoenix_scanner.watcher.ScanWatcher` that enforces
        per-file finding caps and elapsed-time budgets.
    sandboxed:
        When ``True`` (or when ``config.sandboxed`` is ``True``), each file
        is scanned inside a separate worker process so that malformed files,
        ReDoS patterns, or memory exhaustion cannot crash the caller.
        Resource limits are applied via ``resource.setrlimit`` on Linux/macOS.

    Returns
    -------
    list[Finding]
        Aggregated findings from all files.
    """
    all_patterns = _resolve_patterns(config, pattern_registry)

    use_sandboxed = sandboxed or config.sandboxed
    if use_sandboxed:
        return _scan_sandboxed(entries, all_patterns, config, watcher)
    return _scan_inline(entries, all_patterns, config, watcher)


def write_findings(findings: list[Finding], path: Path) -> None:
    """Write findings to a JSONL file.

    If *findings* is empty the file is **not** written, preventing a zero-row
    JSONL from being anchored (which would produce the e3b0c44… null digest).
    """
    if not findings:
        logger.info("No findings to write; skipping %s", path)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for finding in findings:
            fh.write(json.dumps(asdict(finding)) + "\n")
    logger.info("Wrote %d findings to %s", len(findings), path)


def read_findings(path: Path) -> list[Finding]:
    """Read findings from a JSONL file."""
    findings: list[Finding] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                findings.append(Finding(**json.loads(line)))
    return findings
