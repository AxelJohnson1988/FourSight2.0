"""Pattern scanner with chunked reads, CPU baseline, optional GPU path."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from phoenix_scanner.config import Config
from phoenix_scanner.crawler import ManifestEntry
from phoenix_scanner.patterns import PATTERNS, Pattern, build_keyword_pattern

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
        logger.warning("GPU scan failed for %s (%s); falling back to CPU", file_path, exc)
        return _scan_file_cpu(
            file_path,
            patterns,
            chunk_size=256 * 1024,
            max_bytes=max_bytes,
            redact=redact,
        )

    return findings


def scan(
    entries: Iterable[ManifestEntry],
    config: Config,
) -> list[Finding]:
    """Scan all manifest entries and return findings."""
    all_patterns: list[Pattern] = list(PATTERNS)
    kw_pattern = build_keyword_pattern(config.extra_keywords)
    if kw_pattern:
        all_patterns.append(kw_pattern)

    all_findings: list[Finding] = []

    for entry in entries:
        if config.use_gpu:
            findings = _scan_file_gpu(
                entry.path,
                all_patterns,
                max_bytes=config.max_bytes_per_file,
                redact=config.redact_matches,
            )
        else:
            findings = _scan_file_cpu(
                entry.path,
                all_patterns,
                chunk_size=config.chunk_size,
                max_bytes=config.max_bytes_per_file,
                redact=config.redact_matches,
            )
        all_findings.extend(findings)

    return all_findings


def write_findings(findings: list[Finding], path: Path) -> None:
    """Write findings to a JSONL file."""
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
