"""GPAM — Sovereign Knowledge Memory Pipeline.

Phase 1 — local, Git-first; no external write authority:
    MemoryBlock           canonical schema + tamper-evident hash
    verified_memory_gate  Verified Memory Gate (VMG) enforcement
    build_memory_block    factory with ID generation
    NotebookLM exporter   batch Markdown for manual import; outputs committed to Git

Phase 2A — Verification Engine:
    VerificationEngine    multi-source fetch, TF-IDF similarity, domain diversity

External systems (Adobe Spaces, NotebookLM) are ephemeral surfaces.
Nothing is canonical until committed to Git.
"""

from gpam.memory_block import MemoryBlock, MemoryStatus
from gpam.memory_block_builder import BuildInput, build_memory_block, write_memory_block_json
from gpam.notebooklm_batch_runner import (
    BatchPolicy,
    create_batches,
    export_batch_markdown,
    require_verified,
)
from gpam.verification_engine import EngineResult, SourceResult, VerificationEngine
from gpam.verified_memory_gate import VmgPolicy, VmgResult, verified_memory_gate

__all__ = [
    "BatchPolicy",
    "BuildInput",
    "EngineResult",
    "MemoryBlock",
    "MemoryStatus",
    "SourceResult",
    "VerificationEngine",
    "VmgPolicy",
    "VmgResult",
    "build_memory_block",
    "create_batches",
    "export_batch_markdown",
    "require_verified",
    "verified_memory_gate",
    "write_memory_block_json",
]
