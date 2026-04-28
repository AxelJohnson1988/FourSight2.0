"""gpam.vl_llm — Verification Layer above an LLM (VL-LLM v0.1).

Wraps an LLM and enforces truth-maintenance, provenance, and consistency
guarantees externally (§0).  Never assumes the LLM can be made truthful.

Quick start
-----------
>>> from gpam.vl_llm import VerificationPipeline, StubLLMAdapter
>>> pipe = VerificationPipeline(llm_adapter=StubLLMAdapter(["Sky is blue."]))
>>> result = pipe.run("Describe the sky.", scope={"domain": "science"})
>>> result.draft_only  # False when PAL is reachable
False
"""

from gpam.vl_llm.audit_ledger import AuditLedger, PalAppendResult, PalRecord
from gpam.vl_llm.claim_extractor import ClaimExtractor, ExtractionResult
from gpam.vl_llm.closure_engine import ClosureEngine, ClosureResult, ProofStep
from gpam.vl_llm.commitment_gate import (
    ClaimMetrics,
    CommitmentGate,
    CommitmentPolicy,
    CommitmentResult,
)
from gpam.vl_llm.evidence_store import (
    AddArtifactResult,
    FilesystemEvidenceStore,
    InMemoryEvidenceStore,
)
from gpam.vl_llm.llm_adapter import LLMAdapter, LLMInput, LLMResponse, StubLLMAdapter
from gpam.vl_llm.pipeline import EvidenceBinding, PipelineResult, VerificationPipeline
from gpam.vl_llm.types import (
    BeliefState,
    Claim,
    ClaimRelation,
    ClaimStatus,
    EvidenceItem,
    Justification,
    RelationType,
    artifact_hash_for,
    canonical_json,
    claim_id_for,
    evidence_id_for,
    sha256_cj,
)

__all__ = [
    # Pipeline
    "VerificationPipeline",
    "PipelineResult",
    "EvidenceBinding",
    # Adapters
    "LLMAdapter",
    "LLMInput",
    "LLMResponse",
    "StubLLMAdapter",
    # Extractor
    "ClaimExtractor",
    "ExtractionResult",
    # Evidence
    "InMemoryEvidenceStore",
    "FilesystemEvidenceStore",
    "AddArtifactResult",
    # Gate
    "CommitmentGate",
    "CommitmentPolicy",
    "CommitmentResult",
    "ClaimMetrics",
    # Closure
    "ClosureEngine",
    "ClosureResult",
    "ProofStep",
    # Ledger
    "AuditLedger",
    "PalRecord",
    "PalAppendResult",
    # Types
    "Claim",
    "ClaimStatus",
    "ClaimRelation",
    "RelationType",
    "EvidenceItem",
    "Justification",
    "BeliefState",
    "canonical_json",
    "sha256_cj",
    "claim_id_for",
    "evidence_id_for",
    "artifact_hash_for",
]
