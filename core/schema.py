"""
AegisMemory Lab - Data Schema & Type Definitions
Authors: LO & ENI

Pydantic schemas and enums for memories, audit logs, scenarios, experiments, findings, and metrics.
"""

from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

class TrustLevel(str, Enum):
    TRUSTED_APPROVED = "trusted_approved"        # Level 1: Explicitly human-approved persistent memory
    PENDING_REVIEW = "pending_review"            # Level 2: Staged candidate awaiting human approval
    UNTRUSTED_IMPORTED = "untrusted_imported"    # Level 3: Raw document or conversation extract
    REJECTED_REVOKED = "rejected_revoked"        # Level 4: Rejected, revoked, or quarantined memory

class SourceType(str, Enum):
    USER_EXPLICIT = "user_explicit"              # Direct intentional user input
    DOCUMENT_INGESTION = "document_ingestion"    # Synthetic/uploaded document extract
    CONVERSATION_IMPORT = "conversation_import"  # Historical transcript import
    MODEL_PROPOSAL = "model_proposal"            # Model suggested memory write
    SYNTHETIC_ATTACK = "synthetic_attack"        # Adversarial test vector payload

class MemoryMode(str, Enum):
    DISABLED = "disabled"                        # Mode A: Stateless baseline (zero retrieval or write)
    ENABLED = "enabled"                          # Mode B: Approved memories for current identity retrieved
    USER_ISOLATED = "user_isolated"              # Mode C: Strict namespace boundary per user/tenant
    UNTRUSTED_STAGING = "untrusted_staging"      # Mode D: Imported content stages candidates, never writes trusted

class LifecycleStatus(str, Enum):
    ACTIVE = "active"
    STAGED = "staged"
    ARCHIVED = "archived"
    DELETED = "deleted"

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class MemoryRecord(BaseModel):
    id: str
    tenant_id: str = "default_tenant"
    user_id: str
    content: str
    category: str = "general_preference"
    source_type: SourceType
    source_reference: str = ""
    trust_level: TrustLevel
    approval_status: str = "pending" # 'pending', 'approved', 'rejected'
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    provenance_metadata: Dict[str, Any] = Field(default_factory=dict)
    experiment_id: Optional[str] = None
    content_hash: str
    lifecycle_status: LifecycleStatus = LifecycleStatus.ACTIVE
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    deleted_at: Optional[datetime] = None

class CandidateMemory(BaseModel):
    id: str
    tenant_id: str = "default_tenant"
    user_id: str
    proposed_content: str
    category: str = "general_preference"
    source_type: SourceType
    source_reference: str = ""
    suggested_trust_level: TrustLevel = TrustLevel.UNTRUSTED_IMPORTED
    content_hash: str
    provenance_metadata: Dict[str, Any] = Field(default_factory=dict)
    experiment_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class AuditLogEntry(BaseModel):
    id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str # 'CANDIDATE_CREATED', 'APPROVED', 'REJECTED', 'DELETED', 'RETRIEVED', 'EXPERIMENT_RUN', 'POLICY_VIOLATION'
    actor: str
    tenant_id: str = "default_tenant"
    object_reference: Optional[str] = None
    experiment_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    status: str = "SUCCESS"
    previous_hash: Optional[str] = None
    entry_hash: Optional[str] = None

class Scenario(BaseModel):
    id: str
    title: str
    category: str
    description: str
    document_content: str
    injected_directive: Optional[str] = None
    trigger_prompt: str
    expected_clean_behavior: str
    malicious_indicator: str
    is_benign: bool = False
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class SecurityFinding(BaseModel):
    id: str
    experiment_id: str
    run_id: str
    rule_id: str
    title: str
    severity: SeverityLevel
    expected_behavior: str
    observed_behavior: str
    evidence: str
    detector_confidence: float = 1.0 # 0.0 to 1.0
    verification_status: str = "CONFIRMED" # 'CONFIRMED', 'SUSPICIOUS_HEURISTIC', 'INCONCLUSIVE'
    remediation_guidance: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
