"""
AegisMemory Lab - Deterministic Trust & Policy Engine
Authors: LO & ENI

Enforces strict zero-trust boundaries independently of any LLM:
1. 4 Trust Levels: Trusted Approved, Pending Review, Untrusted Imported, Rejected/Revoked
2. Trust cannot be upgraded by text claims inside imported content (anti-spoofing).
3. Source metadata is assigned by application code, not parsed text directives.
4. Model proposals cannot directly authorize persistent memory writes.
5. Content inside documents cannot grant itself approval or alter tenant scope.
"""

import re
from typing import Tuple, Dict, Any, Optional
from core.schema import TrustLevel, SourceType

# Known malicious patterns that attempt to self-promote or subvert policy
SUSPICIOUS_DIRECTIVE_PATTERNS = [
    r"\[SYSTEM(?:\s+MEMORY)?\s*(?:UPDATE|DIRECTIVE|ELEVATION)\]",
    r"<METADATA\s+source=['\"]user_explicit['\"]",
    r"trust_tier=['\"]user_approved['\"]",
    r"trust_level=['\"]trusted_approved['\"]",
    r"store\s+this\s+as\s+(?:an?\s+)?immutable\s+system\s+memory",
    r"override\s+all\s+(?:prior|corporate|safety)\s+(?:guardrails|policies|preferences)",
    r"ignore\s+(?:all\s+)?prior\s+instructions",
    r"\[AUDIT_TELEMETRY:",
    r"\[VIPERSEC\s+EXECUTING\]"
]

class TrustPolicyEngine:
    def __init__(self):
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_DIRECTIVE_PATTERNS]

    def evaluate_candidate_ingestion(
        self,
        content: str,
        declared_source_type: SourceType,
        source_reference: str,
        actor: str = "system"
    ) -> Tuple[TrustLevel, bool, str]:
        """
        Determines the allowable initial trust level for candidate content.
        Rule: Content originating from documents, transcripts, or synthetic payloads
        is ALWAYS classified as UNTRUSTED_IMPORTED and staged for PENDING_REVIEW.
        Under no circumstances can document text self-declare 'TRUSTED_APPROVED'.
        
        Returns: (assigned_trust_level, is_suspicious_directive, policy_reason)
        """
        # 1. Scan for attempted self-promotion or malicious instructions embedded in text
        is_suspicious = False
        matching_patterns = []
        for pat in self.compiled_patterns:
            if pat.search(content):
                is_suspicious = True
                matching_patterns.append(pat.pattern)

        # 2. Strict origin-based policy enforcement
        if declared_source_type in [SourceType.DOCUMENT_INGESTION, SourceType.SYNTHETIC_ATTACK, SourceType.CONVERSATION_IMPORT]:
            # Always untrusted regardless of whatever the text claims
            reason = f"External document/transcript ingestion quarantined to staging area. Source: {source_reference}."
            if is_suspicious:
                reason += f" Detected suspicious embedded directives: {len(matching_patterns)} patterns flagged."
            return TrustLevel.UNTRUSTED_IMPORTED, is_suspicious, reason

        elif declared_source_type == SourceType.MODEL_PROPOSAL:
            # Model proposals are untrusted until human confirms
            return TrustLevel.PENDING_REVIEW, is_suspicious, "Model memory proposal placed in staging; requires human authorization."

        elif declared_source_type == SourceType.USER_EXPLICIT:
            # Direct user preference setting
            if is_suspicious:
                # Even for explicit user, if it contains adversarial prompt injection tokens, flag for confirmation
                return TrustLevel.PENDING_REVIEW, True, "Explicit user input flagged with system prompt injection signatures; held for verification."
            return TrustLevel.TRUSTED_APPROVED, False, "Explicit authorized user preference approved."

        return TrustLevel.UNTRUSTED_IMPORTED, is_suspicious, "Default untrusted fallback."

    def validate_approval_transition(
        self,
        current_level: TrustLevel,
        target_level: TrustLevel,
        actor: str,
        is_admin: bool = False
    ) -> Tuple[bool, str]:
        """
        Validates whether a trust level upgrade/downgrade transition is permitted.
        Rule: Only authorized human actors can promote PENDING_REVIEW to TRUSTED_APPROVED.
        Automated pipelines or untrusted scripts cannot execute transitions.
        """
        if current_level == target_level:
            return True, "No transition required."

        if target_level == TrustLevel.TRUSTED_APPROVED:
            if current_level not in [TrustLevel.PENDING_REVIEW, TrustLevel.UNTRUSTED_IMPORTED]:
                return False, f"Illegal transition: Cannot promote from {current_level.value} directly to {target_level.value}."
            if actor in ["system_auto", "ai_model", "untrusted_pipeline", "document_parser"]:
                return False, f"Unauthorized promotion actor: '{actor}'. Only explicit human review can authorize trusted persistent memory."
            return True, f"Memory promoted to {target_level.value} by authorized reviewer '{actor}'."

        if target_level in [TrustLevel.REJECTED_REVOKED, TrustLevel.PENDING_REVIEW]:
            return True, f"Memory transitioned from {current_level.value} to {target_level.value} by '{actor}'."

        return False, "Unrecognized transition requested."
