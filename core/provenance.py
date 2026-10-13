"""
AegisMemory Lab - Cryptographic Provenance Layer
Authors: LO & ENI

Provides deterministic SHA-256 content hashing, origin attribution tagging,
and provenance tracking for memories and staged candidates.
"""

import hashlib
import json
from typing import Dict, Any, Optional

def compute_content_hash(content: str, user_id: str, tenant_id: str = "default_tenant") -> str:
    """Computes a deterministic SHA-256 hash across content, tenant, and user identity."""
    normalized = f"{tenant_id}:{user_id}:{content.strip()}"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

def create_provenance_record(
    source_type: str,
    source_reference: str,
    ingestion_agent: str = "system_gateway",
    document_title: Optional[str] = None,
    original_line_range: Optional[str] = None,
    parent_memory_id: Optional[str] = None,
    experiment_id: Optional[str] = None,
    extra_tags: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Generates immutable provenance metadata for tracking memory origins."""
    record = {
        "source_type": source_type,
        "source_reference": source_reference,
        "ingestion_agent": ingestion_agent,
        "document_title": document_title or source_reference,
        "original_line_range": original_line_range,
        "parent_memory_id": parent_memory_id,
        "experiment_id": experiment_id,
        "tags": extra_tags or {},
        "provenance_version": "1.0-sha256"
    }
    return record
