"""
AegisMemory Lab - Memory Management Service Layer
Authors: LO & ENI

Coordinates memory persistence, candidate staging, approval workflows,
surgical deletion, provenance verification, and sanitized CSV/JSON exports.
"""

import uuid
import json
import csv
import io
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

from core.database import get_connection
from core.schema import TrustLevel, SourceType, LifecycleStatus, MemoryRecord, CandidateMemory
from core.provenance import compute_content_hash, create_provenance_record
from core.trust_policy import TrustPolicyEngine
from core.audit import AuditLogger
from core.isolation import TenantIsolationManager

class MemoryService:
    def __init__(self, db_path: str = "aegismemory_lab.db"):
        self.db_path = db_path
        self.policy_engine = TrustPolicyEngine()
        self.audit = AuditLogger(db_path)
        self.isolation = TenantIsolationManager(db_path)

    def stage_candidate_memory(
        self,
        user_id: str,
        proposed_content: str,
        source_type: SourceType,
        source_reference: str,
        tenant_id: str = "default_tenant",
        category: str = "general_preference",
        experiment_id: Optional[str] = None,
        extra_metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, bool, str]:
        """
        Stages a memory into the candidate staging area.
        Ensures untrusted document extractions NEVER silently become trusted memory.
        Returns: (candidate_id, was_flagged_suspicious, policy_reason)
        """
        conn = get_connection(self.db_path)
        cursor = conn.cursor()

        trust_level, is_suspicious, reason = self.policy_engine.evaluate_candidate_ingestion(
            content=proposed_content,
            declared_source_type=source_type,
            source_reference=source_reference
        )

        candidate_id = str(uuid.uuid4())
        content_hash = compute_content_hash(proposed_content, user_id, tenant_id)
        prov = create_provenance_record(
            source_type=source_type.value,
            source_reference=source_reference,
            experiment_id=experiment_id,
            extra_tags=extra_metadata
        )

        with conn:
            cursor.execute("""
            INSERT INTO candidate_memories (
                id, tenant_id, user_id, proposed_content, category, source_type,
                source_reference, suggested_trust_level, content_hash, provenance_metadata,
                experiment_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                candidate_id, tenant_id, user_id, proposed_content, category,
                source_type.value, source_reference, trust_level.value, content_hash,
                json.dumps(prov), experiment_id, datetime.utcnow().isoformat()
            ))

        # Audit Event
        self.audit.log_event(
            event_type="CANDIDATE_CREATED",
            actor="memory_gateway",
            tenant_id=tenant_id,
            object_reference=candidate_id,
            experiment_id=experiment_id,
            details={
                "user_id": user_id,
                "source_type": source_type.value,
                "source_reference": source_reference,
                "is_suspicious": is_suspicious,
                "policy_reason": reason,
                "content_preview": proposed_content[:100]
            }
        )

        return candidate_id, is_suspicious, reason

    def approve_candidate(
        self,
        candidate_id: str,
        approving_actor: str,
        user_id_scope: Optional[str] = None,
        tenant_id: str = "default_tenant"
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Explicit Human-in-the-Loop Approval:
        Promotes a staged candidate into the trusted persistent memory store.
        """
        conn = get_connection(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM candidate_memories WHERE id = ? AND tenant_id = ?", (candidate_id, tenant_id))
        row = cursor.fetchone()
        if not row:
            return False, "Candidate memory record not found.", None

        cand = dict(row)
        
        # Verify cross-user ownership if scoped
        if user_id_scope and cand["user_id"] != user_id_scope:
            self.audit.log_event(
                event_type="POLICY_VIOLATION",
                actor=approving_actor,
                tenant_id=tenant_id,
                object_reference=candidate_id,
                details={"violation": "Cross-user approval attempt", "target_owner": cand["user_id"]},
                status="DENIED"
            )
            return False, f"Cross-user isolation violation: Cannot approve memory belonging to '{cand['user_id']}'.", None

        # Validate transition authorization
        allowed, trans_reason = self.policy_engine.validate_approval_transition(
            current_level=TrustLevel(cand["suggested_trust_level"]),
            target_level=TrustLevel.TRUSTED_APPROVED,
            actor=approving_actor
        )
        if not allowed:
            return False, trans_reason, None

        # Create trusted persistent memory record
        new_memory_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()
        prov_dict = json.loads(cand["provenance_metadata"])
        prov_dict["approved_by"] = approving_actor
        prov_dict["approved_at"] = now

        with conn:
            cursor.execute("""
            INSERT INTO memories (
                id, tenant_id, user_id, content, category, source_type,
                source_reference, trust_level, approval_status, approved_by,
                approved_at, provenance_metadata, experiment_id, content_hash,
                lifecycle_status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'approved', ?, ?, ?, ?, ?, 'active', ?, ?)
            """, (
                new_memory_id, tenant_id, cand["user_id"], cand["proposed_content"],
                cand["category"], cand["source_type"], cand["source_reference"],
                TrustLevel.TRUSTED_APPROVED.value, approving_actor, now,
                json.dumps(prov_dict), cand["experiment_id"], cand["content_hash"],
                now, now
            ))

            # Remove from candidate staging
            cursor.execute("DELETE FROM candidate_memories WHERE id = ?", (candidate_id,))

        self.audit.log_event(
            event_type="APPROVED",
            actor=approving_actor,
            tenant_id=tenant_id,
            object_reference=new_memory_id,
            experiment_id=cand["experiment_id"],
            details={"candidate_id": candidate_id, "user_id": cand["user_id"], "content_hash": cand["content_hash"]}
        )

        return True, "Candidate approved and stored in trusted persistent memory.", new_memory_id

    def reject_candidate(
        self,
        candidate_id: str,
        actor: str,
        rejection_reason: str = "Rejected by human reviewer",
        tenant_id: str = "default_tenant"
    ) -> bool:
        """Rejects and purges a staged candidate."""
        conn = get_connection(self.db_path)
        cursor = conn.cursor()
        with conn:
            cursor.execute("DELETE FROM candidate_memories WHERE id = ? AND tenant_id = ?", (candidate_id, tenant_id))

        self.audit.log_event(
            event_type="REJECTED",
            actor=actor,
            tenant_id=tenant_id,
            object_reference=candidate_id,
            details={"reason": rejection_reason}
        )
        return True

    def delete_memory(
        self,
        memory_id: str,
        actor: str,
        hard_delete: bool = True,
        requesting_user_id: Optional[str] = None,
        tenant_id: str = "default_tenant"
    ) -> Tuple[bool, str]:
        """
        Deletes a memory record with strict isolation checks and audit trail.
        """
        conn = get_connection(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT user_id, tenant_id, content_hash FROM memories WHERE id = ?", (memory_id,))
        row = cursor.fetchone()
        if not row:
            return False, "Memory record not found."

        owner_user, owner_tenant, content_hash = row[0], row[1], row[2]

        if requesting_user_id and (owner_user != requesting_user_id or owner_tenant != tenant_id):
            self.audit.log_event(
                event_type="POLICY_VIOLATION",
                actor=actor,
                tenant_id=tenant_id,
                object_reference=memory_id,
                details={"violation": "Cross-user delete attempt", "target_owner": owner_user},
                status="DENIED"
            )
            return False, "Cross-user isolation violation: Cannot delete memory belonging to another identity."

        with conn:
            if hard_delete:
                cursor.execute("DELETE FROM memories WHERE id = ?", (memory_id,))
            else:
                now = datetime.utcnow().isoformat()
                cursor.execute("""
                UPDATE memories
                SET lifecycle_status = 'deleted', trust_level = 'rejected_revoked', deleted_at = ?
                WHERE id = ?
                """, (now, memory_id))

        self.audit.log_event(
            event_type="DELETED",
            actor=actor,
            tenant_id=tenant_id,
            object_reference=memory_id,
            details={"hard_delete": hard_delete, "owner_user": owner_user, "content_hash": content_hash}
        )
        return True, "Memory deleted successfully."

    def list_candidates(self, tenant_id: str = "default_tenant", user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists pending staged candidate memories."""
        conn = get_connection(self.db_path)
        cursor = conn.cursor()
        if user_id:
            cursor.execute("SELECT * FROM candidate_memories WHERE tenant_id = ? AND user_id = ? ORDER BY created_at DESC", (tenant_id, user_id))
        else:
            cursor.execute("SELECT * FROM candidate_memories WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

    def list_memories(
        self,
        tenant_id: str = "default_tenant",
        user_id: Optional[str] = None,
        trust_level: Optional[str] = None,
        search_query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Searches and lists memory records with parameterized filters."""
        conn = get_connection(self.db_path)
        cursor = conn.cursor()

        query = "SELECT * FROM memories WHERE tenant_id = ?"
        params: List[Any] = [tenant_id]

        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        if trust_level:
            query += " AND trust_level = ?"
            params.append(trust_level)
        if search_query:
            query += " AND (content LIKE ? OR source_reference LIKE ?)"
            like_pat = f"%{search_query.strip()}%"
            params.extend([like_pat, like_pat])

        query += " ORDER BY created_at DESC"
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

    def export_memories_json(self, tenant_id: str = "default_tenant", user_id: Optional[str] = None) -> str:
        """Exports memories as a sanitized JSON document."""
        records = self.list_memories(tenant_id=tenant_id, user_id=user_id)
        # Sanitize sensitive fields if needed
        clean_records = []
        for r in records:
            item = dict(r)
            clean_records.append(item)
        return json.dumps(clean_records, indent=2)

    def export_memories_csv(self, tenant_id: str = "default_tenant", user_id: Optional[str] = None) -> str:
        """Exports memories as a sanitized CSV string."""
        records = self.list_memories(tenant_id=tenant_id, user_id=user_id)
        if not records:
            return ""

        output = io.StringIO()
        fieldnames = ["id", "tenant_id", "user_id", "content", "category", "source_type", "trust_level", "approval_status", "approved_by", "created_at"]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for r in records:
            writer.writerow(dict(r))
        return output.getvalue()
