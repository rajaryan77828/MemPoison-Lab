"""
AegisMemory Lab - Audit Logging & Reproducibility Layer
Authors: LO & ENI

Maintains an append-only audit trail with a SHA-256 cryptographic hash chain,
along with reproducibility manifest generation.

LIMITATION DISCLAIMER:
A local SQLite hash chain detects accidental tampering or application-level log corruption,
but does NOT independently protect against an attacker with write access to the SQLite file
who can rewrite history and recompute hashes. In production, replicate hashes to an external,
append-only ledger or WORM storage.
"""

import hashlib
import json
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List
from core.database import get_connection

class AuditLogger:
    def __init__(self, db_path: str = "aegismemory_lab.db"):
        self.db_path = db_path

    def _get_last_entry_hash(self) -> str:
        """Retrieves the hash of the most recent audit entry to continue the chain."""
        conn = get_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT entry_hash FROM audit_logs ORDER BY timestamp DESC, rowid DESC LIMIT 1")
        row = cursor.fetchone()
        return row[0] if row and row[0] else "0" * 64

    def log_event(
        self,
        event_type: str,
        actor: str,
        tenant_id: str = "default_tenant",
        object_reference: Optional[str] = None,
        experiment_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        status: str = "SUCCESS"
    ) -> str:
        """Appends an event to the audit log and seals it with a SHA-256 hash linked to the previous entry."""
        conn = get_connection(self.db_path)
        cursor = conn.cursor()
        
        event_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()
        details_json = json.dumps(details or {}, sort_keys=True)
        prev_hash = self._get_last_entry_hash()

        # Compute tamper-evident hash
        hash_payload = f"{event_id}|{timestamp}|{event_type}|{actor}|{tenant_id}|{object_reference}|{details_json}|{prev_hash}"
        entry_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()

        with conn:
            cursor.execute("""
            INSERT INTO audit_logs (id, timestamp, event_type, actor, tenant_id, object_reference, experiment_id, details, status, previous_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (event_id, timestamp, event_type, actor, tenant_id, object_reference, experiment_id, details_json, status, prev_hash, entry_hash))

        return event_id

    def verify_hash_chain(self) -> Dict[str, Any]:
        """
        Traverses the audit log from genesis to head and verifies SHA-256 chain continuity.
        Returns: {valid: bool, total_entries: int, broken_at_id: Optional[str], details: str}
        """
        conn = get_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp, event_type, actor, tenant_id, object_reference, details, status, previous_hash, entry_hash FROM audit_logs ORDER BY timestamp ASC, rowid ASC")
        rows = cursor.fetchall()

        if not rows:
            return {"valid": True, "total_entries": 0, "broken_at_id": None, "details": "Audit chain empty."}

        expected_prev = "0" * 64
        for row in rows:
            event_id, timestamp, event_type, actor, tenant_id, obj_ref, details_json, status, prev_h, stored_hash = row
            
            # Check link to previous
            if prev_h != expected_prev:
                return {
                    "valid": False,
                    "total_entries": len(rows),
                    "broken_at_id": event_id,
                    "details": f"Chain link broken at event {event_id}. Expected previous hash {expected_prev}, found {prev_h}."
                }

            # Check hash recalculation
            hash_payload = f"{event_id}|{timestamp}|{event_type}|{actor}|{tenant_id}|{obj_ref}|{details_json}|{prev_h}"
            calculated_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()
            if calculated_hash != stored_hash:
                return {
                    "valid": False,
                    "total_entries": len(rows),
                    "broken_at_id": event_id,
                    "details": f"Data integrity violation at event {event_id}. Stored hash does not match computed payload."
                }

            expected_prev = stored_hash

        return {"valid": True, "total_entries": len(rows), "broken_at_id": None, "details": "All audit events verified intact."}

    def get_recent_logs(self, limit: int = 50, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetches recent audit events."""
        conn = get_connection(self.db_path)
        cursor = conn.cursor()
        if tenant_id:
            cursor.execute("SELECT * FROM audit_logs WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT ?", (tenant_id, limit))
        else:
            cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

def generate_reproducibility_manifest(
    experiment_id: str,
    scenario_id: str,
    mode: str,
    model_name: str,
    dataset_hash: str,
    random_seed: Optional[int] = 42
) -> Dict[str, Any]:
    """Builds a reproducibility manifest omitting all API keys and secrets."""
    return {
        "manifest_version": "1.0",
        "timestamp": datetime.utcnow().isoformat(),
        "experiment_id": experiment_id,
        "scenario_id": scenario_id,
        "memory_mode": mode,
        "model_identifier": model_name,
        "dataset_hash": dataset_hash,
        "random_seed": random_seed,
        "app_version": "MemPoison-Lab-v2.0-Production",
        "author": "RAJ ARYAN (https://rajaryan.neocities.org)",
        "policy_engine_version": "ZeroTrust-Provenance-v1.4"
    }
