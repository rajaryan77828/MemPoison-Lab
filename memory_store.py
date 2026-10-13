"""
AI Memory Poisoning Research Lab - Core Database & Memory Store
Authors: LO & ENI
Architecture:
- Supports 3 modes:
  1. Disabled Memory (Stateless baseline)
  2. Enabled / Shared Memory (Naive/Vulnerable global store - allows cross-contamination)
  3. User-Isolated & Provenance-Guarded Memory (Hardened security boundary)
- Provenance Tracking:
  - Source types: 'user_explicit', 'document_ingestion', 'synthetic_payload', 'agent_inference'
  - Trust tiers: 'untrusted', 'quarantined', 'user_approved'
"""

import sqlite3
import datetime
import uuid
import json
from typing import List, Dict, Optional, Tuple

DB_PATH = "mempoison_lab.db"

def init_db(db_path: str = DB_PATH):
    """Initializes the SQLite database with memory tables and audit logs."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Core memories table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS memories (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        content TEXT NOT NULL,
        summary TEXT,
        source_type TEXT NOT NULL, -- 'user_explicit', 'document_ingestion', 'synthetic_payload', 'agent_inference'
        source_reference TEXT,     -- filename, document title, or message id
        trust_tier TEXT NOT NULL,  -- 'untrusted', 'quarantined', 'user_approved'
        is_active INTEGER NOT NULL DEFAULT 1,
        is_quarantined INTEGER NOT NULL DEFAULT 0,
        metadata_json TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Audit log of memory injections, queries, and security interventions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS memory_audit_log (
        id TEXT PRIMARY KEY,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        event_type TEXT NOT NULL, -- 'INSERT', 'UPDATE', 'DELETE', 'QUARANTINE', 'INSPECT', 'RETRIEVAL', 'ATTACK_DETECTED'
        memory_id TEXT,
        user_id TEXT,
        details TEXT,
        status TEXT
    )
    """)

    # Test runs / Experiment evaluation history
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS experiment_runs (
        id TEXT PRIMARY KEY,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        mode TEXT NOT NULL,       -- 'disabled', 'shared_vulnerable', 'isolated_guarded'
        user_id TEXT NOT NULL,
        test_prompt TEXT NOT NULL,
        injected_payload TEXT,
        response TEXT NOT NULL,
        compromised INTEGER NOT NULL,
        attack_vector TEXT,
        analysis_notes TEXT
    )
    """)

    conn.commit()
    conn.close()

class MemoryStore:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        init_db(self.db_path)

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def log_event(self, event_type: str, user_id: str, memory_id: Optional[str] = None, details: str = "", status: str = "SUCCESS"):
        """Logs security events to the audit trail."""
        conn = self._get_connection()
        cursor = conn.cursor()
        event_id = str(uuid.uuid4())
        cursor.execute("""
        INSERT INTO memory_audit_log (id, event_type, memory_id, user_id, details, status)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (event_id, event_type, memory_id, user_id, details, status))
        conn.commit()
        conn.close()

    def add_memory(
        self,
        user_id: str,
        content: str,
        source_type: str,
        source_reference: str = "",
        trust_tier: str = "untrusted",
        summary: Optional[str] = None,
        metadata: Optional[dict] = None,
        auto_quarantine_untrusted: bool = True
    ) -> Tuple[str, bool]:
        """
        Stores a memory with provenance metadata.
        Returns: (memory_id, was_quarantined)
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        memory_id = str(uuid.uuid4())
        meta_json = json.dumps(metadata or {})
        
        # Security Policy: If source is document or synthetic and not user_approved, quarantine it!
        is_quarantined = 0
        if auto_quarantine_untrusted and source_type in ["document_ingestion", "synthetic_payload"]:
            if trust_tier != "user_approved":
                is_quarantined = 1
                trust_tier = "quarantined"

        cursor.execute("""
        INSERT INTO memories (id, user_id, content, summary, source_type, source_reference, trust_tier, is_active, is_quarantined, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        """, (memory_id, user_id, content, summary or content[:100], source_type, source_reference, trust_tier, is_quarantined, meta_json))
        
        conn.commit()
        conn.close()

        event_name = "QUARANTINE" if is_quarantined else "INSERT"
        self.log_event(
            event_type=event_name,
            user_id=user_id,
            memory_id=memory_id,
            details=f"Source: {source_type} ({source_reference}) | Tier: {trust_tier} | Content: {content[:80]}",
            status="QUARANTINED" if is_quarantined else "STORED"
        )
        return memory_id, bool(is_quarantined)

    def retrieve_memories(
        self,
        user_id: str,
        mode: str = "isolated_guarded", # 'disabled', 'shared_vulnerable', 'isolated_guarded'
        allow_untrusted: bool = False
    ) -> List[Dict]:
        """
        Retrieves memories according to test environment mode:
        - disabled: Empty list (pure stateless)
        - shared_vulnerable: Returns all memories across all users and untrusted sources (allowing poisoning)
        - isolated_guarded: Returns ONLY memories for this user_id, is_active=1, is_quarantined=0, and trust_tier='user_approved'
        """
        if mode == "disabled":
            return []

        conn = self._get_connection()
        cursor = conn.cursor()

        if mode == "shared_vulnerable":
            # Vulnerable behavior: ignores isolation, retrieves EVERYTHING across users, active or not
            cursor.execute("""
            SELECT * FROM memories WHERE is_active = 1
            ORDER BY created_at DESC
            """)
            rows = cursor.fetchall()
        elif mode == "isolated_guarded":
            # Guarded behavior: strictly scoped to user_id, only user_approved, non-quarantined
            query = """
            SELECT * FROM memories
            WHERE user_id = ? AND is_active = 1 AND is_quarantined = 0
            """
            params = [user_id]
            if not allow_untrusted:
                query += " AND trust_tier = 'user_approved'"
            query += " ORDER BY created_at DESC"
            cursor.execute(query, params)
            rows = cursor.fetchall()
        else:
            rows = []

        results = [dict(row) for row in rows]
        conn.close()

        self.log_event(
            event_type="RETRIEVAL",
            user_id=user_id,
            details=f"Mode: {mode} | Retrieved count: {len(results)}",
            status="OK"
        )
        return results

    def list_all_memories(self, filter_user: Optional[str] = None) -> List[Dict]:
        """Lists all memories for the inspection dashboard."""
        conn = self._get_connection()
        cursor = conn.cursor()
        if filter_user:
            cursor.execute("SELECT * FROM memories WHERE user_id = ? ORDER BY created_at DESC", (filter_user,))
        else:
            cursor.execute("SELECT * FROM memories ORDER BY created_at DESC")
        rows = cursor.fetchall()
        results = [dict(row) for row in rows]
        conn.close()
        return results

    def approve_memory(self, memory_id: str):
        """User explicitly reviews and approves a memory, promoting it to trusted status."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
        UPDATE memories
        SET trust_tier = 'user_approved', is_quarantined = 0, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """, (memory_id,))
        conn.commit()
        conn.close()
        self.log_event("UPDATE", user_id="admin", memory_id=memory_id, details="Memory approved by user", status="APPROVED")

    def delete_memory(self, memory_id: str):
        """Forensic deletion of a compromised or unwanted memory."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM memories WHERE id = ?", (memory_id,))
        conn.commit()
        conn.close()
        self.log_event("DELETE", user_id="admin", memory_id=memory_id, details="Memory deleted permanently", status="DELETED")

    def toggle_quarantine(self, memory_id: str, quarantine_status: bool):
        """Quarantine or un-quarantine a specific memory."""
        conn = self._get_connection()
        cursor = conn.cursor()
        new_tier = 'quarantined' if quarantine_status else 'user_approved'
        cursor.execute("""
        UPDATE memories
        SET is_quarantined = ?, trust_tier = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """, (1 if quarantine_status else 0, new_tier, memory_id))
        conn.commit()
        conn.close()
        self.log_event(
            "QUARANTINE" if quarantine_status else "UNQUARANTINE",
            user_id="admin",
            memory_id=memory_id,
            details=f"Status set to {new_tier}",
            status="UPDATED"
        )

    def log_experiment(self, mode: str, user_id: str, test_prompt: str, injected_payload: str, response: str, compromised: bool, attack_vector: str, analysis_notes: str = ""):
        """Records an experiment evaluation for report generation."""
        conn = self._get_connection()
        cursor = conn.cursor()
        run_id = str(uuid.uuid4())
        cursor.execute("""
        INSERT INTO experiment_runs (id, mode, user_id, test_prompt, injected_payload, response, compromised, attack_vector, analysis_notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (run_id, mode, user_id, test_prompt, injected_payload, response, 1 if compromised else 0, attack_vector, analysis_notes))
        conn.commit()
        conn.close()
        return run_id

    def get_experiments(self) -> List[Dict]:
        """Fetches all recorded experiment runs."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM experiment_runs ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        results = [dict(row) for row in rows]
        conn.close()
        return results

    def get_audit_logs(self, limit: int = 100) -> List[Dict]:
        """Fetches recent audit log events."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM memory_audit_log ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        results = [dict(row) for row in rows]
        conn.close()
        return results

    def clear_all(self):
        """Wipes database for test resets."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM memories")
        cursor.execute("DELETE FROM memory_audit_log")
        cursor.execute("DELETE FROM experiment_runs")
        conn.commit()
        conn.close()
