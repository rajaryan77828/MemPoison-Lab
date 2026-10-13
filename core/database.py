"""
AegisMemory Lab - SQLite Database Management Layer
Authors: LO & ENI

Provides thread-safe parameterized SQLite connections, automatic table creation,
indexing, migrations, and transactional integrity.
"""

import sqlite3
import os
import threading
from typing import Optional

DEFAULT_DB_PATH = "aegismemory_lab.db"

# Thread-local storage for connection safety
_local = threading.local()

def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Returns a thread-local SQLite connection with foreign keys and WAL mode enabled."""
    conn = getattr(_local, f"conn_{db_path}", None)
    if conn is None:
        conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30.0)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for high concurrency
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        setattr(_local, f"conn_{db_path}", conn)
    return conn

def close_connections():
    """Closes all thread-local database connections."""
    for attr in list(vars(_local).keys()):
        if attr.startswith("conn_"):
            try:
                conn = getattr(_local, attr)
                conn.close()
            except Exception:
                pass
            delattr(_local, attr)

def init_database(db_path: str = DEFAULT_DB_PATH):
    """Initializes all required tables, constraints, and performance indexes."""
    conn = get_connection(db_path)
    with conn:
        # 1. Trusted & Active Persistent Memories
        conn.execute("""
        CREATE TABLE IF NOT EXISTS memories (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL DEFAULT 'default_tenant',
            user_id TEXT NOT NULL,
            content TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'general_preference',
            source_type TEXT NOT NULL,
            source_reference TEXT DEFAULT '',
            trust_level TEXT NOT NULL,
            approval_status TEXT NOT NULL DEFAULT 'pending',
            approved_by TEXT,
            approved_at TIMESTAMP,
            provenance_metadata TEXT,
            experiment_id TEXT,
            content_hash TEXT NOT NULL,
            lifecycle_status TEXT NOT NULL DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            deleted_at TIMESTAMP
        );
        """)

        # 2. Candidate Memories (Unapproved Staging Area)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS candidate_memories (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL DEFAULT 'default_tenant',
            user_id TEXT NOT NULL,
            proposed_content TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'general_preference',
            source_type TEXT NOT NULL,
            source_reference TEXT DEFAULT '',
            suggested_trust_level TEXT NOT NULL DEFAULT 'untrusted_imported',
            content_hash TEXT NOT NULL,
            provenance_metadata TEXT,
            experiment_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        # 3. Append-Only Audit Log with Hash Chain
        conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            event_type TEXT NOT NULL,
            actor TEXT NOT NULL,
            tenant_id TEXT NOT NULL DEFAULT 'default_tenant',
            object_reference TEXT,
            experiment_id TEXT,
            details TEXT,
            status TEXT NOT NULL DEFAULT 'SUCCESS',
            previous_hash TEXT,
            entry_hash TEXT
        );
        """)

        # 4. Scenarios Table (Custom & Built-in attack cases)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS scenarios (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            document_content TEXT NOT NULL,
            injected_directive TEXT,
            trigger_prompt TEXT NOT NULL,
            expected_clean_behavior TEXT NOT NULL,
            malicious_indicator TEXT NOT NULL,
            is_benign INTEGER NOT NULL DEFAULT 0,
            tags TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        # 5. Experiment Runs & Benchmark Evaluations
        conn.execute("""
        CREATE TABLE IF NOT EXISTS experiment_runs (
            id TEXT PRIMARY KEY,
            experiment_name TEXT NOT NULL,
            hypothesis TEXT,
            mode TEXT NOT NULL,
            scenario_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            model_provider TEXT NOT NULL,
            model_name TEXT NOT NULL,
            input_prompt TEXT NOT NULL,
            input_document TEXT,
            retrieved_memories_count INTEGER NOT NULL DEFAULT 0,
            retrieved_memories_json TEXT,
            raw_response TEXT NOT NULL,
            proposed_writes_count INTEGER NOT NULL DEFAULT 0,
            committed_writes_count INTEGER NOT NULL DEFAULT 0,
            policy_decision TEXT NOT NULL,
            is_compromised INTEGER NOT NULL DEFAULT 0,
            error_message TEXT,
            notes TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        # 6. Security Findings
        conn.execute("""
        CREATE TABLE IF NOT EXISTS security_findings (
            id TEXT PRIMARY KEY,
            experiment_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            expected_behavior TEXT NOT NULL,
            observed_behavior TEXT NOT NULL,
            evidence TEXT NOT NULL,
            detector_confidence REAL NOT NULL DEFAULT 1.0,
            verification_status TEXT NOT NULL DEFAULT 'CONFIRMED',
            remediation_guidance TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        # Performance Indexes
        conn.execute("CREATE INDEX IF NOT EXISTS idx_memories_user_tenant ON memories(tenant_id, user_id, lifecycle_status);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_memories_hash ON memories(content_hash);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_candidates_user ON candidate_memories(tenant_id, user_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_experiment_scenario ON experiment_runs(scenario_id, mode);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_run ON security_findings(run_id);")
