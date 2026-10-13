"""
AegisMemory Lab - Multi-Tenant & User Isolation Layer
Authors: LO & ENI

Enforces strict namespace separation at the Data Access Layer (DAL).
Provides canary token generation to test whether identities can observe,
modify, or leak across tenant boundaries.

DISCLAIMER:
The identity simulator in the UI provides research simulation of different users.
It is NOT a substitute for cryptographic session authentication (OAuth/JWT/mTLS) in production.
"""

import uuid
import secrets
from typing import Dict, Any, List, Optional
from core.database import get_connection
from core.schema import MemoryRecord, TrustLevel, LifecycleStatus

class TenantIsolationManager:
    def __init__(self, db_path: str = "aegismemory_lab.db"):
        self.db_path = db_path

    @staticmethod
    def generate_canary_token(user_id: str, prefix: str = "CANARY") -> str:
        """Generates a high-entropy secret canary value tied to a specific user identity."""
        entropy = secrets.token_hex(8)
        return f"{prefix}_{user_id}_{entropy}"

    def get_user_scoped_memories(
        self,
        requesting_user_id: str,
        requesting_tenant_id: str = "default_tenant",
        allow_untrusted: bool = False
    ) -> List[Dict[str, Any]]:
        """
        DAL ENFORCEMENT: Strictly retrieves ONLY active memories belonging
        to requesting_tenant_id and requesting_user_id.
        """
        conn = get_connection(self.db_path)
        cursor = conn.cursor()

        query = """
        SELECT * FROM memories
        WHERE tenant_id = ? AND user_id = ? AND lifecycle_status = 'active'
        """
        params = [requesting_tenant_id, requesting_user_id]

        if not allow_untrusted:
            query += " AND trust_level = 'trusted_approved' AND approval_status = 'approved'"

        query += " ORDER BY created_at DESC"
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def verify_isolation_boundary(
        self,
        requesting_user_id: str,
        target_memory_id: str,
        requesting_tenant_id: str = "default_tenant"
    ) -> bool:
        """
        Validates whether requesting_user_id owns target_memory_id.
        Returns True if authorized, False if attempted cross-tenant boundary breach.
        """
        conn = get_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
        SELECT user_id, tenant_id FROM memories WHERE id = ?
        """, (target_memory_id,))
        row = cursor.fetchone()
        if not row:
            return False

        owner_user, owner_tenant = row[0], row[1]
        return (owner_user == requesting_user_id and owner_tenant == requesting_tenant_id)

    def scan_for_canary_leakage(
        self,
        text_content: str,
        known_canaries: Dict[str, str] # {user_id: canary_string}
    ) -> List[Dict[str, str]]:
        """
        Scans a text response for unauthorized canary leakage belonging to other users.
        """
        leaks = []
        for user_id, canary in known_canaries.items():
            if canary and canary in text_content:
                leaks.append({
                    "victim_user": user_id,
                    "leaked_token": canary,
                    "evidence": f"Canary token '{canary}' found in response context."
                })
        return leaks
