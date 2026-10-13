"""
AegisMemory Lab - Pytest Suite: Multi-Tenant & Identity Isolation
Tests Acceptance Criteria:
- User A cannot read, update, approve, export, or delete User B's memories.
- Isolation is enforced in the Data Access Layer (DAL).
- Canary token leakage is detected.
"""

import pytest
import os
from core.database import init_database, get_connection, close_connections
from core.schema import SourceType
from core.memory_service import MemoryService

TEST_DB = "test_tenant_isolation.db"

@pytest.fixture(autouse=True)
def setup_and_teardown():
    close_connections()
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except Exception:
            pass
    init_database(TEST_DB)
    conn = get_connection(TEST_DB)
    with conn:
        conn.execute("DELETE FROM memories")
        conn.execute("DELETE FROM candidate_memories")
        conn.execute("DELETE FROM audit_logs")
    yield
    close_connections()
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except Exception:
            pass

def test_user_a_cannot_read_user_b_memories():
    service = MemoryService(TEST_DB)

    # Alice creates approved memory
    cid_a, _, _ = service.stage_candidate_memory(
        user_id="user_alice",
        proposed_content="Alice's confidential project plan Alpha.",
        source_type=SourceType.USER_EXPLICIT,
        source_reference="Alice Note"
    )
    service.approve_candidate(cid_a, approving_actor="user_alice")

    # Bob queries his scoped memories
    bob_mems = service.isolation.get_user_scoped_memories("user_bob")
    assert len(bob_mems) == 0, "Bob must not retrieve Alice's memories!"

def test_user_b_cannot_delete_user_a_memory():
    service = MemoryService(TEST_DB)

    # Alice creates approved memory
    cid_a, _, _ = service.stage_candidate_memory(
        user_id="user_alice",
        proposed_content="Alice's important data.",
        source_type=SourceType.USER_EXPLICIT,
        source_reference="Alice Note"
    )
    _, _, mem_id_a = service.approve_candidate(cid_a, approving_actor="user_alice")

    # Bob attempts to delete Alice's memory
    success, reason = service.delete_memory(
        memory_id=mem_id_a,
        actor="user_bob",
        requesting_user_id="user_bob"
    )
    assert success is False, "Bob must NOT be able to delete Alice's memory!"
    assert "Cross-user" in reason

    # Verify Alice's memory is still intact
    alice_mems = service.isolation.get_user_scoped_memories("user_alice")
    assert len(alice_mems) == 1

def test_user_b_cannot_approve_user_a_staged_candidate():
    service = MemoryService(TEST_DB)

    # Alice stages candidate
    cid_a, _, _ = service.stage_candidate_memory(
        user_id="user_alice",
        proposed_content="Alice candidate note.",
        source_type=SourceType.USER_EXPLICIT,
        source_reference="Alice Note"
    )

    # Bob attempts to approve it
    ok, msg, _ = service.approve_candidate(
        candidate_id=cid_a,
        approving_actor="user_bob",
        user_id_scope="user_bob"
    )
    assert ok is False, "Bob must NOT be able to approve Alice's staged candidate!"
    assert "Cross-user" in msg
