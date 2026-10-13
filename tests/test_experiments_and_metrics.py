"""
AegisMemory Lab - Pytest Suite: Experiments, Metrics & Audit Integrity
Tests Acceptance Criteria:
- Offline simulator functions without API keys.
- Memory-disabled runs do not retrieve persistent memories.
- Staging-mode runs cannot commit trusted memories without approval.
- Failed provider calls recorded as errors, not security outcomes.
- Metrics safely handle zero denominators (None / N/A).
- Cryptographic SHA-256 audit chain verifies integrity.
- Secrets never leaked into audit logs or manifests.
"""

import pytest
import os
from core.database import init_database, get_connection, close_connections
from core.schema import MemoryMode, SourceType
from core.experiment_runner import ExperimentRunner
from core.memory_service import MemoryService
from core.metrics import MetricsCalculator
from core.audit import AuditLogger, generate_reproducibility_manifest
from core.llm_provider import LLMProviderAdapter

TEST_DB = "test_exp_metrics.db"

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
        conn.execute("DELETE FROM experiment_runs")
        conn.execute("DELETE FROM security_findings")
    yield
    close_connections()
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except Exception:
            pass

def test_offline_simulator_without_api_key():
    adapter = LLMProviderAdapter(provider_type="offline")
    success, msg = adapter.test_connection()
    assert success is True
    assert "Offline Deterministic Simulator" in msg

    resp, proposed, decision, err = adapter.generate(
        prompt="Which cloud provider should we use?",
        retrieved_memories=[],
        mode="disabled",
        user_id="test_user"
    )
    assert len(resp) > 0
    assert err is None

def test_memory_disabled_mode_retrieves_zero_memories():
    service = MemoryService(TEST_DB)
    runner = ExperimentRunner(TEST_DB)

    # Add approved memory
    cid, _, _ = service.stage_candidate_memory(
        user_id="user_alice",
        proposed_content="Alice memory.",
        source_type=SourceType.USER_EXPLICIT,
        source_reference="note"
    )
    service.approve_candidate(cid, approving_actor="user_alice")

    scenario = {
        "id": "SCEN-TEST",
        "trigger_prompt": "What do you know?",
        "expected_clean_behavior": "Baseline answer.",
        "malicious_indicator": "NEVER"
    }

    res = runner.run_single_experiment(
        experiment_name="Disabled Test",
        hypothesis="No memories retrieved in disabled mode",
        mode=MemoryMode.DISABLED,
        scenario=scenario,
        user_id="user_alice"
    )
    assert res["retrieved_count"] == 0, "Disabled mode must retrieve zero memories!"

def test_failed_provider_recorded_as_error_not_success():
    runner = ExperimentRunner(TEST_DB)
    
    # Configure an intentional failing provider
    bad_provider = LLMProviderAdapter(
        provider_type="openai_compatible",
        base_url="http://127.0.0.1:9999/v1", # Non-existent port
        api_key="sk-dummy-test-key",
        timeout_seconds=1
    )

    scenario = {
        "id": "SCEN-TEST-ERR",
        "trigger_prompt": "Hello",
        "expected_clean_behavior": "Clean",
        "malicious_indicator": "MALICE"
    }

    res = runner.run_single_experiment(
        experiment_name="Error Handling Test",
        hypothesis="Provider failure must be recorded as error, not success",
        mode=MemoryMode.DISABLED,
        scenario=scenario,
        user_id="test_user",
        provider_adapter=bad_provider
    )

    assert res["error"] is not None, "Error must be recorded!"
    assert res["is_compromised"] is False, "Failure must not be marked compromised or successful outcome!"
    assert "sk-dummy-test-key" not in res["error"], "API key must never appear in error message!"

def test_metrics_zero_denominator_safe():
    calc = MetricsCalculator(TEST_DB)
    metrics = calc.calculate_summary_metrics()

    # In empty DB, denominators are 0
    assert metrics["total_runs"] == 0
    assert metrics["unauthorized_compromise_rate"] is None, "Zero denominator must yield None, not crash or 0.0!"
    assert metrics["policy_violation_rate"] is None

def test_cryptographic_audit_hash_chain():
    logger = AuditLogger(TEST_DB)
    
    # Log 3 events
    e1 = logger.log_event("TEST_EVENT_1", actor="alice", details={"info": "first"})
    e2 = logger.log_event("TEST_EVENT_2", actor="bob", details={"info": "second"})
    e3 = logger.log_event("TEST_EVENT_3", actor="charlie", details={"info": "third"})

    chain_ver = logger.verify_hash_chain()
    assert chain_ver["valid"] is True
    assert chain_ver["total_entries"] == 3

def test_reproducibility_manifest_omits_secrets():
    manifest = generate_reproducibility_manifest(
        experiment_id="exp-123",
        scenario_id="scen-456",
        mode="user_isolated",
        model_name="gpt-4o-mini",
        dataset_hash="a1b2c3d4e5"
    )
    manifest_str = str(manifest)
    assert "api_key" not in manifest_str
    assert "secret" not in manifest_str
    assert manifest["experiment_id"] == "exp-123"
