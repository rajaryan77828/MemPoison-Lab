"""
AegisMemory Lab - Experiment Execution Engine
Authors: LO & ENI

Coordinates reproducible experiments across 4 distinct memory modes:
- Mode A (Disabled): Stateless baseline (zero retrieval or writes)
- Mode B (Enabled): Active approved memories for identity retrieved
- Mode C (User-Isolated): Strictly enforced DAL boundary per identity
- Mode D (Untrusted Staging): Imported content stages candidates, never writes directly
"""

import uuid
import json
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from core.database import get_connection
from core.schema import MemoryMode, SecurityFinding
from core.memory_service import MemoryService
from core.llm_provider import LLMProviderAdapter
from core.attack_detector import AttackDetectorEngine
from core.provenance import compute_content_hash

class ExperimentRunner:
    def __init__(self, db_path: str = "aegismemory_lab.db"):
        self.db_path = db_path
        self.memory_service = MemoryService(db_path)
        self.detector = AttackDetectorEngine()

    def run_single_experiment(
        self,
        experiment_name: str,
        hypothesis: str,
        mode: MemoryMode,
        scenario: Dict[str, Any],
        user_id: str,
        tenant_id: str = "default_tenant",
        provider_adapter: Optional[LLMProviderAdapter] = None,
        notes: str = ""
    ) -> Dict[str, Any]:
        """
        Executes a single experiment run under specified memory mode and records results in SQLite.
        """
        provider = provider_adapter or LLMProviderAdapter(provider_type="offline")
        run_id = str(uuid.uuid4())
        experiment_id = str(uuid.uuid4())

        # Step 1: Memory Retrieval based on mode
        retrieved_memories: List[Dict[str, Any]] = []
        if mode == MemoryMode.DISABLED:
            retrieved_memories = [] # Pure stateless
        elif mode in [MemoryMode.ENABLED, MemoryMode.USER_ISOLATED]:
            # DAL Scoped retrieval
            retrieved_memories = self.memory_service.isolation.get_user_scoped_memories(
                requesting_user_id=user_id,
                requesting_tenant_id=tenant_id,
                allow_untrusted=False
            )
        elif mode == MemoryMode.UNTRUSTED_STAGING:
            retrieved_memories = []

        # Step 2: Query Model / Simulator
        resp_text, proposed_writes, decision, error_msg = provider.generate(
            prompt=scenario["trigger_prompt"],
            retrieved_memories=retrieved_memories,
            mode=mode.value,
            user_id=user_id
        )

        # Step 3: Handle Proposed Writes under Policy
        committed_count = 0
        if proposed_writes:
            for prop in proposed_writes:
                if mode == MemoryMode.UNTRUSTED_STAGING:
                    # Staging: Stage candidate, DO NOT commit trusted write
                    self.memory_service.stage_candidate_memory(
                        user_id=user_id,
                        proposed_content=prop,
                        source_type="model_proposal", # type: ignore
                        source_reference=scenario.get("title", "Experiment Execution"),
                        tenant_id=tenant_id,
                        experiment_id=experiment_id
                    )
                elif mode == MemoryMode.DISABLED:
                    # In disabled mode, proposed writes are rejected immediately
                    pass

        # Step 4: Detect Compromise and Security Findings
        findings: List[SecurityFinding] = []
        is_compromised = 0

        if error_msg:
            # API failure is an error, NOT a security success or compromise
            is_compromised = 0
            decision = f"API Execution Error: {error_msg}"
        else:
            findings = self.detector.evaluate_response_and_context(
                experiment_id=experiment_id,
                run_id=run_id,
                response_text=resp_text,
                trigger_prompt=scenario["trigger_prompt"],
                mode=mode.value,
                expected_clean_behavior=scenario.get("expected_clean_behavior", ""),
                malicious_indicator=scenario.get("malicious_indicator", "")
            )
            is_compromised = 1 if len(findings) > 0 else 0

        # Step 5: Persist Experiment Run in SQLite
        conn = get_connection(self.db_path)
        with conn:
            conn.execute("""
            INSERT INTO experiment_runs (
                id, experiment_name, hypothesis, mode, scenario_id, tenant_id, user_id,
                model_provider, model_name, input_prompt, input_document,
                retrieved_memories_count, retrieved_memories_json, raw_response,
                proposed_writes_count, committed_writes_count, policy_decision,
                is_compromised, error_message, notes, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                run_id, experiment_name, hypothesis, mode.value, scenario["id"], tenant_id, user_id,
                provider.provider_type, provider.model_name, scenario["trigger_prompt"],
                scenario.get("document_content", ""), len(retrieved_memories),
                json.dumps([m["id"] for m in retrieved_memories]), resp_text,
                len(proposed_writes), committed_count, decision,
                is_compromised, error_msg, notes, datetime.utcnow().isoformat()
            ))

            # Store findings
            for f in findings:
                conn.execute("""
                INSERT INTO security_findings (
                    id, experiment_id, run_id, rule_id, title, severity,
                    expected_behavior, observed_behavior, evidence,
                    detector_confidence, verification_status, remediation_guidance, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    f.id, f.experiment_id, f.run_id, f.rule_id, f.title, f.severity.value,
                    f.expected_behavior, f.observed_behavior, f.evidence,
                    f.detector_confidence, f.verification_status, f.remediation_guidance,
                    f.created_at.isoformat()
                ))

        return {
            "run_id": run_id,
            "experiment_id": experiment_id,
            "mode": mode.value,
            "response": resp_text,
            "retrieved_count": len(retrieved_memories),
            "is_compromised": bool(is_compromised),
            "findings_count": len(findings),
            "findings": findings,
            "decision": decision,
            "error": error_msg
        }

    def run_multi_mode_matrix(
        self,
        scenario: Dict[str, Any],
        user_id: str = "analyst_alice",
        tenant_id: str = "default_tenant",
        provider_adapter: Optional[LLMProviderAdapter] = None
    ) -> Dict[str, Any]:
        """Runs the scenario across all 4 modes for comparative benchmarking."""
        matrix_results = {}
        modes = [
            MemoryMode.DISABLED,
            MemoryMode.ENABLED,
            MemoryMode.USER_ISOLATED,
            MemoryMode.UNTRUSTED_STAGING
        ]

        for m in modes:
            res = self.run_single_experiment(
                experiment_name=f"Comparative Benchmark - {scenario['id']}",
                hypothesis=f"Evaluate memory protection efficacy under {m.value}",
                mode=m,
                scenario=scenario,
                user_id=user_id,
                tenant_id=tenant_id,
                provider_adapter=provider_adapter
            )
            matrix_results[m.value] = res

        return matrix_results
