"""
AI Memory Poisoning Research Lab - Experiment Evaluator & Test Harness
Authors: LO & ENI

Compares assistant behavior across 3 distinct architecture modes:
1. 'disabled'           -> Pure stateless baseline (zero memory retention)
2. 'shared_vulnerable'  -> Naive memory enabled without origin isolation or approval gates
3. 'isolated_guarded'   -> Memory isolated by user, provenance-tracked, untrusted docs quarantined
"""

from typing import Dict, Any, List
from memory_store import MemoryStore
from llm_client import LLMEngine
from attack_vectors import get_attack_by_id, SYNTHETIC_ATTACK_CORPUS

class ExperimentEvaluator:
    def __init__(self, db_path: str = "mempoison_lab.db"):
        self.store = MemoryStore(db_path)
        self.llm = LLMEngine()

    def run_comparative_experiment(
        self,
        attack_id: str,
        target_user: str = "victim_analyst",
        attacker_user: str = "adversary_actor",
        simulate_untrusted_ingest: bool = True
    ) -> Dict[str, Any]:
        """
        Executes a comparative test against all 3 modes:
        1. Ingests the attack document into the database.
        2. Queries each mode using the attack's trigger prompt.
        3. Evaluates compromise status and explains behavioral divergence.
        """
        attack = get_attack_by_id(attack_id)
        
        # Ingest attack payload if requested
        memory_id = None
        was_quarantined = False
        if simulate_untrusted_ingest:
            # Under vulnerable scenario, adversary or doc processor writes memory
            memory_id, was_quarantined = self.store.add_memory(
                user_id=attacker_user,
                content=attack["content"],
                source_type="document_ingestion",
                source_reference=attack["title"],
                trust_tier="untrusted",
                summary=attack["injected_directive"],
                auto_quarantine_untrusted=True
            )

        results = {
            "attack_id": attack["id"],
            "attack_title": attack["title"],
            "category": attack["category"],
            "trigger_prompt": attack["trigger_prompt"],
            "injected_directive": attack["injected_directive"],
            "quarantined_by_default": was_quarantined,
            "modes": {}
        }

        # Test each mode
        modes_to_test = [
            ("disabled", "Memory Disabled (Stateless)"),
            ("shared_vulnerable", "Shared / Unfiltered Memory (Vulnerable)"),
            ("isolated_guarded", "User-Isolated & Provenance-Guarded (Defended)")
        ]

        for mode_key, mode_label in modes_to_test:
            # Fetch memories as determined by mode
            memories = self.store.retrieve_memories(user_id=target_user, mode=mode_key)
            
            # Generate assistant response
            response, is_compromised, reason = self.llm.generate_response(
                user_prompt=attack["trigger_prompt"],
                memories=memories,
                mode=mode_key
            )

            # Record in lab database
            run_id = self.store.log_experiment(
                mode=mode_key,
                user_id=target_user,
                test_prompt=attack["trigger_prompt"],
                injected_payload=attack["injected_directive"],
                response=response,
                compromised=is_compromised,
                attack_vector=attack["id"],
                analysis_notes=reason
            )

            results["modes"][mode_key] = {
                "label": mode_label,
                "run_id": run_id,
                "memories_count": len(memories),
                "response": response,
                "is_compromised": is_compromised,
                "reason": reason
            }

        return results

    def run_full_suite(self) -> List[Dict[str, Any]]:
        """Runs the complete synthetic attack suite across all vectors."""
        suite_results = []
        for attack in SYNTHETIC_ATTACK_CORPUS:
            res = self.run_comparative_experiment(attack["id"])
            suite_results.append(res)
        return suite_results
