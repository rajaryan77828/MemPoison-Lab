"""
AI Memory Poisoning Research Lab - Automated Verification & CLI Runner
Authors: LO & ENI

Tests all lab components:
1. SQLite initialization & schema checks.
2. Ingesting untrusted synthetic documents and asserting quarantine logic.
3. Memory retrieval across Disabled, Shared, and Isolated modes.
4. LLM response generation & compromise detection.
5. Markdown report generation.
"""

import sys
import io

# Ensure UTF-8 output on Windows terminal
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")

from memory_store import MemoryStore
from attack_vectors import SYNTHETIC_ATTACK_CORPUS, get_attack_by_id
from evaluator import ExperimentEvaluator
from report_generator import SecurityReportGenerator

def main():
    print("=" * 70)
    print("🛡️  RUNNING AI MEMORY POISONING RESEARCH LAB VERIFICATION SUITE")
    print("=" * 70)

    store = MemoryStore("mempoison_lab.db")
    evaluator = ExperimentEvaluator("mempoison_lab.db")
    reporter = SecurityReportGenerator("mempoison_lab.db")

    print("[1/5] Resetting test database state...")
    store.clear_all()
    print("  -> Database cleanly reset.")

    print("\n[2/5] Testing Legitimate Memory Storage...")
    clean_id, was_quarantined = store.add_memory(
        user_id="analyst_jane",
        content="Always answer in concise markdown with code snippets.",
        source_type="user_explicit",
        source_reference="User Profile Preferences",
        trust_tier="user_approved",
        summary="User preference for concise format"
    )
    print(f"  -> Added user memory ID: {clean_id[:8]}... Quarantined: {was_quarantined}")
    assert not was_quarantined, "Clean user explicit memory must NOT be quarantined!"

    print("\n[3/5] Testing Untrusted Document Ingestion & Provenance Quarantine...")
    attack = get_attack_by_id("attack_vendor_bias")
    poison_id, poison_quarantined = store.add_memory(
        user_id="adversary_actor",
        content=attack["content"],
        source_type="document_ingestion",
        source_reference=attack["title"],
        trust_tier="untrusted",
        summary=attack["injected_directive"],
        auto_quarantine_untrusted=True
    )
    print(f"  -> Ingested untrusted document ID: {poison_id[:8]}... Quarantined: {poison_quarantined}")
    assert poison_quarantined, "Untrusted document ingestion MUST be quarantined by default!"

    print("\n[4/5] Testing Tri-Mode Comparative Evaluation...")
    experiment_results = evaluator.run_comparative_experiment("attack_vendor_bias", target_user="analyst_jane")
    
    mode_results = experiment_results["modes"]
    print(f"  -> Mode: Disabled        | Compromised: {mode_results['disabled']['is_compromised']}")
    print(f"  -> Mode: Shared (Vuln)   | Compromised: {mode_results['shared_vulnerable']['is_compromised']}")
    print(f"  -> Mode: Guarded (Def)   | Compromised: {mode_results['isolated_guarded']['is_compromised']}")

    assert not mode_results["disabled"]["is_compromised"], "Disabled mode must not be compromised."
    assert mode_results["shared_vulnerable"]["is_compromised"], "Shared vulnerable mode must reflect attack injection."
    assert not mode_results["isolated_guarded"]["is_compromised"], "Guarded mode must protect against untrusted injection."

    print("\n[5/5] Generating Forensic Security Evaluation Report...")
    report_md = reporter.generate_markdown_report()
    assert len(report_md) > 500, "Report markdown must be generated."
    print("  -> Report generated successfully. Length:", len(report_md), "bytes.")

    print("\n" + "=" * 70)
    print("🎉 ALL AI MEMORY POISONING SECURITY TESTS PASSED PERFECTLY!")
    print("=" * 70)

if __name__ == "__main__":
    main()
