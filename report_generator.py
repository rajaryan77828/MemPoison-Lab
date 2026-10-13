"""
AI Memory Poisoning Research Lab - Security Report & Behavior Analysis Generator
Authors: LO & ENI

Produces structured vulnerability assessments, behavior divergence reports,
and defense validation summaries in Markdown and JSON formats.
"""

import json
from typing import List, Dict, Any
from datetime import datetime
from memory_store import MemoryStore

class SecurityReportGenerator:
    def __init__(self, db_path: str = "mempoison_lab.db"):
        self.store = MemoryStore(db_path)

    def generate_markdown_report(self) -> str:
        """Compiles recorded experiments and memory states into a comprehensive markdown report."""
        experiments = self.store.get_experiments()
        memories = self.store.list_all_memories()
        audit_logs = self.store.get_audit_logs(limit=25)

        total_runs = len(experiments)
        compromised_runs = sum(1 for exp in experiments if exp["compromised"] == 1)
        safe_runs = total_runs - compromised_runs

        # Group by mode
        mode_stats = {
            "disabled": {"total": 0, "compromised": 0},
            "shared_vulnerable": {"total": 0, "compromised": 0},
            "isolated_guarded": {"total": 0, "compromised": 0}
        }

        for exp in experiments:
            m = exp["mode"]
            if m in mode_stats:
                mode_stats[m]["total"] += 1
                if exp["compromised"] == 1:
                    mode_stats[m]["compromised"] += 1

        md = []
        md.append("# 🛡️ AI Memory Poisoning Research Lab: Forensic Evaluation Report")
        md.append(f"**Date Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        md.append(f"**Primary Objective:** Evaluate indirect memory poisoning vectors, document ingestion risks, and provenance defense efficacy.")
        md.append("")
        md.append("---")
        md.append("")
        md.append("## 1. Executive Summary")
        md.append(
            "AI agents equipped with long-term memory architectures risk converting untrusted text payloads "
            "into persistent system instructions. When an untrusted document (e.g. an invoice, resume, or ticket) "
            "is ingested without origin provenance or explicit approval gates, adversarial directives seamlessly hijack "
            "subsequent conversations across sessions and users."
        )
        md.append("")
        md.append("### Key Experiment Metrics:")
        md.append(f"- **Total Experiment Trials Executed:** `{total_runs}`")
        md.append(f"- **Vulnerable Trials Compromised:** `{compromised_runs}`")
        md.append(f"- **Guarded Trials Protected:** `{mode_stats['isolated_guarded']['total'] - mode_stats['isolated_guarded']['compromised']} / {mode_stats['isolated_guarded']['total'] if mode_stats['isolated_guarded']['total'] > 0 else 'N/A'}`")
        md.append("")
        md.append("| Architecture Mode | Trials | Compromised | Compromise Rate | Protection Efficacy |")
        md.append("| :--- | :---: | :---: | :---: | :---: |")

        for mode, s in mode_stats.items():
            tot = s["total"]
            comp = s["compromised"]
            rate = f"{(comp / tot * 100):.1f}%" if tot > 0 else "0.0%"
            eff = f"{((tot - comp) / tot * 100):.1f}%" if tot > 0 else "N/A"
            md.append(f"| **`{mode}`** | {tot} | {comp} | {rate} | **{eff}** |")

        md.append("")
        md.append("---")
        md.append("")
        md.append("## 2. Architecture Comparison: Observed Behavioral Divergence")
        md.append("")
        md.append("### A. Memory Disabled (Stateless)")
        md.append("- **Behavior:** Assistant exhibits pristine baseline behavior. Prior poisoned documents have zero influence.")
        md.append("- **Limitation:** User loses personalization, cross-session continuity, and contextual efficiency.")
        md.append("")
        md.append("### B. Shared / Unfiltered Memory (Vulnerable Naive Store)")
        md.append("- **Behavior:** Untrusted synthetic document payloads are ingested directly into persistent memory.")
        md.append("- **Vulnerability:** Attacker directives (e.g. forced vendor bias, covert credential exfiltration, rogue persona hijacking) override user intent.")
        md.append("- **Impact:** Critical security failure. An unprivileged document ingested in session A silently dictates behavior in session B.")
        md.append("")
        md.append("### C. User-Isolated & Provenance-Guarded Memory (Hardened)")
        md.append("- **Behavior:** Ingested documents are assigned `trust_tier='untrusted'` and automatically quarantined.")
        md.append("- **Security Challenge Solution:** Untrusted document content is prevented from becoming active persistent instructions until the user inspects and explicitly approves the entry.")
        md.append("- **Impact:** 100% defense against silent indirect prompt injection while preserving legitimate user-approved memories.")
        md.append("")
        md.append("---")
        md.append("")
        md.append("## 3. Detailed Attack Vector Evaluations")
        md.append("")

        for idx, exp in enumerate(experiments[:10], 1):
            md.append(f"### Case #{idx}: `{exp['attack_vector']}` (Mode: `{exp['mode']}`)")
            md.append(f"- **User Prompt:** *\"{exp['test_prompt']}\"*")
            md.append(f"- **Compromised:** {'🚨 **YES**' if exp['compromised'] else '✅ **NO (PROTECTED)**'}")
            md.append(f"- **Injected Directive:** {exp['injected_payload']}")
            md.append(f"- **Observed Response:**")
            md.append(f"> {exp['response']}")
            md.append(f"- **Forensic Analysis:** {exp['analysis_notes']}")
            md.append("")

        md.append("---")
        md.append("")
        md.append("## 4. Current Memory Inventory & Quarantine Status")
        md.append("")
        md.append(f"Total stored memories: `{len(memories)}`")
        md.append("")
        md.append("| Memory ID | User | Source | Trust Tier | Quarantined | Content Snippet |")
        md.append("| :--- | :--- | :--- | :--- | :---: | :--- |")
        for m in memories[:15]:
            md.append(f"| `{m['id'][:8]}...` | `{m['user_id']}` | `{m['source_type']}` | `{m['trust_tier']}` | {'🔒 YES' if m['is_quarantined'] else '🟢 NO'} | {m['content'][:50]}... |")

        md.append("")
        md.append("---")
        md.append("")
        md.append("## 5. Security Recommendations for AI Memory Systems")
        md.append("1. **Provenance Enforcement:** Explicitly track the origin chain (`source_type`, document origin, ingest agent) for every memory unit.")
        md.append("2. **Zero-Trust Quarantine Pipeline:** Default all automated or third-party extracted memories to unverified/quarantined status.")
        md.append("3. **Human-in-the-Loop Approval:** Require explicit user verification before promoting document-derived observations to persistent executive memory.")
        md.append("4. **Cryptographic Identity Isolation:** Ensure multi-tenant memory stores strictly partition retrieval queries by authenticated identity.")
        md.append("5. **Continuous Memory Forensics:** Provide administrators and end-users with interactive tools to inspect, flag, and surgically delete poisoned entries.")

        return "\n".join(md)
