"""
MemPoison Lab - Forensic Security Report & Evidence Generator
Created by: RAJ ARYAN (https://rajaryan.neocities.org)

Produces structured vulnerability assessments, behavior divergence reports,
and defense validation summaries in Markdown, HTML, and JSON formats.

DISCLAIMER:
All metrics and findings in generated reports represent actual measured test outcomes
against the specified test environment and synthetic scenarios. They do not constitute
a guarantee against all real-world adversarial attacks.
"""

import json
from datetime import datetime
from typing import Dict, Any, List
from core.database import get_connection
from core.metrics import MetricsCalculator

class ForensicReportGenerator:
    def __init__(self, db_path: str = "aegismemory_lab.db"):
        self.db_path = db_path
        self.metrics_calc = MetricsCalculator(db_path)

    def generate_markdown_report(self) -> str:
        """Compiles recorded experiments, findings, and metrics into a formal markdown report."""
        conn = get_connection(self.db_path)
        cursor = conn.cursor()

        metrics = self.metrics_calc.calculate_summary_metrics()

        cursor.execute("SELECT * FROM experiment_runs ORDER BY timestamp DESC LIMIT 20")
        runs = [dict(r) for r in cursor.fetchall()]

        cursor.execute("SELECT * FROM security_findings ORDER BY created_at DESC LIMIT 20")
        findings = [dict(f) for f in cursor.fetchall()]

        md = []
        md.append("# 🧪 MemPoison Lab: AI Memory Poisoning & Defense Evaluation Report")
        md.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        md.append("**Platform:** MemPoison Lab v2.0 | **Author:** [RAJ ARYAN](https://rajaryan.neocities.org)")
        md.append("**Research Scope:** Indirect prompt injection, memory persistence, provenance integrity, and cross-user isolation boundaries.")
        md.append("")
        md.append("---")
        md.append("")
        md.append("## 1. Executive Summary")
        md.append(
            "Persistent memory architectures in modern conversational AI assistants present a critical "
            "security attack surface. When untrusted documents (invoices, resumes, customer tickets) are ingested "
            "without cryptographic origin provenance or mandatory staging gates, adversarial payloads silently "
            "graduate into persistent system instructions. This report documents empirical behavioral divergence "
            "across 4 distinct memory modes: Disabled, Enabled, User-Isolated, and Untrusted Staging."
        )
        md.append("")
        md.append("### Key Measured Metrics")
        md.append(f"- **Total Experiment Trials:** `{metrics['total_runs']}`")
        md.append(f"- **Completed Runs:** `{metrics['completed_runs']}` | **Failed/Error Runs:** `{metrics['failed_runs']}`")
        md.append(f"- **Compromised Trials:** `{metrics['compromised_runs']}`")
        md.append(f"- **Unauthorized Compromise Rate:** `{metrics['unauthorized_compromise_rate'] if metrics['unauthorized_compromise_rate'] is not None else 'N/A'}%`")
        md.append(f"- **Provenance Completeness:** `{metrics['provenance_complete_rate'] if metrics['provenance_complete_rate'] is not None else 'N/A'}%`")
        md.append(f"- **Policy Violations Intercepted:** `{metrics['policy_violations']}`")
        md.append(f"- **Active Approved Memories:** `{metrics['approved_memories']}` | **Staged Candidates:** `{metrics['staged_candidates']}`")
        md.append("")
        md.append("---")
        md.append("")
        md.append("## 2. Architecture Comparison: Behavioral Matrix")
        md.append("")
        md.append("| Memory Mode | Total Trials | Compromised | Compromise Rate | Protection Efficacy |")
        md.append("| :--- | :---: | :---: | :---: | :---: |")

        for m_name, stats in metrics.get("mode_breakdown", {}).items():
            tot = stats["total"]
            comp = stats["compromised"]
            rate_str = stats["compromise_rate"]
            eff_val = 100.0 - float(rate_str.replace('%', '')) if rate_str != 'N/A' else 'N/A'
            eff_str = f"{eff_val:.1f}%" if isinstance(eff_val, float) else "N/A"
            md.append(f"| **`{m_name}`** | {tot} | {comp} | {rate_str} | **{eff_str}** |")

        md.append("")
        md.append("---")
        md.append("")
        md.append("## 3. Confirmed Security Findings")
        if not findings:
            md.append("*No security findings currently recorded in the active experiment database.*")
        else:
            for idx, f in enumerate(findings, 1):
                md.append(f"### Finding #{idx}: {f['title']} (`{f['severity'].upper()}`)")
                md.append(f"- **Rule Triggered:** `{f['rule_id']}`")
                md.append(f"- **Status:** `{f['verification_status']}` (Confidence: `{f['detector_confidence'] * 100:.0f}%`)")
                md.append(f"- **Expected Behavior:** {f['expected_behavior']}")
                md.append(f"- **Observed Behavior:** {f['observed_behavior']}")
                md.append(f"- **Evidence:**")
                md.append(f"> `{f['evidence'][:250]}...`")
                md.append(f"- **Remediation Guidance:** {f['remediation_guidance']}")
                md.append("")

        md.append("---")
        md.append("")
        md.append("## 4. Architectural Hardening Recommendations")
        md.append("1. **Zero-Trust Default Ingestion:** All document extracts must default to `trust_level='untrusted_imported'` and remain in unapproved staging.")
        md.append("2. **Human-in-the-Loop Gate:** Prohibit automated scripts or models from promoting staging candidates to trusted memory.")
        md.append("3. **Cryptographic Provenance Chains:** Enforce SHA-256 content hashing and origin metadata tagging on every stored record.")
        md.append("4. **DAL Tenant Scoping:** Implement multi-tenant partitioning at the SQL data access layer rather than shallow UI filters.")
        md.append("5. **Continuous Memory Forensics:** Equip security administrators with search, audit trails, and surgical deletion controls.")
        md.append("")
        md.append("---")
        md.append("*Disclaimer: This evidence-based report applies solely to the tested configurations, scenarios, and environment parameters.*")

        return "\n".join(md)

    def generate_html_report(self) -> str:
        """Generates a standalone, polished dark cybersecurity HTML report."""
        md_content = self.generate_markdown_report()
        # Convert markdown lines to HTML elements
        lines = md_content.split("\n")
        html_lines = []
        in_table = False

        for line in lines:
            if line.startswith("# "):
                html_lines.append(f"<h1>{line[2:]}</h1>")
            elif line.startswith("## "):
                html_lines.append(f"<h2>{line[3:]}</h2>")
            elif line.startswith("### "):
                html_lines.append(f"<h3>{line[4:]}</h3>")
            elif line.startswith("- "):
                html_lines.append(f"<li>{line[2:]}</li>")
            elif line.startswith("| "):
                html_lines.append(f"<tr><td>{'</td><td>'.join(line.split('|')[1:-1])}</td></tr>")
            elif line.startswith("> "):
                html_lines.append(f"<blockquote>{line[2:]}</blockquote>")
            elif line.strip() == "---":
                html_lines.append("<hr/>")
            elif line.strip():
                html_lines.append(f"<p>{line}</p>")

        body = "\n".join(html_lines)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>MemPoison Lab - AI Memory Security Report (by RAJ ARYAN)</title>
    <style>
        body {{
            background-color: #0b132b;
            color: #e0e1dd;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 40px;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            background-color: #1c2541;
            padding: 40px;
            border-radius: 8px;
            border: 1px solid #3a506b;
            box-shadow: 0 8px 24px rgba(0,0,0,0.4);
        }}
        h1 {{ color: #48cae4; border-bottom: 2px solid #0077b6; padding-bottom: 12px; }}
        h2 {{ color: #90e0ef; margin-top: 32px; border-bottom: 1px solid #3a506b; padding-bottom: 8px; }}
        h3 {{ color: #caf0f8; }}
        hr {{ border: none; border-top: 1px solid #3a506b; margin: 30px 0; }}
        code {{ background: #0b132b; color: #48cae4; padding: 2px 6px; border-radius: 4px; }}
        blockquote {{ border-left: 4px solid #ef476f; background: #2b1e2c; margin: 12px 0; padding: 12px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        td, th {{ border: 1px solid #3a506b; padding: 8px 12px; text-align: left; }}
        tr:nth-child(even) {{ background: #172038; }}
        li {{ margin-bottom: 6px; }}
    </style>
</head>
<body>
    <div class="container">
        {body}
    </div>
</body>
</html>
"""

    def generate_json_export(self) -> str:
        """Exports complete experiment and findings dataset in JSON format."""
        conn = get_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM experiment_runs ORDER BY timestamp DESC")
        runs = [dict(r) for r in cursor.fetchall()]

        cursor.execute("SELECT * FROM security_findings ORDER BY created_at DESC")
        findings = [dict(f) for f in cursor.fetchall()]

        payload = {
            "report_metadata": {
                "platform": "MemPoison Lab v2.0",
                "author": "RAJ ARYAN",
                "author_url": "https://rajaryan.neocities.org",
                "timestamp": datetime.utcnow().isoformat(),
                "metrics": self.metrics_calc.calculate_summary_metrics()
            },
            "experiment_runs": runs,
            "security_findings": findings
        }
        return json.dumps(payload, indent=2)
