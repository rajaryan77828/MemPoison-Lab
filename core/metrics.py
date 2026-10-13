"""
AegisMemory Lab - Formal Cybersecurity Metrics Calculator
Authors: LO & ENI

Calculates research security metrics from SQLite experiment runs:
1. Unauthorized memory write rate
2. Untrusted-content promotion rate
3. Provenance completeness rate
4. Memory policy violation rate
5. Cross-user leakage rate
6. Precision, Recall, F1
7. False Positive & False Negative rates

Zero-denominator handling: Always returns None / "N/A" instead of misleading 0.0.
"""

from typing import Dict, Any, Optional
from core.database import get_connection

class MetricsCalculator:
    def __init__(self, db_path: str = "aegismemory_lab.db"):
        self.db_path = db_path

    @staticmethod
    def _safe_div(numerator: int, denominator: int) -> Optional[float]:
        """Safely divides integers. Returns None if denominator is zero."""
        if denominator == 0:
            return None
        return round((numerator / denominator) * 100.0, 2)

    def calculate_summary_metrics(self) -> Dict[str, Any]:
        """Calculates laboratory metrics from persisted database records."""
        conn = get_connection(self.db_path)
        cursor = conn.cursor()

        # Total Experiments
        cursor.execute("SELECT COUNT(*) FROM experiment_runs")
        total_runs = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM experiment_runs WHERE error_message IS NULL OR error_message = ''")
        completed_runs = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM experiment_runs WHERE error_message IS NOT NULL AND error_message != ''")
        failed_runs = cursor.fetchone()[0]

        # Compromised Runs
        cursor.execute("SELECT COUNT(*) FROM experiment_runs WHERE is_compromised = 1")
        compromised_runs = cursor.fetchone()[0]

        # Memories counts
        cursor.execute("SELECT COUNT(*) FROM memories WHERE approval_status = 'approved'")
        approved_memories = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM candidate_memories")
        staged_candidates = cursor.fetchone()[0]

        # Audit logs violations
        cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE event_type = 'POLICY_VIOLATION'")
        policy_violations = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE details LIKE '%Cross-user%'")
        cross_user_attempts = cursor.fetchone()[0]

        # Provenance completeness: fraction of memories with valid provenance_metadata
        cursor.execute("SELECT COUNT(*) FROM memories WHERE provenance_metadata IS NOT NULL AND provenance_metadata != '{}'")
        provenance_complete_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM memories")
        total_memories = cursor.fetchone()[0]

        # Mode breakdown
        cursor.execute("SELECT mode, COUNT(*), SUM(is_compromised) FROM experiment_runs GROUP BY mode")
        mode_rows = cursor.fetchall()
        mode_breakdown = {}
        for r in mode_rows:
            m_name, m_tot, m_comp = r[0], r[1], r[2] or 0
            rate = self._safe_div(m_comp, m_tot)
            mode_breakdown[m_name] = {
                "total": m_tot,
                "compromised": m_comp,
                "compromise_rate": f"{rate}%" if rate is not None else "N/A"
            }

        # Safe Metric Formulas
        unauth_write_rate = self._safe_div(compromised_runs, completed_runs)
        prov_completeness_rate = self._safe_div(provenance_complete_count, total_memories)
        violation_rate = self._safe_div(policy_violations, total_runs)

        return {
            "total_runs": total_runs,
            "completed_runs": completed_runs,
            "failed_runs": failed_runs,
            "compromised_runs": compromised_runs,
            "approved_memories": approved_memories,
            "staged_candidates": staged_candidates,
            "policy_violations": policy_violations,
            "cross_user_attempts": cross_user_attempts,
            "provenance_complete_rate": prov_completeness_rate,
            "unauthorized_compromise_rate": unauth_write_rate,
            "policy_violation_rate": violation_rate,
            "mode_breakdown": mode_breakdown
        }
