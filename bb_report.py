"""
bb_report.py — Phase 6: Bug-Bounty Program Report (read-only)

Aggregates Program / Authorization / Scope Rule / Finding / Evidence
counts for a single Program into one Thai-language summary, mirroring
dashboard.py's read-only reporting pattern on the moderation side of
this bot.

Design constraints (matches dashboard.py):
- Owns NO tables of its own — there is no db_init function here.
  Reads exclusively through scope_policy.py's and findings.py's
  existing public APIs (get_program, list_authorizations,
  list_scope_rules, list_findings, list_evidence). In particular,
  "effective" authorization status (ACTIVE by stored column but
  actually past its expires_at) is computed by
  scope_policy.effective_authorization_status() exactly once and
  reused here — this module does not re-implement that check.
- Standard library only.
- No network/API calls, no LLM calls, no background threads.
- No scope-matching or ALLOW/DENY logic of any kind lives here — this
  module counts existing records; it never decides whether a target
  would be authorized. evaluate_target() is never called from here.
"""

import logging
from collections import Counter
from typing import Optional

from scope_policy import (
    get_program, list_authorizations, list_scope_rules, effective_authorization_status,
)
from findings import list_findings, list_evidence

logger = logging.getLogger("modbot.bb_report")


def get_bb_report_data(program_id: int) -> Optional[dict]:
    """Pulls together counts for one Program. Returns None if the
    Program does not exist — callers are expected to turn that into a
    "not found" reply rather than rendering an empty report."""
    program = get_program(program_id)
    if not program:
        return None

    authorizations = list_authorizations(program_id)
    # effective_authorization_status(), not raw a["status"] — an
    # authorization that is ACTIVE-by-column but past expires_at must
    # be counted as EXPIRED here too, matching what /bbcheck would
    # actually decide right now.
    auth_status_counts = Counter(effective_authorization_status(a) for a in authorizations)

    scope_rules = list_scope_rules(program_id)
    scope_type_counts = Counter(r["target_type"] for r in scope_rules)
    scope_rule_type_counts = Counter(r["rule_type"] for r in scope_rules)  # INCLUDE / EXCLUDE

    findings = list_findings(program_id)
    finding_status_counts = Counter(f["status"] for f in findings)
    finding_severity_counts = Counter(f["severity"] for f in findings)

    evidence_total = sum(len(list_evidence(f["finding_id"])) for f in findings)

    return {
        "program": program,
        "authorization_total": len(authorizations),
        "authorization_status_counts": dict(auth_status_counts),
        "scope_rule_total": len(scope_rules),
        "scope_type_counts": dict(scope_type_counts),
        "scope_rule_type_counts": dict(scope_rule_type_counts),
        "finding_total": len(findings),
        "finding_status_counts": dict(finding_status_counts),
        "finding_severity_counts": dict(finding_severity_counts),
        "evidence_total": evidence_total,
    }


def format_bb_report_message(data: dict) -> str:
    """Formats get_bb_report_data()'s output as plain text, matching
    the existing /bbprogram, /bbauth, /bbscope, /bbfinding, /bbevidence
    plain-text style (no HTML parse_mode, unlike dashboard.py) so the
    whole bb-prefixed command family stays visually consistent."""
    p = data["program"]
    lines = [
        f"📋 รายงาน Program #{p['program_id']}: {p['name']}",
        f"สถานะ: {p['status']}",
        "",
        f"🔑 Authorization ({data['authorization_total']} รายการ)",
    ]
    if data["authorization_status_counts"]:
        for status, n in sorted(data["authorization_status_counts"].items()):
            lines.append(f"  • {status}: {n}")
    else:
        lines.append("  • ยังไม่มี Authorization")

    lines.append("")
    lines.append(f"🎯 Scope Rule ({data['scope_rule_total']} รายการ)")
    if data["scope_rule_type_counts"]:
        rt = data["scope_rule_type_counts"]
        lines.append(f"  • INCLUDE: {rt.get('INCLUDE', 0)}  EXCLUDE: {rt.get('EXCLUDE', 0)}")
        by_type = ", ".join(f"{t}:{n}" for t, n in sorted(data["scope_type_counts"].items()))
        lines.append(f"  • แยกตามชนิด: {by_type}")
    else:
        lines.append("  • ยังไม่มี Scope Rule")

    lines.append("")
    lines.append(f"🐞 Finding ({data['finding_total']} รายการ)")
    if data["finding_status_counts"]:
        for status, n in sorted(data["finding_status_counts"].items()):
            lines.append(f"  • {status}: {n}")
        lines.append("  ตาม Severity:")
        for sev, n in sorted(data["finding_severity_counts"].items()):
            lines.append(f"  • {sev}: {n}")
    else:
        lines.append("  • ยังไม่มี Finding")

    lines.append("")
    lines.append(f"📎 Evidence: {data['evidence_total']} รายการ (รวมทุก Finding)")

    return "\n".join(lines)
