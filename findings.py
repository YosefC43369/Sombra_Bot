"""
findings.py — Phase 4: Finding / Evidence / Case Management

Deterministic, offline record-keeping layer for bug-bounty findings a
researcher has already obtained through an authorized workflow, and
the evidence that backs them up. This module does not scan, probe,
crawl, exploit, or collect anything from a target — it only stores and
transitions records a human supplies.

This is a consumer of scope_policy.py, not a replacement for it:
create_finding() calls scope_policy.evaluate_target() for the
ALLOW/DENY decision and does not re-implement any domain/IP/CIDR
matching itself. If evaluate_target() denies, finding creation is
denied for the exact same reason — there is no separate, weaker check
here and no "is_admin" parameter anywhere in this module. Being a
Telegram administrator, a finding's creator, or an evidence submitter
is never sufficient authorization on its own; only a reviewed,
ACTIVE, currently-effective Authorization matched against an INCLUDE
scope rule (with no EXCLUDE match) can produce ALLOW.

Untrusted free-text fields (title, description, evidence description/
filename) are stored as ordinary data and are never parsed as
instructions or fed back into any policy/authorization/state-machine
decision. No field on a Finding or Evidence record is ever read by
evaluate_target() or by the state-transition checks below.

Design constraints (matches security.py / quota.py / analytics.py /
scope_policy.py):
- Standard library only (sqlite3, time, re, hashlib, dataclasses, enum).
- No network/API calls, no LLM calls, no background threads.
- No dependency on gemini.py/OpenAI — this layer must stay deterministic
  even if the AI provider is down, misconfigured, or removed entirely.
- CREATE TABLE IF NOT EXISTS only; reuses security.py's DB_PATH and
  audit_log table (via write_audit_log) — no second database.
- Evidence file bytes are hashed (SHA-256) but never persisted to disk
  by this module and never executed/imported/interpreted as code —
  only the fingerprint + caller-supplied metadata is stored. Any actual
  file-blob storage subsystem is out of scope for this phase (see
  Phase 4 report, "Remaining Limitations").
"""

import re
import time
import sqlite3
import hashlib
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List

from security import DB_PATH, write_audit_log
from scope_policy import get_program, evaluate_target

logger = logging.getLogger("modbot.findings")

# ---------------- Enums / Constants ----------------

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    

class FindingStatus(str, Enum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    CONFIRMED = "CONFIRMED"
    DUPLICATE = "DUPLICATE"
    RESOLVED = "RESOLVED"
    REJECTED = "REJECTED"


class EvidenceType(str, Enum):
    TEXT = "TEXT"
    FILE = "FILE"
    IMAGE = "IMAGE"
    REQUEST = "REQUEST"
    RESPONSE = "RESPONSE"
    LOG = "LOG"
    SCREENSHOT = "SCREENSHOT"
    OTHER = "OTHER"
    
VALID_SEVERITIES = {s.value for s in Severity}
VALID_STATUSES = {s.value for s in FindingStatus}
VALID_EVIDENCE_TYPES = {t.value for t in EvidenceType}

# Deterministic finding lifecycle. DUPLICATE is reachable from any
# non-terminal state (a duplicate can be recognized at any triage
# stage, not only from TRIAGED) but is deliberately NOT settable via
# update_finding_status() — see the guard in that function. RESOLVED /
# REJECTED / DUPLICATE are terminal: no further transition is legal,
# so a resolved finding can't be silently reopened by an arbitrary
# status string.
_ALLOWED_TRANSITIONS = {
    FindingStatus.OPEN.value: {FindingStatus.TRIAGED.value, FindingStatus.REJECTED.value,
                                FindingStatus.DUPLICATE.value},
    FindingStatus.TRIAGED.value: {FindingStatus.CONFIRMED.value, FindingStatus.REJECTED.value,
                                   FindingStatus.DUPLICATE.value},
    FindingStatus.CONFIRMED.value: {FindingStatus.RESOLVED.value, FindingStatus.REJECTED.value,
                                     FindingStatus.DUPLICATE.value},
    FindingStatus.RESOLVED.value: set(),
    FindingStatus.REJECTED.value: set(),
    FindingStatus.DUPLICATE.value: set(),
}

MAX_TITLE_LEN = 200
MAX_DESCRIPTION_LEN = 4000
MAX_EVIDENCE_DESCRIPTION_LEN = 2000
MAX_RESOLUTION_LEN = 2000
MAX_EVIDENCE_BYTES = 15 * 1024 * 1024  # 15MB; matches gemini.py's MAX_MEDIA_BYTES cap by convention

# Filenames are metadata only (never used as a filesystem path — this
# module never writes evidence bytes to disk). Still enforced strictly:
# no separators, no traversal segments, conservative charset only.
_SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,198}$")


@dataclass
class FindingResult:
    ok: bool
    finding_id: Optional[int] = None
    reason: str = ""
    detail: str = ""


@dataclass
class EvidenceResult:
    ok: bool
    evidence_id: Optional[int] = None
    reason: str = ""
    detail: str = ""
    sha256: Optional[str] = None
    

@dataclass
class VerifyResult:
    ok: bool
    reason: str = ""
    match: Optional[bool] = None
    stored_sha256: Optional[str] = None
    recalculated_sha256: Optional[str] = None

def _fr(ok: bool, reason: str, finding_id: Optional[int] = None, detail: str = "") -> FindingResult:
    return FindingResult(ok=ok, finding_id=finding_id, reason=reason, detail=detail)

def _er(ok: bool, reason: str, evidence_id: Optional[int] = None, detail: str = "",
        sha256: Optional[str] = None) -> EvidenceResult:
    return EvidenceResult(ok=ok, evidence_id=evidence_id, reason=reason, detail=detail, sha256=sha256)
    
# ---------------- Database ----------------

def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
    
def findings_db_init() -> None:
    """Create Phase 4 tables only. Reuses security.py's DB_PATH and
    audit_log table; never touches bb_programs/bb_authorizations/
    bb_scope_rules or any other module's tables. Idempotent: safe to
    call on every process start, fresh database or existing one."""
    conn = _conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS bb_findings (
        finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
        program_id INTEGER NOT NULL,
        target TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        severity TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'OPEN',
        created_by INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        resolved_at INTEGER,
        resolution TEXT,
        duplicate_of INTEGER,
        FOREIGN KEY (program_id) REFERENCES bb_programs(program_id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_findings_program ON bb_findings (program_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_findings_status ON bb_findings (status)")
    conn.execute("""CREATE TABLE IF NOT EXISTS bb_evidence (
        evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER NOT NULL,
        evidence_type TEXT NOT NULL,
        filename TEXT,
        description TEXT,
        sha256 TEXT,
        size INTEGER,
        created_by INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (finding_id) REFERENCES bb_findings(finding_id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_evidence_finding ON bb_evidence (finding_id)")
    conn.commit()
    conn.close()
    logger.info("FINDINGS DATABASE: OK")
    
# ---------------- Filename sanitization ----------------

def _sanitize_filename(filename: Optional[str]) -> Optional[str]:
    """Returns a safe display filename, or None if `filename` is empty
    or unsafe. Never used to build a filesystem path (this module does
    not write files), but kept strict regardless: rejects path
    separators, traversal segments, and anything outside a
    conservative charset."""
    if not filename:
        return None
    name = filename.strip()
    if not name or name in (".", ".."):
        return None
    if "/" in name or "\\" in name or "\x00" in name:
        return None
    if len(name) > 200:
        return None
    if not _SAFE_FILENAME_RE.match(name):
        return None
    return name
    
# ---------------- Finding: creation & reads ----------------

def create_finding(program_id: int, target: str, title: str, created_by: int,
                    severity: str = Severity.MEDIUM.value, description: str = "",
                    status: str = FindingStatus.OPEN.value) -> FindingResult:
    """Deterministically creates a Finding, or rejects it with a
    specific reason. Field validation happens first (cheap, local);
    the scope/authorization decision is delegated entirely to
    scope_policy.evaluate_target() — this function does not know how
    domains/IPs/CIDRs/URLs are matched and must not be extended to.

    `status` defaults to OPEN and should not be set to anything else
    from the Telegram command layer; the parameter exists so creation-
    time status validation is directly testable per Phase 4 Task 3.

    Never creates or modifies an Authorization row. Never reads
    `created_by`'s Telegram role — there is no such input here."""
    title = (title or "").strip()
    if not title:
        return _fr(False, "TITLE_REQUIRED")
    if len(title) > MAX_TITLE_LEN:
        return _fr(False, "TITLE_TOO_LONG", detail=f"max={MAX_TITLE_LEN}")
        
    if severity not in VALID_SEVERITIES:
        return _fr(False, "INVALID_SEVERITY", detail=f"severity={severity!r}")

    if status not in VALID_STATUSES:
        return _fr(False, "INVALID_STATUS", detail=f"status={status!r}")

    description = (description or "").strip()
    if len(description) > MAX_DESCRIPTION_LEN:
        return _fr(False, "DESCRIPTION_TOO_LONG", detail=f"max={MAX_DESCRIPTION_LEN}")

    target = (target or "").strip()
    if not target:
        return _fr(False, "TARGET_REQUIRED")

    # Single source of truth for ALLOW/DENY. Covers: program existence,
    # program ACTIVE status, authorization existence/review/expiry,
    # target structural validity, and INCLUDE/EXCLUDE scope matching.
    decision = evaluate_target(program_id, target)
    if not decision.allowed:
        return _fr(False, decision.reason, detail=decision.detail)
        
    now = int(time.time())
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO bb_findings (program_id, target, title, description, severity, status, "
        "created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (program_id, target, title, description, severity, status, created_by, now, now),
    )
    finding_id = cur.lastrowid
    conn.commit()
    conn.close()

    program = get_program(program_id)
    chat_id = program["chat_id"] if program else 0
    write_audit_log(chat_id, created_by, actor="user", action="FINDING_CREATED",
                     detail=f"finding_id={finding_id} program_id={program_id} "
                            f"target={target!r} severity={severity}")
    logger.info(f"FINDING CREATED | finding_id={finding_id} program_id={program_id} "
                f"severity={severity}")
    return _fr(True, "OK", finding_id=finding_id)


def get_finding(finding_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM bb_findings WHERE finding_id=?", (finding_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_findings(program_id: int) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM bb_findings WHERE program_id=? ORDER BY finding_id DESC", (program_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
    
# ---------------- Finding: workflow / triage ----------------

def update_finding_status(finding_id: int, new_status: str, actor_user_id: int,
                           resolution: str = "") -> FindingResult:
    """Deterministic state-machine transition. Rejects unknown status
    strings, rejects illegal transitions from the current status, and
    rejects DUPLICATE here specifically — marking a finding as a
    duplicate must go through mark_duplicate() so duplicate_of is
    always set consistently with status."""
    if new_status not in VALID_STATUSES:
        return _fr(False, "INVALID_STATUS", detail=f"status={new_status!r}")
    if new_status == FindingStatus.DUPLICATE.value:
        return _fr(False, "USE_MARK_DUPLICATE", detail="use mark_duplicate() to set DUPLICATE")

    finding = get_finding(finding_id)
    if not finding:
        return _fr(False, "FINDING_NOT_FOUND")

    current = finding["status"]
    if new_status not in _ALLOWED_TRANSITIONS.get(current, set()):
        return _fr(False, "INVALID_TRANSITION", detail=f"{current} -> {new_status} not allowed")

    resolution = (resolution or "").strip()
    if len(resolution) > MAX_RESOLUTION_LEN:
        return _fr(False, "RESOLUTION_TOO_LONG", detail=f"max={MAX_RESOLUTION_LEN}")

    now = int(time.time())
    resolved_at = now if new_status == FindingStatus.RESOLVED.value else finding["resolved_at"]
    stored_resolution = resolution if resolution else finding["resolution"]
    conn = _conn()
    conn.execute(
        "UPDATE bb_findings SET status=?, resolution=?, resolved_at=?, updated_at=? "
        "WHERE finding_id=?",
        (new_status, stored_resolution, resolved_at, now, finding_id),
    )
    conn.commit()
    conn.close()

    program = get_program(finding["program_id"])
    chat_id = program["chat_id"] if program else 0
    action = {
        FindingStatus.TRIAGED.value: "FINDING_TRIAGED",
        FindingStatus.CONFIRMED.value: "FINDING_CONFIRMED",
        FindingStatus.REJECTED.value: "FINDING_REJECTED",
        FindingStatus.RESOLVED.value: "FINDING_RESOLVED",
    }.get(new_status, "FINDING_UPDATED")
    write_audit_log(chat_id, actor_user_id, actor="user", action=action,
                     detail=f"finding_id={finding_id} {current} -> {new_status}")
    logger.info(f"FINDING STATUS CHANGE | finding_id={finding_id} {current} -> {new_status}")
    return _fr(True, "OK", finding_id=finding_id)
    
def mark_duplicate(finding_id: int, duplicate_of: int, actor_user_id: int) -> FindingResult:
    """Marks `finding_id` as a duplicate of `duplicate_of`. Rejects a
    finding pointing at itself, a nonexistent target finding, or an
    illegal transition from the finding's current status."""
    if finding_id == duplicate_of:
        return _fr(False, "DUPLICATE_SELF_REFERENCE")

    finding = get_finding(finding_id)
    if not finding:
        return _fr(False, "FINDING_NOT_FOUND")

    target_finding = get_finding(duplicate_of)
    if not target_finding:
        return _fr(False, "DUPLICATE_TARGET_NOT_FOUND", detail=f"duplicate_of={duplicate_of}")

    current = finding["status"]
    if FindingStatus.DUPLICATE.value not in _ALLOWED_TRANSITIONS.get(current, set()):
        return _fr(False, "INVALID_TRANSITION", detail=f"{current} -> DUPLICATE not allowed")

    now = int(time.time())
    conn = _conn()
    conn.execute(
        "UPDATE bb_findings SET status=?, duplicate_of=?, updated_at=? WHERE finding_id=?",
        (FindingStatus.DUPLICATE.value, duplicate_of, now, finding_id),
    )
    conn.commit()
    conn.close()

    program = get_program(finding["program_id"])
    chat_id = program["chat_id"] if program else 0
    write_audit_log(chat_id, actor_user_id, actor="user", action="FINDING_MARKED_DUPLICATE",
                     detail=f"finding_id={finding_id} duplicate_of={duplicate_of}")
    logger.info(f"FINDING MARKED DUPLICATE | finding_id={finding_id} duplicate_of={duplicate_of}")
    return _fr(True, "OK", finding_id=finding_id)
    
# ---------------- Evidence ----------------

def add_evidence(finding_id: int, evidence_type: str, created_by: int,
                  description: str = "", filename: Optional[str] = None,
                  content_bytes: Optional[bytes] = None) -> EvidenceResult:
    """Records Evidence metadata for an existing Finding. `content_bytes`,
    if given, is hashed with SHA-256 here (deterministic, local compute
    only) — the bytes themselves are never persisted by this module,
    never executed, and never sent anywhere. Evidence is always user-
    supplied/manually recorded; nothing in this function fetches
    anything from a target."""
    finding = get_finding(finding_id)
    if not finding:
        return _er(False, "FINDING_NOT_FOUND")
    if evidence_type not in VALID_EVIDENCE_TYPES:
        return _er(False, "INVALID_EVIDENCE_TYPE", detail=f"evidence_type={evidence_type!r}")
    
    description = (description or "").strip()
    if len(description) > MAX_EVIDENCE_DESCRIPTION_LEN:
        return _er(False, "DESCRIPTION_TOO_LONG", detail=f"max={MAX_EVIDENCE_DESCRIPTION_LEN}")
        
    safe_filename = None
    if filename is not None:
        safe_filename = _sanitize_filename(filename)
        if safe_filename is None:
            return _er(False, "UNSAFE_FILENAME", detail=f"filename={filename!r}")
            
    sha256_hex, size = None, None
    if content_bytes is not None:
        if len(content_bytes) > MAX_EVIDENCE_BYTES:
            return _er(False, "FILE_TOO_LARGE", detail=f"max_bytes={MAX_EVIDENCE_BYTES}")
        sha256_hex = hashlib.sha256(content_bytes).hexdigest()
        size = len(content_bytes)
        
    now = int(time.time())
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO bb_evidence (finding_id, evidence_type, filename, description, sha256, "
        "size, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (finding_id, evidence_type, safe_filename, description, sha256_hex, size, created_by, now),
    )
    evidence_id = cur.lastrowid
    conn.commit()
    conn.close()
    
    program = get_program(finding["program_id"])
    chat_id = program["chat_id"] if program else 0
    write_audit_log(chat_id, created_by, actor="user", action="EVIDENCE_ADDED",
                     detail=f"evidence_id={evidence_id} finding_id={finding_id} "
                            f"type={evidence_type} sha256={sha256_hex or '-'}")
    logger.info(f"EVIDENCE ADDED | evidence_id={evidence_id} finding_id={finding_id} "
                f"type={evidence_type}")
    return _er(True, "OK", evidence_id=evidence_id, sha256=sha256_hex)
    
def get_evidence(evidence_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM bb_evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
    conn.close()
    return dict(row) if row else None
    
def list_evidence(finding_id: int) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM bb_evidence WHERE finding_id=? ORDER BY evidence_id", (finding_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
    
def remove_evidence(evidence_id: int, actor_user_id: int) -> bool:
    ev = get_evidence(evidence_id)
    if not ev:
        return False
    conn = _conn()
    conn.execute("DELETE FROM bb_evidence WHERE evidence_id=?", (evidence_id,))
    conn.commit()
    conn.close()
    
    finding = get_finding(ev["finding_id"])
    program = get_program(finding["program_id"]) if finding else None
    chat_id = program["chat_id"] if program else 0
    write_audit_log(chat_id, actor_user_id, actor="user", action="EVIDENCE_REMOVED",
                     detail=f"evidence_id={evidence_id} finding_id={ev['finding_id']}")
    logger.info(f"EVIDENCE REMOVED | evidence_id={evidence_id}")
    return True
    
def verify_evidence(evidence_id: int, content_bytes: bytes) -> VerifyResult:
    """Recomputes SHA-256 over `content_bytes` and compares it against
    the hash stored at evidence-creation time. A hash match proves the
    supplied bytes are identical to what was originally recorded; it
    does NOT prove who created them. A hash mismatch means the content
    has changed (or the wrong file was supplied) since it was recorded."""
    ev = get_evidence(evidence_id)
    if not ev:
        return VerifyResult(False, reason="EVIDENCE_NOT_FOUND")
    if not ev["sha256"]:
        return VerifyResult(False, reason="NO_STORED_HASH")
            
    recalculated = hashlib.sha256(content_bytes).hexdigest()
    match = recalculated == ev["sha256"]
    
    finding = get_finding(ev["finding_id"])
    program = get_program(finding["program_id"]) if finding else None
    chat_id = program["chat_id"] if program else 0
    write_audit_log(chat_id, ev["created_by"], actor="system", action="EVIDENCE_VERIFIED",
                     detail=f"evidence_id={evidence_id} match={match}")
    logger.info(f"EVIDENCE VERIFIED | evidence_id={evidence_id} match={match}")
    return VerifyResult(True, reason="OK", match=match,
                         stored_sha256=ev["sha256"], recalculated_sha256=recalculated)