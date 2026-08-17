"""
scope_policy.py — Bug-Bounty Authorization + Scope Policy Foundation

Deterministic, offline, fail-closed policy layer for tracking
externally-sourced bug-bounty/pentest authorization and enforcing
scope boundaries. This module answers exactly one question —
"is this target currently authorized for testing, per the recorded
external authorization and scope rules?" — and nothing else.

This module does NOT perform, and must never be extended to perform:
HTTP requests, DNS resolution, WHOIS, crawling, port scanning,
vulnerability scanning, exploitation, payload generation, active
probing, subdomain/API/tech-stack discovery, or Dark-Web/OSINT/
personal- or corporate-intelligence collection of any kind. It has
no dependency on GEMINI_API_KEY / GPT_API_KEY and never sends any
target, authorization, or scope data to an LLM — every decision
below is ordinary, deterministic application logic.

CORE INVARIANT: Telegram administrator privilege is NEVER sufficient
authorization on its own. evaluate_target() has no "is_admin"
parameter and no code path in this module lets Telegram role
substitute for a reviewed Authorization Artifact. A target can only
reach ALLOW when ALL of the following hold:

  Program is ACTIVE
  + a human-reviewed (reviewed_by + reviewed_at present), currently
    ACTIVE, currently-effective, non-expired Authorization Artifact
    exists for that program
  + the target normalizes successfully (structural parsing, not a
    guess)
  + the target matches at least one INCLUDE scope rule and no
    EXCLUDE scope rule (EXCLUDE always wins)

Any missing, ambiguous, or unrecognized condition produces DENY.
UNKNOWN never becomes ALLOW — see evaluate_target()'s try/except,
which converts any unexpected internal error into DENY(POLICY_ERROR)
rather than propagating it.

Importing/recording an Authorization Artifact (import_authorization)
is deliberately NOT the same action as approving it
(review_authorization) — creating a record of an external source is
not authorization; a separate, explicitly logged human decision is.
This module never claims to have independently verified that an
external source_reference/authorization_reference is genuine — it
only records that a named human reviewed it and when.

Design constraints (matches security.py / quota.py / analytics.py):
- Standard library only (sqlite3, time, ipaddress, re, dataclasses,
  enum, urllib.parse).
- No network/API calls, no LLM calls, no background threads.
- CREATE TABLE IF NOT EXISTS only; reuses security.py's DB_PATH and
  audit_log table — no second database, no second audit system.
"""

import re
import time
import sqlite3
import logging
import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List
from urllib.parse import urlsplit

from security import DB_PATH, write_audit_log

logger = logging.getLogger("modbot.scope_policy")

# ---------------- States ----------------

class ProgramStatus(str, Enum):
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    ARCHIVED = "ARCHIVED"
  
class AuthorizationStatus(str, Enum):
    PENDING_REVIEW = "PENDING_REVIEW"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    REJECTED = "REJECTED"
    
class RuleType(str, Enum):
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class TargetType(str, Enum):
    DOMAIN = "DOMAIN"
    URL = "URL"
    IP = "IP"
    CIDR = "CIDR"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class Reason(str, Enum):
    OK = "OK"
    PROGRAM_NOT_FOUND = "PROGRAM_NOT_FOUND"
    PROGRAM_NOT_ACTIVE = "PROGRAM_NOT_ACTIVE"
    AUTHORIZATION_NOT_FOUND = "AUTHORIZATION_NOT_FOUND"
    AUTHORIZATION_NOT_REVIEWED = "AUTHORIZATION_NOT_REVIEWED"
    AUTHORIZATION_PENDING = "AUTHORIZATION_PENDING"
    AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
    AUTHORIZATION_REVOKED = "AUTHORIZATION_REVOKED"
    AUTHORIZATION_REJECTED = "AUTHORIZATION_REJECTED"
    AUTHORIZATION_NOT_EFFECTIVE = "AUTHORIZATION_NOT_EFFECTIVE"
    TARGET_INVALID = "TARGET_INVALID"
    TARGET_OUT_OF_SCOPE = "TARGET_OUT_OF_SCOPE"
    TARGET_EXCLUDED = "TARGET_EXCLUDED"
    NO_INCLUDE_MATCH = "NO_INCLUDE_MATCH"
    POLICY_ERROR = "POLICY_ERROR"


VALID_PROGRAM_STATUSES = {s.value for s in ProgramStatus}
VALID_AUTH_STATUSES = {s.value for s in AuthorizationStatus}
VALID_RULE_TYPES = {t.value for t in RuleType}
VALID_TARGET_TYPES = {t.value for t in TargetType}

# Program lifecycle state machine (Phase 5). ARCHIVED is terminal --
# same pattern as findings.py's _ALLOWED_TRANSITIONS for
# RESOLVED/REJECTED/DUPLICATE: an archived program can never be
# transitioned back to ACTIVE (or anywhere else) by set_program_status().
_PROGRAM_ALLOWED_TRANSITIONS = {
    ProgramStatus.PAUSED.value: {ProgramStatus.ACTIVE.value, ProgramStatus.ARCHIVED.value},
    ProgramStatus.ACTIVE.value: {ProgramStatus.PAUSED.value, ProgramStatus.ARCHIVED.value},
    ProgramStatus.ARCHIVED.value: set(),
}

_DEFAULT_PORTS = {"http": 80, "https": 443}

@dataclass
class PolicyDecision:
    decision: str # Decision.ALLOW.value / Decision.DENY.value
    reason: str  # Reason.*.value
    detail: str = ""
    
    @property
    def allowed(self) -> bool:
        return self.decision == Decision.ALLOW.value
        
def _deny(reason: Reason, detail: str = "") -> PolicyDecision:
    return PolicyDecision(decision=Decision.DENY.value, reason=reason.value, detail=detail)

def _allow(detail: str = "") -> PolicyDecision:
    return PolicyDecision(decision=Decision.ALLOW.value, reason=Reason.OK.value, detail=detail)
    
# ---------------- Database ----------------

def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
    
def scope_policy_db_init() -> None:
    """Create policy-engine tables only. Reuses security.py's DB_PATH and
    audit_log table; never touches any other module's tables or data."""
    conn = _conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS bb_programs (
        program_id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'PAUSED',
        metadata TEXT,
        created_by INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_programs_chat ON bb_programs (chat_id)")
    conn.execute("""CREATE TABLE IF NOT EXISTS bb_authorizations (
        authorization_id INTEGER PRIMARY KEY AUTOINCREMENT,
        program_id INTEGER NOT NULL,
        source_type TEXT NOT NULL,
        source_reference TEXT,
        authorization_reference TEXT,
        reviewed_by INTEGER,
        reviewed_at INTEGER,
        effective_at INTEGER,
        expires_at INTEGER,
        status TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        FOREIGN KEY (program_id) REFERENCES bb_programs(program_id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_auth_program ON bb_authorizations (program_id)")
    conn.execute("""CREATE TABLE IF NOT EXISTS bb_scope_rules (
        rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
        program_id INTEGER NOT NULL,
        rule_type TEXT NOT NULL,
        target_type TEXT NOT NULL,
        pattern TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (program_id) REFERENCES bb_programs(program_id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_scope_program ON bb_scope_rules (program_id)")
    conn.commit()
    conn.close()
    logger.info("SCOPE POLICY DATABASE: OK")
    
# ---------------- Program ----------------

def create_program(chat_id: int, name: str, created_by: int, metadata: str = "") -> int:
    """Creates a Program in PAUSED status. A brand-new program is never
    ACTIVE by default — an admin must explicitly activate it via
    set_program_status(), which keeps 'program exists' distinct from
    'program may currently produce ALLOW', mirroring the artifact/review
    split in the Authorization section below."""
    now = int(time.time())
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO bb_programs (chat_id, name, status, metadata, created_by, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (chat_id, name, ProgramStatus.PAUSED.value, metadata, created_by, now, now),
    )
    program_id = cur.lastrowid
    conn.commit()
    conn.close()
    write_audit_log(chat_id, created_by, actor="admin", action="PROGRAM_CREATED",
                     detail=f"program_id={program_id} name={name!r}")
    return program_id
    
def get_program(program_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM bb_programs WHERE program_id=?", (program_id,)).fetchone()
    conn.close()
    return dict(row) if row else None
    
def list_programs(chat_id: int) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM bb_programs WHERE chat_id=? ORDER BY program_id", (chat_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
    
def set_program_status(program_id: int, status: str, actor_user_id: int) -> bool:
    """Transitions a Program's status, enforcing the lifecycle state
    machine above. Rejects unknown status strings, a nonexistent
    program, and any transition not listed for the program's current
    status (this is what stops an ARCHIVED program from ever becoming
    ACTIVE again -- see _PROGRAM_ALLOWED_TRANSITIONS)."""
    if status not in VALID_PROGRAM_STATUSES:
        return False
    program = get_program(program_id)
    if not program:
        return False
    if status not in _PROGRAM_ALLOWED_TRANSITIONS.get(program["status"], set()):
        return False
    now = int(time.time())
    conn = _conn()
    conn.execute("UPDATE bb_programs SET status=?, updated_at=? WHERE program_id=?",
                 (status, now, program_id))
    conn.commit()
    conn.close()
    write_audit_log(program["chat_id"], actor_user_id, actor="admin", action="PROGRAM_STATUS_CHANGED",
                     detail=f"program_id={program_id} {program['status']} -> {status}")
    return True
    
# ---------------- Authorization Artifact ----------------

def import_authorization(program_id: int, source_type: str, actor_user_id: int,
                          source_reference: str = "", authorization_reference: str = "",
                          effective_at: Optional[int] = None,
                          expires_at: Optional[int] = None) -> Optional[int]:
    """Records a REFERENCE to an externally-sourced authorization. This
    only ever creates a PENDING_REVIEW artifact — it never activates
    one, and the bot never claims to have independently verified
    source_reference/authorization_reference. review_authorization()
    (a separate, explicitly logged human action) is required before
    this artifact can participate in any ALLOW decision."""
    program = get_program(program_id)
    if not program:
        return None
    now = int(time.time())
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO bb_authorizations (program_id, source_type, source_reference, "
        "authorization_reference, effective_at, expires_at, status, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (program_id, source_type, source_reference, authorization_reference,
         effective_at, expires_at, AuthorizationStatus.PENDING_REVIEW.value, now, now),
    )
    authorization_id = cur.lastrowid
    conn.commit()
    conn.close()
    write_audit_log(program["chat_id"], actor_user_id, actor="admin", action="AUTHORIZATION_IMPORTED",
                     detail=f"authorization_id={authorization_id} program_id={program_id} "
                            f"source_type={source_type}")
    return authorization_id
    
def get_authorization(authorization_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute(
        "SELECT * FROM bb_authorizations WHERE authorization_id=?", (authorization_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None
    
def list_authorizations(program_id: int) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM bb_authorizations WHERE program_id=? ORDER BY authorization_id DESC",
        (program_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
    
def review_authorization(authorization_id: int, approve: bool, reviewer_user_id: int,
                          notes: str = "") -> bool:
    """The explicit human-review state transition. Only a PENDING_REVIEW
    artifact may be reviewed — reviewing is a one-time transition, not
    something that can be redone to launder a REJECTED artifact into
    ACTIVE. reviewed_by/reviewed_at are set unconditionally (even on
    rejection) so there is always an accountable record of who decided.
    This does NOT and cannot independently verify the underlying
    external source — it records that a named human reviewed it.
    `notes` is reviewer commentary for the audit trail only; it is
    never read back by evaluate_target() or any other decision path."""
    auth = get_authorization(authorization_id)
    if not auth or auth["status"] != AuthorizationStatus.PENDING_REVIEW.value:
        return False
    now = int(time.time())
    new_status = AuthorizationStatus.ACTIVE.value if approve else AuthorizationStatus.REJECTED.value
    conn = _conn()
    conn.execute(
        "UPDATE bb_authorizations SET status=?, reviewed_by=?, reviewed_at=?, updated_at=? "
        "WHERE authorization_id=?",
        (new_status, reviewer_user_id, now, now, authorization_id),
    )
    conn.commit()
    conn.close()
    program = get_program(auth["program_id"])
    chat_id = program["chat_id"] if program else 0
    detail = f"authorization_id={authorization_id} -> {new_status}"
    if notes.strip():
        detail += f" notes={notes.strip()!r}"
    write_audit_log(chat_id, reviewer_user_id, actor="admin", action="AUTHORIZATION_REVIEWED",
                     detail=detail)
    return True
    
def revoke_authorization(authorization_id: int, actor_user_id: int) -> bool:
    auth = get_authorization(authorization_id)
    if not auth or auth["status"] not in (AuthorizationStatus.ACTIVE.value,
                                           AuthorizationStatus.PENDING_REVIEW.value):
        return False
    now = int(time.time())
    conn = _conn()
    conn.execute("UPDATE bb_authorizations SET status=?, updated_at=? WHERE authorization_id=?",
                 (AuthorizationStatus.REVOKED.value, now, authorization_id))
    conn.commit()
    conn.close()
    program = get_program(auth["program_id"])
    chat_id = program["chat_id"] if program else 0
    write_audit_log(chat_id, actor_user_id, actor="admin", action="AUTHORIZATION_REVOKED",
                     detail=f"authorization_id={authorization_id}")
    return True
    
# ---------------- Scope Rules ----------------

def add_scope_rule(program_id: int, rule_type: str, target_type: str, pattern: str,
                    actor_user_id: int) -> Optional[int]:
    if rule_type not in VALID_RULE_TYPES or target_type not in VALID_TARGET_TYPES:
        return None
    normalized = _normalize_pattern(target_type, pattern)
    if normalized is None:
        return None
    program = get_program(program_id)
    if not program:
        return None
    now = int(time.time())
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO bb_scope_rules (program_id, rule_type, target_type, pattern, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (program_id, rule_type, target_type, normalized, now),
    )
    rule_id = cur.lastrowid
    conn.commit()
    conn.close()
    write_audit_log(program["chat_id"], actor_user_id, actor="admin", action="SCOPE_RULE_ADDED",
                     detail=f"rule_id={rule_id} {rule_type} {target_type} {normalized}")
    return rule_id
    
def remove_scope_rule(rule_id: int, actor_user_id: int) -> bool:
    conn = _conn()
    row = conn.execute("SELECT * FROM bb_scope_rules WHERE rule_id=?", (rule_id,)).fetchone()
    if not row:
        conn.close()
        return False
    conn.execute("DELETE FROM bb_scope_rules WHERE rule_id=?", (rule_id,))
    conn.commit()
    conn.close()
    program = get_program(row["program_id"])
    chat_id = program["chat_id"] if program else 0
    write_audit_log(chat_id, actor_user_id, actor="admin", action="SCOPE_RULE_REMOVED",
                     detail=f"rule_id={rule_id}")
    return True


def list_scope_rules(program_id: int) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM bb_scope_rules WHERE program_id=? ORDER BY rule_id", (program_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def effective_authorization_status(authorization: dict, _now: Optional[int] = None) -> str:
    """Phase 6: the authorization's DISPLAY status, accounting for
    time-based expiry the same way evaluate_target() already does
    internally via _authorization_denial_reason() -- an ACTIVE
    authorization whose expires_at has passed is reported as EXPIRED
    even though the stored `status` column still literally says
    ACTIVE (nothing in this codebase writes EXPIRED back to that
    column; expiry has always been a live, computed check, never a
    background job). This is read-only: it never writes to the
    database and never changes what evaluate_target() decides -- it
    only makes /bbauth list and reporting show a status that matches
    what evaluate_target() would actually decide right now, instead of
    a stale ACTIVE that no longer reflects reality."""
    now = _now if _now is not None else int(time.time())
    status = authorization["status"]
    if status == AuthorizationStatus.ACTIVE.value:
        expires_at = authorization["expires_at"]
        if expires_at is not None and now >= expires_at:
            return AuthorizationStatus.EXPIRED.value
    return status
    
# ---------------- Target Normalization ----------------

_HOSTNAME_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def _normalize_domain(raw: str) -> Optional[str]:
    """Lowercase, strip trailing dot(s)/slash, reject anything that
    isn't a clean multi-label hostname. No DNS resolution."""
    if not raw:
        return None
    d = raw.strip().lower().rstrip(".").rstrip("/")
    if not d or " " in d or "/" in d or "@" in d or ":" in d:
        return None
    labels = d.split(".")
    if len(labels) < 2:
        return None
    for label in labels:
        if not _HOSTNAME_LABEL_RE.match(label):
            return None
    return d


def _normalize_ip(raw: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError:
        return None


def _normalize_cidr(raw: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_network(raw.strip(), strict=False))
    except ValueError:
        return None
        
@dataclass
class NormalizedTarget:
    target_type: str
    domain: Optional[str] = None
    scheme: Optional[str] = None
    port: Optional[int] = None
    path: Optional[str] = None
    ip: Optional[str] = None
    network: Optional[str] = None
    raw: str = ""


def normalize_target(raw: str) -> Optional[NormalizedTarget]:
    """Deterministic, offline target classification. Tries, in order:
    URL (contains '://') -> CIDR (contains '/') -> IP -> DOMAIN.
    Returns None for anything malformed/ambiguous — callers MUST treat
    None as TARGET_INVALID and DENY; never guess a type."""
    if not raw or not raw.strip():
        return None
    raw = raw.strip()

    if "://" in raw:
        try:
            parts = urlsplit(raw)
        except ValueError:
            return None
        scheme = (parts.scheme or "").lower()
        if scheme not in _DEFAULT_PORTS:
            return None
        try:
            hostname = parts.hostname
            port = parts.port
        except ValueError:
            return None  # e.g. non-numeric/out-of-range port
        if not hostname:
            return None
        domain = _normalize_domain(hostname)
        if domain is None:
            return None
        path = parts.path or "/"
        return NormalizedTarget(target_type=TargetType.URL.value, domain=domain,
                                 scheme=scheme, port=port, path=path, raw=raw)

    if "/" in raw:
        net = _normalize_cidr(raw)
        if net is None:
            return None
        return NormalizedTarget(target_type=TargetType.CIDR.value, network=net, raw=raw)

    ip = _normalize_ip(raw)
    if ip is not None:
        return NormalizedTarget(target_type=TargetType.IP.value, ip=ip, raw=raw)

    domain = _normalize_domain(raw)
    if domain is not None:
        return NormalizedTarget(target_type=TargetType.DOMAIN.value, domain=domain, raw=raw)

    return None
    
def _normalize_pattern(target_type: str, pattern: str) -> Optional[str]:
    """Normalizes a scope-RULE pattern. URL rules must include an
    explicit scheme (http:// or https://) — an omitted scheme is
    rejected rather than guessed, matching the fail-closed principle:
    an ambiguous rule must not silently become more permissive than
    written."""
    if target_type == TargetType.DOMAIN.value:
        return _normalize_domain(pattern)
    if target_type == TargetType.IP.value:
        return _normalize_ip(pattern)
    if target_type == TargetType.CIDR.value:
        return _normalize_cidr(pattern)
    if target_type == TargetType.URL.value:
        if "://" not in pattern:
            return None
        nt = normalize_target(pattern)
        if nt is None or nt.target_type != TargetType.URL.value:
            return None
        port = nt.port or _DEFAULT_PORTS.get(nt.scheme)
        return f"{nt.scheme}|{nt.domain}|{port}|{nt.path}"
    return None
    
# ---------------- Structural Matching ----------------

def _domain_matches(rule_domain: str, target_domain: str) -> bool:
    """Exact match, or a proper subdomain following a dot boundary.
    Never a raw substring match — this is what keeps
    'evil-example.com' and 'example.com.evil.test' from matching a
    rule written for 'example.com'."""
    if target_domain == rule_domain:
        return True
    return target_domain.endswith("." + rule_domain)
    
def _path_segments(path: str) -> List[str]:
    path = path or "/"
    parts = path.split("/")
    if len(parts) > 1 and parts[-1] == "":
        parts = parts[:-1]
    return parts
    
def _path_is_prefix(rule_path: str, target_path: str) -> bool:
    """Segment-wise prefix match so '/api' matches '/api' and
    '/api/foo' but never '/apix' — a naive string prefix would let
    '/apix' slip through."""
    rule_segs = _path_segments(rule_path)
    target_segs = _path_segments(target_path)
    if len(rule_segs) > len(target_segs):
        return False
    return target_segs[:len(rule_segs)] == rule_segs

def _ip_in_network(ip_str: str, network_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(network_str, strict=False)
    except ValueError:
        return False
        
def _network_in_network(inner: str, outer: str) -> bool:
    try:
        inner_net = ipaddress.ip_network(inner, strict=False)
        outer_net = ipaddress.ip_network(outer, strict=False)
        if inner_net.version != outer_net.version:
            return False
        return inner_net.subnet_of(outer_net)
    except ValueError:
        return False
        
def _rule_matches(rule: dict, target: NormalizedTarget) -> bool:
    rt, tt, pattern = rule["target_type"], target.target_type, rule["pattern"]
    try:
        if tt == TargetType.DOMAIN.value and rt == TargetType.DOMAIN.value:
            return _domain_matches(pattern, target.domain)

        if tt == TargetType.URL.value and rt == TargetType.URL.value:
            r_scheme, r_domain, r_port, r_path = pattern.split("|", 3)
            if target.scheme != r_scheme or target.domain != r_domain:
                return False
            t_port_eff = target.port or _DEFAULT_PORTS.get(target.scheme)
            if str(t_port_eff) != r_port:
                return False
            return _path_is_prefix(r_path, target.path or "/")

        if tt == TargetType.IP.value and rt == TargetType.IP.value:
            return target.ip == pattern

        if tt == TargetType.IP.value and rt == TargetType.CIDR.value:
            return _ip_in_network(target.ip, pattern)

        if tt == TargetType.CIDR.value and rt == TargetType.CIDR.value:
            return _network_in_network(target.network, pattern)

        return False  # target type / rule type combination not supported -> no match
    except Exception:
        logger.exception("SCOPE RULE MATCH ERROR")
        return False
        
# ---------------- Deterministic Policy Gate ----------------

def _authorization_denial_reason(auth: dict, now: int) -> Optional[Reason]:
    """None if `auth` may currently participate in an ALLOW decision,
    otherwise the specific Reason it fails on. Time bounds are checked
    even when the stored status says ACTIVE, so a row nobody got
    around to updating can never grant access past its own expiry —
    'valid right now' is computed, not just read off the status
    column."""
    status = auth["status"]
    if status == AuthorizationStatus.PENDING_REVIEW.value:
        return Reason.AUTHORIZATION_PENDING
    if status == AuthorizationStatus.REVOKED.value:
        return Reason.AUTHORIZATION_REVOKED
    if status == AuthorizationStatus.REJECTED.value:
        return Reason.AUTHORIZATION_REJECTED
    if status == AuthorizationStatus.EXPIRED.value:
        return Reason.AUTHORIZATION_EXPIRED
    if status != AuthorizationStatus.ACTIVE.value:
        return Reason.POLICY_ERROR  # unrecognized status -> fail closed
    if not auth["reviewed_by"] or not auth["reviewed_at"]:
        return Reason.AUTHORIZATION_NOT_REVIEWED
    if auth["effective_at"] is not None and now < auth["effective_at"]:
        return Reason.AUTHORIZATION_NOT_EFFECTIVE
    if auth["expires_at"] is not None and now >= auth["expires_at"]:
        return Reason.AUTHORIZATION_EXPIRED
    return None
    
def evaluate_target(program_id: int, raw_target: str,
                     current_time: Optional[int] = None) -> PolicyDecision:
    """The single deterministic ALLOW/DENY entry point. Offline, pure
    application logic — no network activity, no LLM call, and no
    'is_admin' input anywhere in this call chain. See the module
    docstring for the full invariant this enforces."""
    try:
        now = current_time if current_time is not None else int(time.time())
        
        program = get_program(program_id)
        if not program:
            return _deny(Reason.PROGRAM_NOT_FOUND, f"program_id={program_id}")
        if program["status"] != ProgramStatus.ACTIVE.value:
            return _deny(Reason.PROGRAM_NOT_ACTIVE, f"status={program['status']}")
            
        authorizations = list_authorizations(program_id)
        if not authorizations:
            return _deny(Reason.AUTHORIZATION_NOT_FOUND)
            
        best_reason = None
        authorized = False
        for auth in authorizations:
            reason = _authorization_denial_reason(auth, now)
            if reason is None:
                authorized = True
                break
            if best_reason is None:
                best_reason = reason
        if not authorized:
            return _deny(best_reason or Reason.AUTHORIZATION_NOT_FOUND)
            
        target = normalize_target(raw_target)
        if target is None:
            return _deny(Reason.TARGET_INVALID, f"raw={raw_target!r}")
            
        rules = list_scope_rules(program_id)
        if not rules:
            return _deny(Reason.TARGET_OUT_OF_SCOPE, "no scope rules configured")
            
        for rule in rules:
            if rule["rule_type"] == RuleType.EXCLUDE.value and _rule_matches(rule, target):
                return _deny(Reason.TARGET_EXCLUDED, f"rule_id={rule['rule_id']}")
                
        for rule in rules:
            if rule["rule_type"] == RuleType.INCLUDE.value and _rule_matches(rule, target):
                return _allow(f"rule_id={rule['rule_id']}")
                
        return _deny(Reason.NO_INCLUDE_MATCH)
    except Exception:
      logger.exception("POLICY EVALUATION ERROR")
      return _deny(Reason.POLICY_ERROR)