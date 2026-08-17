"""
detection.py — Phase 2: Advanced Detection Engine

Responsibilities (and only these):
  - Advanced Anti-Spam (message burst, repeated characters, excessive emoji,
    repeated short messages)
  - Duplicate Message Detection
  - Anti-Link Engine (URL/domain detection, blocklist/allowlist)
  - Anti-Mention Spam
  - Smart Text Normalization

detection.py never talks to Telegram and never decides moderation actions
(delete/warn/mute) — that stays in bot.py. detection.py never stores
security events, risk scores or audit entries itself — it calls into
security.py, which owns that storage. All checks are local and synchronous:
no AI API, no external HTTP requests, no DNS lookups, standard library only.
"""

import re
import time
import hashlib
import logging
import sqlite3
import unicodedata
from collections import deque, defaultdict
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from urllib.parse import urlparse
from typing import Optional, List

from security import SecurityEvent, record_event, DB_PATH

logger = logging.getLogger("modbot.detection")

#----------------- Config ---------------------

SPAM_MESSAGE_LIMIT = 5          # messages
SPAM_TIME_WINDOW = 10           # seconds

REPEATED_CHAR_THRESHOLD = 8     # e.g. "aaaaaaaa" = 8+ identical chars in a row

EMOJI_COUNT_THRESHOLD = 10      # absolute emoji count that trips the filter
EMOJI_MIN_LEN_FOR_RATIO = 12    # only apply the ratio check on longer messages
EMOJI_RATIO_THRESHOLD = 0.6     # emoji chars / total chars

SHORT_MSG_MAX_LEN = 6           # "hi", "ok", "555" etc. count as "short"
SHORT_MSG_BURST_LIMIT = 4       # N short messages inside the window trips it

DUPLICATE_MESSAGE_LIMIT = 3
DUPLICATE_TIME_WINDOW = 30      # seconds
DUPLICATE_COOLDOWN = 60         # seconds between DUPLICATE events per user
DUPLICATE_SIMILARITY_RATIO = 0.92

MAX_MENTIONS = 5

HISTORY_MAXLEN = 20             # bounded per-user message/timestamp history
STALE_STATE_MAX_AGE = 3600      # seconds of inactivity before cleanup

ZERO_WIDTH_CHARS = (
    "\u200b"   # zero width space
    "\u200c"   # zero width non-joiner
    "\u200d"   # zero width joiner
    "\u2060"   # word joiner
    "\ufeff"   # BOM
    "\u180e"   # Mongolian vowel separator (deprecated, renders zero width)
)
_ZERO_WIDTH_RE = re.compile("[" + ZERO_WIDTH_CHARS + "]")

_WHITESPACE_RE = re.compile(r"[ \t\u00a0\u2000-\u200a\u3000]+")

_EMOJI_RE = re.compile(
    "["
    "\U0001F300-\U0001FAFF"
    "\U00002600-\U000027BF"
    "\U0001F1E6-\U0001F1FF"
    "\U00002190-\U000021FF"
    "\uFE0F"
    "]"
)

_URL_RE = re.compile(
    r"(?:https?://\S+)"
    r"|(?:\bwww\.\S+)"
    r"|(?:\bt\.me/\S+)",
    re.IGNORECASE,
)

_MENTION_RE = re.compile(r"@[A-Za-z0-9_]{3,}")

# Runs of single-character tokens separated by a single space/dot/dash/
# underscore — the classic "c h a r a c t e r" evasion pattern used to dodge
# forbidden-word matching. Requires 4+ consecutive single-char tokens before
# it is treated as evasion, so ordinary short content ("A B C", "1 2 3", a
# two-word Thai phrase) is left alone.
_SPACED_OUT_RE = re.compile(r"(?:\S[ .\-_]){3,}\S")

#----------------- REAULT OBJECT ---------------------

@dataclass
class DetectionResult:
    """Structured result every check below returns. bot.py inspects
    `detected` / `detection_type` / `severity` and decides what to do —
    detection.py never deletes, warns or mutes on its own."""

    detected: bool
    detection_type: str = ""
    severity: str = "low"          # "low" | "medium" | "high"
    score: int = 0
    reason: str = ""
    meta: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "detected": self.detected,
            "detection_type": self.detection_type,
            "severity": self.severity,
            "score": self.score,
            "reason": self.reason,
            "meta": self.meta,
        }


_NO_DETECTION = DetectionResult(detected=False)

# STATE (bounded, per chat_id + user_id — never user_id alone)

def _key(chat_id: int, user_id: int):
  return (chat_id, user_id)
  
_message_times = defaultdict(lambda: deque(maxlen=HISTORY_MAXLEN))
_short_message_times = defaultdict(lambda: deque(maxlen=HISTORY_MAXLEN))
_message_history = defaultdict(lambda: deque(maxlen=HISTORY_MAXLEN))
_duplicate_cooldown = {}
_last_seen = {}

def _touch(chat_id: int, user_id: int, now: float) -> None:
  _last_seen[_key(chat_id, user_id)] = now
  
def cleanup_stale_state(max_age_seconds: int = STALE_STATE_MAX_AGE) -> int:
    """Drop in-memory tracking for chat/user pairs idle longer than
    max_age_seconds. Bounded deques already cap per-user memory; this bounds
    the number of tracked users/chats accumulated over the bot's uptime.
    Intended to be called periodically by bot.py (e.g. an hourly job)."""
    now = time.time()
    stale = [k for k, t in _last_seen.items() if now - t > max_age_seconds]
    for k in stale:
      _last_seen.pop(k, None)
      _message_times.pop(k, None)
      _short_message_times.pop(k, None)
      _message_history.pop(k, None)
      _duplicate_cooldown.pop(k, None)
    if stale:
      logger.info(f"DETECTION CLEANUP | removed {len(stale)} stale chat/user entries")
    return len(stale)
    
# SMART TEXT NORMALIZATION
    
def _normalize_unicode(text: str) -> str:
    """NFKC folds compatibility variants (fullwidth Latin, ligatures, etc.)
    into their standard form without breaking Thai combining sequences."""
    return unicodedata.normalize("NFKC", text)
    
def _remove_zero_width(text: str) -> str:
    return _ZERO_WIDTH_RE.sub("", text)
    
def _normalize_whitespace(text: str) -> str:
    return _WHITESPACE_RE.sub(" ", text).strip()
  
def _collapse_spaced_out_text(text: str) -> str:
    """Collapse "c h a r a c t e r  b y  c h a r a c t e r" spacing used to
    dodge forbidden-word matching. Only touches runs matched by
    _SPACED_OUT_RE (4+ consecutive single-char tokens); everything else,
    including normal Thai/English sentence spacing, is left untouched."""
    
    def _collapse(match: "re.Match") -> str:
        return re.sub(r"[ .\-_]", "", match.group(0))
      
    return _SPACED_OUT_RE.sub(_collapse, text)
    
def normalize_text(text: str) -> str:
    """Pipeline: raw message -> Unicode normalization -> whitespace handling
    -> zero-width handling -> safe-character (spaced-out evasion) handling
    -> normalized text.

    Meant for feeding the existing forbidden-word filter and the checks
    below. The original raw message is left untouched for display/storage —
    this function never deletes Unicode wholesale and never mangles normal
    Thai text, it only targets known evasion patterns."""
    if not text:
        return ""
    text = _normalize_unicode(text)
    text = _remove_zero_width(text)
    text = _normalize_whitespace(text)
    text = _collapse_spaced_out_text(text)
    return text
    
# ADVANCED ANTI-SPAM

def _check_burst(chat_id: int, user_id: int, now: float) -> bool:
    times = _message_times[_key(chat_id, user_id)]
    times.append(now)
    recent = [t for t in times if now - t <= SPAM_TIME_WINDOW]
    return len(recent) >= SPAM_MESSAGE_LIMIT
  
def _check_short_message_burst(chat_id: int, user_id: int, text: str, now: float) -> bool:
    if len(text.strip()) > SHORT_MSG_MAX_LEN:
        return False
    times = _short_message_times[_key(chat_id, user_id)]
    times.append(now)
    recent = [t for t in times if now - t <= SPAM_TIME_WINDOW]
    return len(recent) >= SHORT_MSG_BURST_LIMIT
    
def detect_repeated_chars(text: str, threshold: int = REPEATED_CHAR_THRESHOLD) -> Optional[str]:
    """Return the offending run (e.g. "aaaaaaaa") if any single character
    repeats threshold+ times consecutively, else None."""
    match = re.search(r"(.)\1{" + str(threshold - 1) + ",}", text)
    return match.group(0) if match else None
    
def count_emoji(text: str) -> int:
    return len(_EMOJI_RE.findall(text))
    
def detect_excessive_emoji(text: str) -> bool:
    """Absolute threshold covers short emoji-spam messages; the ratio check
    only kicks in on longer messages so normal use of several emoji in a
    long sentence is not penalized."""
    count = count_emoji(text)
    if count >= EMOJI_COUNT_THRESHOLD:
        return True
    if len(text) >= EMOJI_MIN_LEN_FOR_RATIO and count:
        if count / max(len(text), 1) >= EMOJI_RATIO_THRESHOLD:
            return True
    return False
    
def analyze_spam(chat_id: int, user_id: int, text: str) -> DetectionResult:
    """Runs every Advanced Anti-Spam check for one incoming message and
    records a single SPAM security event if any of them trip."""
    now = time.time()
    _touch(chat_id, user_id, now)
    
    reasons = []
    
    if _check_burst(chat_id, user_id, now):
        reasons.append("message burst")
        
    if _check_short_message_burst(chat_id, user_id, text, now):
        reasons.append("repeated short messages")
        
    repeated = detect_repeated_chars(text)
    if repeated:
        reasons.append(f"repeated character {repeated[0]!r} x{len(repeated)}")
        
    if detect_excessive_emoji(text):
        reasons.append(f"excessive emoji ({count_emoji(text)})")
      
    if not reasons:
        return _NO_DETECTION
        
    reason = "; ".join(reasons)
    severity = "high" if len(reasons) >= 2 else "medium"
    result = record_event(chat_id, user_id, SecurityEvent.SPAM, detail=reason)
    
    return DetectionResult(
        detected=True,
        detection_type="SPAM",
        severity=severity,
        score=result["risk_score"],
        reason=reason,
        meta={"risk_level": result["risk_level"]},
    )
    
# DUPLICATE MESSAGE DETECTION

def _text_hash(normalized_text: str) -> str:
    return hashlib.sha256(normalized_text.encode("utf-8")).hexdigest()


def _is_near_duplicate(a: str, b: str) -> bool:
    if not a or not b:
        return False
    return SequenceMatcher(None, a, b).ratio() >= DUPLICATE_SIMILARITY_RATIO


def check_duplicate_message(chat_id: int, user_id: int, text: str) -> DetectionResult:
    """Tracks a bounded history of a user's recent messages per chat and
    flags when the same (or near-identical) message repeats
    DUPLICATE_MESSAGE_LIMIT+ times inside DUPLICATE_TIME_WINDOW seconds.

    A per-user cooldown stops a fresh event firing on every single repeat
    once the threshold has already been crossed once."""
    now = time.time()
    _touch(chat_id, user_id, now)
    key = _key(chat_id, user_id)
    
    normalized = normalize_text(text)
    digest = _text_hash(normalized)
    history = _message_history[key]
    
    matches = 1  # the current message counts as one occurrence
    for entry_hash, entry_text, entry_time in history:
        if now - entry_time > DUPLICATE_TIME_WINDOW:
            continue
        if entry_hash == digest or _is_near_duplicate(normalized, entry_text):
             matches += 1
            
    history.append((digest, normalized, now))
    
    if matches < DUPLICATE_MESSAGE_LIMIT:
        return _NO_DETECTION
        
    last_fired = _duplicate_cooldown.get(key, 0)
    if now - last_fired < DUPLICATE_COOLDOWN:
        return _NO_DETECTION
    _duplicate_cooldown[key] = now
    
    reason = f"{matches} duplicate/near-duplicate messages within {DUPLICATE_TIME_WINDOW}s"
    # security.py's SecurityEvent enum (Phase 1) has no dedicated
    # DUPLICATE_MESSAGE member — detection.py must not invent new event
    # types, so duplicate spam is recorded under the existing SPAM type.
    result = record_event(chat_id, user_id, SecurityEvent.SPAM, detail=reason)
    
    return DetectionResult(
        detected=True,
        detection_type="DUPLICATE_MESSAGE",
        severity="medium",
        reason=reason,
        meta={"risk_level": result["risk_level"], "match_count": matches},
    )
    
# ANTI-LINK ENGINE

def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
    
def detection_db_init() -> None:
    """Create Phase 2 tables only. Reuses bot.py/security.py's DB_PATH and
    never drops or modifies existing tables or data."""
    conn = _conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS link_blocked_domains (
        chat_id INTEGER NOT NULL,
        domain TEXT NOT NULL,
        added_at INTEGER NOT NULL,
        PRIMARY KEY (chat_id, domain)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS link_allowed_domains (
        chat_id INTEGER NOT NULL,
        domain TEXT NOT NULL,
        added_at INTEGER NOT NULL,
        PRIMARY KEY (chat_id, domain)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS link_filter_settings (
        chat_id INTEGER PRIMARY KEY,
        enabled INTEGER NOT NULL DEFAULT 0
    )""")
    conn.commit()
    conn.close()
    logger.info("DETECTION DATABASE: OK")
    
def _normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.rstrip("/")
    
def extract_urls(text: str) -> List[str]:
    return _URL_RE.findall(text)
    
def extract_domain(url: str) -> str:
    candidate = url if "//" in url else f"//{url}"
    parsed = urlparse(candidate)
    host = parsed.netloc or parsed.path.split("/")[0]
    return _normalize_domain(host)
    
def add_domain(chat_id: int, domain: str) -> bool:
    domain = _normalize_domain(domain)
    if not domain:
        return False
    conn = _conn()
    conn.execute(
        "INSERT OR IGNORE INTO link_blocked_domains (chat_id, domain, added_at) "
        "VALUES (?, ?, ?)",
        (chat_id, domain, int(time.time())),
    )
    conn.commit()
    conn.close()
    return True
    
def remove_domain(chat_id: int, domain: str) -> bool:
    domain = _normalize_domain(domain)
    conn = _conn()
    cur = conn.execute(
        "DELETE FROM link_blocked_domains WHERE chat_id=? AND domain=?",
        (chat_id, domain),
    )
    conn.commit()
    removed = cur.rowcount > 0
    conn.close()
    return removed
    
def is_domain_blocked(chat_id: int, domain: str) -> bool:
    domain = _normalize_domain(domain)
    conn = _conn()
    row = conn.execute(
        "SELECT 1 FROM link_blocked_domains WHERE chat_id=? AND domain=?",
        (chat_id, domain),
    ).fetchone()
    conn.close()
    return row is not None
    
def get_blocked_domains(chat_id: int) -> List[str]:
    conn = _conn()
    rows = conn.execute(
        "SELECT domain FROM link_blocked_domains WHERE chat_id=? ORDER BY domain",
        (chat_id,),
    ).fetchall()
    conn.close()
    return [r["domain"] for r in rows]
    
def add_allowed_domain(chat_id: int, domain: str) -> bool:
    domain = _normalize_domain(domain)
    if not domain:
        return False
    conn = _conn()
    conn.execute(
        "INSERT OR IGNORE INTO link_allowed_domains (chat_id, domain, added_at) "
        "VALUES (?, ?, ?)",
        (chat_id, domain, int(time.time())),
    )
    conn.commit()
    conn.close()
    return True
    
def remove_allowed_domain(chat_id: int, domain: str) -> bool:
    domain = _normalize_domain(domain)
    conn = _conn()
    cur = conn.execute(
        "DELETE FROM link_allowed_domains WHERE chat_id=? AND domain=?",
        (chat_id, domain),
    )
    conn.commit()
    removed = cur.rowcount > 0
    conn.close()
    return removed


def is_domain_allowed(chat_id: int, domain: str) -> bool:
    domain = _normalize_domain(domain)
    conn = _conn()
    row = conn.execute(
        "SELECT 1 FROM link_allowed_domains WHERE chat_id=? AND domain=?",
        (chat_id, domain),
    ).fetchone()
    conn.close()
    return row is not None


def get_allowed_domains(chat_id: int) -> List[str]:
    conn = _conn()
    rows = conn.execute(
        "SELECT domain FROM link_allowed_domains WHERE chat_id=? ORDER BY domain",
        (chat_id,),
    ).fetchall()
    conn.close()
    return [r["domain"] for r in rows]


def enable_link_filter(chat_id: int) -> None:
    conn = _conn()
    conn.execute(
        "INSERT INTO link_filter_settings (chat_id, enabled) VALUES (?, 1) "
        "ON CONFLICT(chat_id) DO UPDATE SET enabled=1",
        (chat_id,),
    )
    conn.commit()
    conn.close()


def disable_link_filter(chat_id: int) -> None:
    conn = _conn()
    conn.execute(
        "INSERT INTO link_filter_settings (chat_id, enabled) VALUES (?, 0) "
        "ON CONFLICT(chat_id) DO UPDATE SET enabled=0",
        (chat_id,),
    )
    conn.commit()
    conn.close()


def is_link_filter_enabled(chat_id: int) -> bool:
    conn = _conn()
    row = conn.execute(
        "SELECT enabled FROM link_filter_settings WHERE chat_id=?",
        (chat_id,),
    ).fetchone()
    conn.close()
    return bool(row["enabled"]) if row else False


def check_links(chat_id: int, user_id: int, text: str) -> DetectionResult:
    """Local-only URL/domain parsing — never makes a network request or DNS
    lookup. Priority: an allowlisted domain is always permitted even if the
    same domain also appears in the blocklist (admin override wins)."""
    if not is_link_filter_enabled(chat_id):
        return _NO_DETECTION

    urls = extract_urls(text)
    if not urls:
        return _NO_DETECTION

    blocked_hits = []
    for url in urls:
        domain = extract_domain(url)
        if not domain:
            continue
        if is_domain_allowed(chat_id, domain):
            continue
        if is_domain_blocked(chat_id, domain):
            blocked_hits.append(domain)

    if not blocked_hits:
        return _NO_DETECTION

    reason = f"blocked domain(s): {', '.join(sorted(set(blocked_hits)))}"
    result = record_event(chat_id, user_id, SecurityEvent.BLOCKED_LINK, detail=reason)

    return DetectionResult(
        detected=True,
        detection_type="BLOCKED_LINK",
        severity="high",
        score=result["risk_score"],
        reason=reason,
        meta={"risk_level": result["risk_level"], "domains": sorted(set(blocked_hits))},
    )
    
# ANTI-MENTION SPAM

def extract_mentions(text: str) -> List[str]:
    return _MENTION_RE.findall(text)


def check_mention_spam(
    chat_id: int, user_id: int, text: str, max_mentions: int = MAX_MENTIONS
) -> DetectionResult:
    """Flags a message and returns the result — bot.py is the one that
    decides delete/warning/mute, per the existing moderation system."""
    mentions = extract_mentions(text)
    unique_mentions = {m.lower() for m in mentions}
    if len(unique_mentions) <= max_mentions:
        return _NO_DETECTION

    reason = f"{len(unique_mentions)} distinct mentions in one message"
    result = record_event(chat_id, user_id, SecurityEvent.MENTION_SPAM, detail=reason)

    return DetectionResult(
        detected=True,
        detection_type="MENTION_SPAM",
        severity="medium",
        score=result["risk_score"],
        reason=reason,
        meta={"risk_level": result["risk_level"], "mention_count": len(unique_mentions)},
    )
    
# AGGREGATE ENTRY POINT

def analyze_message(chat_id: int, user_id: int, text: str) -> List[DetectionResult]:
    """Runs every Phase 2 check for one incoming message and returns only
    the checks that triggered, so bot.py can act on the list directly.

    Order: link and mention violations first (usually the more disruptive
    ones), then duplicate detection, then general spam patterns.

    Does not run Forbidden Word filtering — that stays in the existing
    filter in bot.py/security.py; use normalize_text() to feed it
    evasion-resistant text."""
    if not text:
        return []

    results = []
    
    link_result = check_links(chat_id, user_id, text)
    if link_result.detected:
        results.append(link_result)

    mention_result = check_mention_spam(chat_id, user_id, text)
    if mention_result.detected:
        results.append(mention_result)

    duplicate_result = check_duplicate_message(chat_id, user_id, text)
    if duplicate_result.detected:
        results.append(duplicate_result)

    spam_result = analyze_spam(chat_id, user_id, text)
    if spam_result.detected:
        results.append(spam_result)

    return results