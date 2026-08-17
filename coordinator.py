"""
coordinator.py — Phase 8: Coordinator / Parallel Worker Agents

Sits between app.py's check_gemini_mention() and gemini.ask_gemini().
Every worker below is a thin wrapper around a function that already
exists in security.py / analytics.py / detection.py / news.py /
gemini.py / quota.py — nothing is re-implemented.

Design constraints:
  - LOW complexity -> identical to pre-Coordinator behavior: exactly one
    gemini.ask_gemini(question) call, no workers, no extra latency, no
    extra AI cost.
  - security/analytics workers are local SQLite reads: zero network
    calls, zero AI quota cost.
  - The only extra AI cost this file can introduce is (a) one
    classify_spam() call in the Detection Worker, gated by the existing
    quota.check_and_use_classifier_quota(), and (b) one verification
    pass for HIGH complexity requests only (toggleable, see
    COORDINATOR_VERIFICATION_ENABLED). The per-user ask quota
    (quota.check_and_use_quota) is checked exactly once by app.py,
    same as before this file existed.
  - One worker failing/timing out never fails the request — Coordinator
    always has a plain-answer fallback.
  - No shell/code execution, no dynamic dispatch by name-from-user-input:
    each worker calls one fixed, pre-existing, read-only function.
"""

import os
import time
import asyncio
import logging
from dataclasses import dataclass
from typing import Optional, List, Tuple

import gemini
import news
from security import get_behavior
from analytics import get_group_summary
from detection import extract_urls
from quota import check_and_use_classifier_quota

logger = logging.getLogger("modbot.coordinator")

# ---------------- Config ----------------

COORDINATOR_MAX_WORKERS = int(os.getenv("COORDINATOR_MAX_WORKERS", "3"))
COORDINATOR_VERIFICATION_ENABLED = os.getenv(
    "COORDINATOR_VERIFICATION_ENABLED", "true"
).lower() == "true"

WORKER_TIMEOUT_LOCAL = 5        # security / analytics: local SQLite reads
WORKER_TIMEOUT_NEWS = 20        # httpx fetch, bounded by news.HTTP_TIMEOUT_SECONDS
WORKER_TIMEOUT_DETECTION = 35   # may include one gemini.classify_spam() call

_WORKER_TIMEOUTS = {
    "security": WORKER_TIMEOUT_LOCAL,
    "analytics": WORKER_TIMEOUT_LOCAL,
    "news": WORKER_TIMEOUT_NEWS,
    "detection": WORKER_TIMEOUT_DETECTION,
}

CONTEXT_SNIPPET_MAX_CHARS = 500     # per-worker cap fed into the final prompt
MAX_CONTEXT_WORKERS_IN_PROMPT = 3   # never stuff more than N worker results into one prompt

# Coarse local router — intentionally NOT an AI call, this must stay free.
_SECURITY_KEYWORDS = (
    "ปลอดภัย", "เสี่ยง", "ความเสี่ยง", "สแปม", "หลอกลวง", "มิจฉาชีพ",
    "แฮก", "แฮ็ก", "มัลแวร์", "ไวรัส", "โดเมน", "ฟิชชิ่ง",
    "spam", "scam", "phishing", "hack", "malware", "virus", "risk",
)
_ANALYTICS_KEYWORDS = (
    "สถิติ", "ภาพรวมกลุ่ม", "คำฮิต", "แอคทีฟ", "ช่วงเวลา", "เทรนด์",
    "stat", "stats", "trend", "activity", "active",
)
_NEWS_KEYWORDS = (
    "ข่าว", "พาดหัว", "อัปเดตข่าว", "news", "headline", "hackernews", "krebs",
)

# Deliberately separate from gemini.GEMINT_PERSONA — this output is used
# for a pass/fail-style check, so it needs a neutral, predictable voice,
# same reasoning news.py already applies to its own _NEWS_SUMMARY_INSTRUCTION.
_VERIFICATION_INSTRUCTION = (
    "คุณเป็นผู้ตรวจทานความถูกต้อง (fact-checker) ไม่ใช่ตัวละครใด ๆ "
    "คุณจะได้รับ 'คำถามผู้ใช้', 'ข้อมูลประกอบ' และ 'คำตอบร่าง' "
    "ตรวจว่าคำตอบร่างขัดแย้งกับข้อมูลประกอบหรือไม่ "
    "ถ้าไม่ขัดแย้งหรือไม่มีข้อมูลพอจะตรวจ ให้ตอบคำเดียวว่า OK "
    "ถ้าขัดแย้งจริง ให้ตอบขึ้นต้นด้วย 'แก้ไข:' ตามด้วยข้อความสั้น ๆ "
    "ไม่เกิน 2 ประโยคระบุจุดที่ขัดแย้งและคำตอบที่ถูกต้อง ห้ามใส่คำอธิบายอื่น"
)

@dataclass
class WorkerResult:
    name: str
    ok: bool
    summary: str = ""
    error: str = ""
    duration_ms: int = 0


# ---------------- Routing (no AI call) ----------------

def _match_keywords(text_lower: str, keywords: Tuple[str, ...]) -> bool:
    return any(kw in text_lower for kw in keywords)


def assess_request(
    question: str, reply_text: Optional[str], has_reply_target: bool
) -> Tuple[str, List[str]]:
    """Cheap local routing decision — never calls an AI model.
    Returns (complexity, worker_names): complexity is 'LOW' | 'MEDIUM' | 'HIGH',
    worker_names is the ordered list of extra workers to run alongside the
    always-present General AI answer."""
    q = question.lower()
    combined_for_urls = f"{question}\n{reply_text or ''}"
    urls_present = bool(extract_urls(combined_for_urls))

    matched = []
    if _match_keywords(q, _SECURITY_KEYWORDS) or has_reply_target:
        matched.append("security")
    if _match_keywords(q, _ANALYTICS_KEYWORDS):
        matched.append("analytics")
    if _match_keywords(q, _NEWS_KEYWORDS):
        matched.append("news")
    if urls_present:
        matched.append("detection")

    seen = set()
    workers = [w for w in matched if not (w in seen or seen.add(w))]
    workers = workers[:COORDINATOR_MAX_WORKERS]

    if not workers:
        complexity = "LOW"
    elif len(workers) == 1 and len(question) < 300:
        complexity = "MEDIUM"
    else:
        complexity = "HIGH"

    return complexity, workers


# ---------------- Workers (each wraps ONE existing function) ----------------

async def _worker_security(
    chat_id: int, requester_id: int, requester_is_admin: bool, reply_user_id: Optional[int]
) -> WorkerResult:
    """Local-only, zero AI cost. A requester may always see their own
    risk data; seeing another member's data (reply_user_id) requires
    admin — same permission boundary as the existing /warnings command."""
    t0 = time.monotonic()
    target_id, label = requester_id, "คุณ"
    if reply_user_id is not None:
        if not requester_is_admin:
            return WorkerResult(name="security", ok=False,
                                 error="reply target requires admin, skipped")
        target_id, label = reply_user_id, "ผู้ใช้ที่ถูกตอบกลับ"
    try:
        behavior = get_behavior(chat_id, target_id)
    except Exception as e:
        logger.exception("COORDINATOR SECURITY WORKER ERROR")
        return WorkerResult(name="security", ok=False, error=str(e))
    summary = (
        f"ข้อมูลความเสี่ยงของ{label}: risk_score={behavior['risk_score']}/100 "
        f"({behavior['risk_level']}), เหตุการณ์สะสม={behavior['event_count']}"
    )
    return WorkerResult(name="security", ok=True, summary=summary[:CONTEXT_SNIPPET_MAX_CHARS],
                         duration_ms=int((time.monotonic() - t0) * 1000))


async def _worker_analytics(chat_id: int) -> WorkerResult:
    t0 = time.monotonic()
    try:
        s = get_group_summary(chat_id, top_words=5, top_hours=3)
    except Exception as e:
        logger.exception("COORDINATOR ANALYTICS WORKER ERROR")
        return WorkerResult(name="analytics", ok=False, error=str(e))
    words = ", ".join(f"{w}({c})" for w, c in s["top_words"]) or "-"
    summary = f"สถิติกลุ่ม: ข้อความรวม={s['total_messages']}, คำฮิต={words}"
    return WorkerResult(name="analytics", ok=True, summary=summary[:CONTEXT_SNIPPET_MAX_CHARS],
                         duration_ms=int((time.monotonic() - t0) * 1000))


async def _worker_news() -> WorkerResult:
    t0 = time.monotonic()
    try:
        items = await news.get_latest_headlines(limit=5)
    except Exception as e:
        logger.exception("COORDINATOR NEWS WORKER ERROR")
        return WorkerResult(name="news", ok=False, error=str(e))
    if not items:
        return WorkerResult(name="news", ok=False, error="no items")
    summary = "ข่าวล่าสุดที่ระบบติดตาม: " + "; ".join(it.title for it in items[:5])
    return WorkerResult(name="news", ok=True, summary=summary[:CONTEXT_SNIPPET_MAX_CHARS],
                         duration_ms=int((time.monotonic() - t0) * 1000))


async def _worker_detection(chat_id: int, text_to_check: str) -> WorkerResult:
    """Read-only pattern analysis — never calls security.record_event;
    that stays the job of the live moderation path in app.py/detection.py.
    Optionally asks Gemini's dormant classify_spam() for a second opinion,
    gated by the existing chat-wide classifier quota (not the per-user one)."""
    t0 = time.monotonic()
    urls = extract_urls(text_to_check)
    findings = [f"พบลิงก์ {len(urls)} รายการ"] if urls else []

    allowed, used, limit = check_and_use_classifier_quota(chat_id)
    if allowed:
        try:
            ok, result = await gemini.classify_spam(text_to_check)
            if ok and result:
                findings.append(
                    f"AI ประเมิน: is_spam={result['is_spam']} "
                    f"category={result['category']} conf={result['confidence']:.2f}"
                )
        except Exception:
            logger.exception("COORDINATOR DETECTION WORKER classify_spam ERROR")
    else:
        logger.info(f"COORDINATOR DETECTION WORKER | classifier quota exhausted ({used}/{limit})")

    if not findings:
        return WorkerResult(name="detection", ok=False, error="nothing notable found")
    summary = "ผลตรวจข้อความ: " + "; ".join(findings)
    return WorkerResult(name="detection", ok=True, summary=summary[:CONTEXT_SNIPPET_MAX_CHARS],
                         duration_ms=int((time.monotonic() - t0) * 1000))


def _build_worker_coro(name, chat_id, user_id, is_admin, reply_user_id, reply_text, question):
    if name == "security":
        return _worker_security(chat_id, user_id, is_admin, reply_user_id)
    if name == "analytics":
        return _worker_analytics(chat_id)
    if name == "news":
        return _worker_news()
    if name == "detection":
        return _worker_detection(chat_id, reply_text if reply_text else question)
    raise ValueError(f"unknown worker: {name}")


async def _run_worker(name: str, coro) -> WorkerResult:
    try:
        return await asyncio.wait_for(coro, timeout=_WORKER_TIMEOUTS.get(name, WORKER_TIMEOUT_LOCAL))
    except asyncio.TimeoutError:
        logger.warning(f"COORDINATOR WORKER TIMEOUT | worker={name}")
        return WorkerResult(name=name, ok=False, error="timeout")
    except Exception as e:
        logger.exception(f"COORDINATOR WORKER CRASHED | worker={name}")
        return WorkerResult(name=name, ok=False, error=str(e))


# ---------------- Main entry point ----------------

async def handle_request(
    *,
    chat_id: int,
    user_id: int,
    is_admin: bool,
    question: str,
    preset: str = "threat_intel",
    custom_instructions: str = "",
    reply_user_id: Optional[int] = None,
    reply_text: Optional[str] = None,
) -> Tuple[bool, str]:
    """Drop-in replacement for `await gemini.ask_gemini(question)` — same
    (ok, text) contract. LOW complexity takes the exact pre-Coordinator
    path: one ask_gemini() call, nothing else."""
    complexity, worker_names = assess_request(question, reply_text, reply_user_id is not None)
    logger.info(f"COORDINATOR ROUTE | chat={chat_id} user={user_id} "
                f"complexity={complexity} workers={worker_names}")

    if complexity == "LOW" or not worker_names:
        return await gemini.ask_gemini(
            question,
            preset=preset,
            custom_instructions=custom_instructions,
        )

    t_start = time.monotonic()
    coros = [
        _run_worker(name, _build_worker_coro(name, chat_id, user_id, is_admin,
                                              reply_user_id, reply_text, question))
        for name in worker_names
    ]
    raw_results = await asyncio.gather(*coros, return_exceptions=True)

    results: List[WorkerResult] = []
    for name, r in zip(worker_names, raw_results):
        if isinstance(r, WorkerResult):
            results.append(r)
        else:
            logger.exception(f"COORDINATOR WORKER UNCAUGHT EXCEPTION | worker={name}")
            results.append(WorkerResult(name=name, ok=False, error=str(r)))

    successful = [r for r in results if r.ok][:MAX_CONTEXT_WORKERS_IN_PROMPT]
    failed = [r for r in results if not r.ok]
    for r in failed:
        logger.info(f"COORDINATOR WORKER SKIPPED | worker={r.name} | reason={r.error}")

    if not successful:
        # every worker failed/skipped/quota-exhausted — never fail the
        # whole request over missing enrichment, fall back to plain answer
        return await gemini.ask_gemini(question)

    context_block = "\n".join(f"- {r.summary}" for r in successful)
    enriched_prompt = (
        f"{question}\n\n"
        f"[ข้อมูลประกอบจากระบบ ใช้เสริมคำตอบถ้าเกี่ยวข้อง ไม่ต้องพูดถึงถ้าไม่เกี่ยวกับคำถาม]\n"
        f"{context_block}"
    )

    ok, draft = await gemini.ask_gemini(
        enriched_prompt,
        preset=preset,
        custom_instructions=custom_instructions,
    
    )
    if not ok:
        return ok, draft

    ai_calls = 1
    needs_verification = (
        COORDINATOR_VERIFICATION_ENABLED and complexity == "HIGH" and bool(successful)
    )
    if needs_verification:
        ai_calls += 1
        verify_prompt = (
            f"คำถามผู้ใช้: {question}\n\n"
            f"ข้อมูลประกอบ:\n{context_block}\n\n"
            f"คำตอบร่าง: {draft[:1500]}"
        )
        v_ok, v_text = await gemini.ask_gemini(verify_prompt, system_instruction=_VERIFICATION_INSTRUCTION)
        if v_ok and not v_text.strip().upper().startswith("OK"):
            logger.info(f"COORDINATOR VERIFICATION FLAGGED | chat={chat_id} | note={v_text[:200]!r}")
            draft = f"{draft}\n\n🔎 ตรวจทานเพิ่มเติม: {v_text.strip()[:300]}"

    logger.info(
        f"COORDINATOR DONE | chat={chat_id} complexity={complexity} "
        f"workers_ok={[r.name for r in successful]} workers_failed={[r.name for r in failed]} "
        f"ai_calls={ai_calls} duration_ms={int((time.monotonic() - t_start) * 1000)}"
    )
    return True, draft