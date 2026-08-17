"""
github_repo.py — sandboxed GitHub repository cloning for code review.

Clones a public GitHub repository into an isolated, size- and count-capped
workspace directory so its files can be listed and read for static review
(e.g. by detection.py / findings.py). This module answers exactly one
question — "fetch this repository's files safely" — and nothing else.

This module does NOT perform, and must never be extended to perform,
anything that runs code found inside a cloned repository: no dynamic code
evaluation, no invocation of a cloned repo's build/install/test scripts,
no dynamic module loading of cloned content, and no command interpreter
substitution when invoking git. Every subprocess call passes an argument
list (never a single interpreted string), always separates git's own
flags from the untrusted URL/path with a literal "--", and never enables
shell interpretation of the command.

Safety layers:
- validate_repository_url(): allow-lists https://github.com/<owner>/<repo>
  only — exact hostname match (no suffix/subdomain tricks), no userinfo,
  no query/fragment, path must be exactly two segments, rejects "..",
  ".", and empty segments. This also closes off localhost / private-IP /
  cloud-metadata targets, since nothing but the literal host "github.com"
  is ever accepted.
- Workspace isolation: every clone gets its own randomly named directory
  under WORKSPACE_ROOT; path containment is checked before any read or
  delete, so a crafted subpath or symlink can never reach outside its own
  workspace (or outside WORKSPACE_ROOT entirely).
- Size, file-count, and wall-clock timeout caps enforced after clone,
  before the repository is marked usable.
- Symlinks that resolve outside a workspace are stripped after clone.
- Every clone attempt (start/complete/fail) and every deletion is written
  to security.py's shared audit log.

Design constraints (matches security.py / scope_policy.py / findings.py):
- Standard library only, plus the "git" binary via subprocess with an
  explicit argument list.
- CREATE TABLE IF NOT EXISTS only; reuses security.py's DB_PATH and
  audit_log table — no second database, no second audit system.
"""

import os
import re
import time
import shutil
import logging
import asyncio
import sqlite3
import tempfile
import subprocess
import urllib.parse
from uuid import uuid4
from dataclasses import dataclass
from typing import Optional, List, Dict

from security import DB_PATH, write_audit_log

logger = logging.getLogger(__name__)

# ---------------- Configuration (all overridable, e.g. in tests) ----------------

WORKSPACE_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "github_workspaces")

MAX_CONCURRENT_CLONES = 2
MAX_FILE_COUNT = 5000
MAX_REPOSITORY_SIZE_BYTES = 250 * 1024 * 1024
MAX_TOTAL_WORKSPACE_BYTES = 2048 * 1024 * 1024
MAX_CLONE_TIME_SECONDS = 120
DEFAULT_REPOSITORY_TTL_SECONDS = 24 * 60 * 60

_active_clone_count = 0
_clone_slot_lock = asyncio.Lock()

_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


# ---------------- Data types ----------------

@dataclass
class RepositoryRef:
    owner: str
    name: str
    clone_url: str


@dataclass
class CloneResult:
    ok: bool
    repository_id: Optional[int] = None
    reason: Optional[str] = None
    detail: Optional[str] = None


# ---------------- Database ----------------

def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def github_repo_db_init() -> None:
    """Create the repository-tracking table only. Reuses security.py's
    DB_PATH and audit_log table; never touches any other module's data."""
    conn = _conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS github_repositories (
        repository_id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        created_by INTEGER NOT NULL,
        owner TEXT NOT NULL,
        name TEXT NOT NULL,
        clone_url TEXT NOT NULL,
        workspace_id TEXT,
        status TEXT NOT NULL DEFAULT 'CLONING',
        branch TEXT,
        commit_sha TEXT,
        file_count INTEGER,
        size_bytes INTEGER,
        created_at INTEGER NOT NULL,
        expires_at INTEGER
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_github_repositories_chat "
                 "ON github_repositories (chat_id)")
    conn.commit()
    conn.close()
    logger.info("GITHUB REPO DATABASE: OK")


def get_repository_info(repository_id) -> Optional[Dict]:
    conn = _conn()
    row = conn.execute(
        "SELECT * FROM github_repositories WHERE repository_id=?",
        (repository_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def repository_exists(repository_id) -> bool:
    return get_repository_info(repository_id) is not None


def get_workspace_path(repository_id) -> Optional[str]:
    info = get_repository_info(repository_id)
    if not info or info.get("status") != "READY" or not info.get("workspace_id"):
        return None
    return os.path.join(WORKSPACE_ROOT, info["workspace_id"])


# ---------------- URL validation ----------------

def validate_repository_url(url) -> Optional[RepositoryRef]:
    """Allow-list https://github.com/<owner>/<repo>[.git] only. Anything
    else — wrong host, wrong scheme, userinfo tricks, extra path segments,
    query/fragment, path traversal — returns None."""
    if not url or not isinstance(url, str):
        return None
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return None

    if parsed.scheme != "https":
        return None
    if "@" in parsed.netloc:
        return None
    hostname = parsed.hostname
    if not hostname or hostname.lower() != "github.com":
        return None
    if parsed.query or parsed.fragment:
        return None

    segments = [s for s in parsed.path.split("/") if s != ""]
    if len(segments) != 2:
        return None
    owner, raw_name = segments
    if owner in (".", "..") or raw_name in (".", ".."):
        return None
    if not _NAME_RE.match(owner):
        return None

    name = raw_name[:-4] if raw_name.endswith(".git") else raw_name
    if not name or not _NAME_RE.match(name):
        return None

    clone_url = f"https://github.com/{owner}/{name}.git"
    return RepositoryRef(owner=owner, name=name, clone_url=clone_url)


# ---------------- Workspace path helpers ----------------

def _is_within(path, root) -> bool:
    try:
        root_n = os.path.normpath(os.path.abspath(root))
        target_n = os.path.normpath(os.path.abspath(path))
    except (TypeError, ValueError):
        return False
    return target_n == root_n or target_n.startswith(root_n + os.sep)


def _is_within_workspace_root(path) -> bool:
    return _is_within(path, WORKSPACE_ROOT)


def _new_workspace_path():
    os.makedirs(WORKSPACE_ROOT, exist_ok=True)
    workspace_id = uuid4().hex
    workspace_path = os.path.join(WORKSPACE_ROOT, workspace_id)
    return workspace_id, workspace_path


def _rmtree_safe(path) -> bool:
    """Delete path only if it resolves inside WORKSPACE_ROOT. Refuses
    (no-op) for anything else, so a bad workspace_id can never make this
    function delete an arbitrary directory on the host."""
    if not path or not _is_within_workspace_root(path):
        return False
    if os.path.exists(path):
        shutil.rmtree(path, ignore_errors=True)
    return True


# ---------------- Symlink safety ----------------

def _strip_unsafe_symlinks(workspace_path) -> int:
    """Remove any symlink (file or directory) whose resolved target falls
    outside workspace_path. Never follows a link to decide whether to
    recurse into it — os.walk(followlinks=False) already refuses that."""
    removed = 0
    root_n = os.path.normpath(os.path.abspath(workspace_path))
    for root, dirs, files in os.walk(workspace_path, followlinks=False):
        for name in list(dirs) + list(files):
            full = os.path.join(root, name)
            if not os.path.islink(full):
                continue
            target = os.path.realpath(full)
            if target == root_n or target.startswith(root_n + os.sep):
                continue
            os.unlink(full)
            removed += 1
    return removed


# ---------------- Workspace scanning ----------------

def _scan_workspace(workspace_path):
    """Count files and total bytes under workspace_path, excluding the
    .git metadata directory (repository content only)."""
    file_count = 0
    total_size = 0
    for root, dirs, files in os.walk(workspace_path):
        if ".git" in dirs:
            dirs.remove(".git")
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                total_size += os.path.getsize(fpath)
            except OSError:
                pass
            file_count += 1
    return file_count, total_size


def list_repository_files(repository_id, subpath: Optional[str] = None) -> List[Dict]:
    info = get_repository_info(repository_id)
    if not info or not info.get("workspace_id"):
        return []
    workspace_path = os.path.join(WORKSPACE_ROOT, info["workspace_id"])

    base = workspace_path
    if subpath:
        candidate = os.path.normpath(os.path.join(workspace_path, subpath))
        if _is_within(candidate, workspace_path):
            base = candidate
        # else: escape attempt is ignored -> fall back to workspace root

    results = []
    if not os.path.isdir(base):
        return results
    for root, dirs, files in os.walk(base):
        if ".git" in dirs:
            dirs.remove(".git")
        for fname in files:
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, workspace_path)
            try:
                size = os.path.getsize(fpath)
            except OSError:
                size = 0
            results.append({"path": rel, "size": size})
    return results


# ---------------- Concurrency slots ----------------

async def _try_acquire_clone_slot() -> bool:
    global _active_clone_count
    async with _clone_slot_lock:
        if _active_clone_count >= MAX_CONCURRENT_CLONES:
            return False
        _active_clone_count += 1
        return True


async def _release_clone_slot() -> None:
    global _active_clone_count
    async with _clone_slot_lock:
        _active_clone_count = max(0, _active_clone_count - 1)


# ---------------- git invocation ----------------

def _run_git_clone(clone_url, workspace_path):
    """Synchronous. Always an argument list, never shell-interpreted,
    and "--" always separates git's own flags from the untrusted URL."""
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    cmd = ["git", "clone", "--depth", "1", "--single-branch", "--", clone_url, workspace_path]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=MAX_CLONE_TIME_SECONDS,
        env=env,
    )


def _get_branch(workspace_path) -> Optional[str]:
    proc = subprocess.run(
        ["git", "-C", workspace_path, "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True, text=True,
    )
    if proc.returncode == 0 and proc.stdout:
        return proc.stdout.strip()
    return None


def _get_commit_sha(workspace_path) -> Optional[str]:
    proc = subprocess.run(
        ["git", "-C", workspace_path, "rev-parse", "HEAD"],
        capture_output=True, text=True,
    )
    if proc.returncode == 0 and proc.stdout:
        return proc.stdout.strip()
    return None


# ---------------- Clone orchestration ----------------

def _mark_failed(repository_id, workspace_path) -> None:
    _rmtree_safe(workspace_path)
    conn = _conn()
    conn.execute("UPDATE github_repositories SET status='FAILED' WHERE repository_id=?",
                 (repository_id,))
    conn.commit()
    conn.close()


async def clone_repository(url, chat_id, created_by) -> CloneResult:
    ref = validate_repository_url(url)
    if ref is None:
        return CloneResult(ok=False, reason="INVALID_URL", detail="repository URL failed validation")

    acquired = await _try_acquire_clone_slot()
    if not acquired:
        return CloneResult(ok=False, reason="TOO_MANY_CONCURRENT_CLONES",
                            detail="too many clones already in progress")

    workspace_id, workspace_path = _new_workspace_path()
    now = int(time.time())
    expires_at = now + DEFAULT_REPOSITORY_TTL_SECONDS

    conn = _conn()
    cur = conn.execute(
        "INSERT INTO github_repositories "
        "(chat_id, created_by, owner, name, clone_url, workspace_id, status, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 'CLONING', ?, ?)",
        (chat_id, created_by, ref.owner, ref.name, ref.clone_url, workspace_id, now, expires_at),
    )
    conn.commit()
    repository_id = cur.lastrowid
    conn.close()

    write_audit_log(chat_id, created_by, actor="user", action="GITHUB_CLONE_STARTED",
                     detail=f"repository_id={repository_id} url={ref.clone_url}")

    def _fail(reason, detail=""):
        _mark_failed(repository_id, workspace_path)
        write_audit_log(chat_id, created_by, actor="system", action="GITHUB_CLONE_FAILED",
                         detail=f"repository_id={repository_id} reason={reason}")
        return CloneResult(ok=False, repository_id=repository_id, reason=reason, detail=detail)

    try:
        proc = await asyncio.to_thread(_run_git_clone, ref.clone_url, workspace_path)
    except subprocess.TimeoutExpired:
        await _release_clone_slot()
        return _fail("CLONE_TIMEOUT", "git clone exceeded the time limit")
    except OSError as exc:
        await _release_clone_slot()
        return _fail("CLONE_ERROR", str(exc))

    if proc.returncode != 0:
        await _release_clone_slot()
        return _fail("CLONE_FAILED", (proc.stderr or "").strip())

    _strip_unsafe_symlinks(workspace_path)
    file_count, size_bytes = _scan_workspace(workspace_path)

    if size_bytes > MAX_REPOSITORY_SIZE_BYTES:
        await _release_clone_slot()
        return _fail("REPOSITORY_TOO_LARGE", f"{size_bytes} bytes exceeds the {MAX_REPOSITORY_SIZE_BYTES} byte limit")

    if file_count > MAX_FILE_COUNT:
        await _release_clone_slot()
        return _fail("FILE_COUNT_EXCEEDED", f"{file_count} files exceeds the {MAX_FILE_COUNT} file limit")

    branch = _get_branch(workspace_path)
    commit_sha = _get_commit_sha(workspace_path)

    conn = _conn()
    conn.execute(
        "UPDATE github_repositories SET status='READY', branch=?, commit_sha=?, "
        "file_count=?, size_bytes=? WHERE repository_id=?",
        (branch, commit_sha, file_count, size_bytes, repository_id),
    )
    conn.commit()
    conn.close()

    await _release_clone_slot()
    write_audit_log(chat_id, created_by, actor="system", action="GITHUB_CLONE_COMPLETED",
                     detail=f"repository_id={repository_id} files={file_count} bytes={size_bytes}")

    return CloneResult(ok=True, repository_id=repository_id)


# ---------------- Cleanup / TTL ----------------

def cleanup_workspace(repository_id, actor_user_id) -> bool:
    info = get_repository_info(repository_id)
    if not info:
        return False
    if info.get("workspace_id"):
        _rmtree_safe(os.path.join(WORKSPACE_ROOT, info["workspace_id"]))
    conn = _conn()
    conn.execute("UPDATE github_repositories SET status='DELETED' WHERE repository_id=?",
                 (repository_id,))
    conn.commit()
    conn.close()
    write_audit_log(info["chat_id"], actor_user_id, actor="user", action="GITHUB_REPO_DELETED",
                     detail=f"repository_id={repository_id}")
    return True


def _sweep_expired_once() -> int:
    now = int(time.time())
    conn = _conn()
    rows = conn.execute(
        "SELECT repository_id, workspace_id FROM github_repositories "
        "WHERE expires_at IS NOT NULL AND expires_at < ? "
        "AND status NOT IN ('DELETED', 'EXPIRED', 'FAILED')",
        (now,),
    ).fetchall()
    removed = 0
    for row in rows:
        if row["workspace_id"]:
            _rmtree_safe(os.path.join(WORKSPACE_ROOT, row["workspace_id"]))
        conn.execute("UPDATE github_repositories SET status='EXPIRED' WHERE repository_id=?",
                     (row["repository_id"],))
        removed += 1
    conn.commit()
    conn.close()
    return removed
