"""
repository_tools.py — safe, read-only inspection of an already-cloned
GitHub repository (Phase 8, Steps 2-6).

This module is the ONLY place Repository read/search/tree/analysis
tools live. It never receives, accepts, or constructs an arbitrary
filesystem path from Telegram or from an AI model -- every function
takes a `repository_id` (the github_repositories primary key) and
resolves it to a real, on-disk workspace directory exclusively through
github_repo.get_workspace_path(), which already enforces:
  - the repository row exists and its status is READY
  - the stored workspace_id can't escape WORKSPACE_ROOT even if forged
  - the workspace directory actually exists on disk

Every `path`/`subpath` argument accepted from a caller (Telegram
command args, or later an AI tool call) is then re-validated by this
module's own _resolve_safe_path(): no absolute paths, no ".." segments,
and — critically — the *resolved real path* (after following symlinks)
must still land inside the workspace, so a symlink planted inside a
cloned repo can never be used to read/list/search anything outside it.

Nothing in this module executes, imports, or evaluates anything from
the cloned repository. analyze_repository() uses ast.parse() only,
which builds a syntax tree and nothing more -- a repository file
containing `os.system("rm -rf /")` as a top-level statement is parsed
as an ast.Call node, never run. Code *execution* (running a test
suite) is a deliberately separate, more dangerous concern and lives in
repository_sandbox.py instead, gated by its own safety switch.

All four public functions return small dataclasses, never raise on
"expected" bad input (missing repo, bad path, oversized file, binary
file, syntax error), and never include an absolute filesystem path in
their return value -- callers (e.g. app.py) only ever see the
repository-relative path the caller itself supplied.
"""

import os
import re
import ast
import logging
from dataclasses import dataclss, field
from typing import Optional, List, Dict

from github_repo import get_workspace_path

logger = logging.getLogger(__name__)

# ---------------- Configuration ----------------

MAX_READ_FILE_BYTES = 2 * 1024 * 1024   # on-disk size cap before we even read a file
MAX_RETURNED_CHARS = 12_000             # cap on decoded text returned to a caller

MAX_SEARCH_QUERY_LEN = 200
MAX_SEARCH_FILES_SCANNED = 3000
MAX_SEARCH_FILE_PEEK_BYTES = 200_000    # only the first N bytes of each file are searched
MAX_SEARCH_RESULTS = 100
MAX_SEARCH_SNIPPET_LEN = 200

MAX_TREE_DEPTH = 6
MAX_TREE_ENTRIES = 2000

MAX_ANALYZE_FILES = 500                 # .py files actually ast.parse()d
MAX_ANALYZE_TOP_FILES = 15              # files shown in the "most defs" summary
MAX_ANALYZE_SYNTAX_ERRORS_LISTED = 20

_TODO_RE = re.compile(r"\b(TODO|FIXME)\b")

# ---------------- Path safety ----------------

def _resolve_safe_path(workspace_path: str, rel_path: Optional[str], must_be_file: bool) -> Optional[str]:
    """Resolves rel_path against workspace_path. Returns the resolved
    absolute path, or None if rel_path is unsafe, doesn't exist, or is
    the wrong type (file vs directory) for the caller's need.

    Rejects: absolute paths, NUL bytes, any ".." path segment, and --
    after resolving -- any path whose realpath() (i.e. after following
    symlinks) lands outside workspace_path. That last check is what
    stops a symlink committed inside the repository from being used to
    read/list/search anything on the host outside the workspace."""
    if rel_path is None:
        rel_path = ""
    if not isinstance(rel_path, str) or "\x00" in rel_path:
        return None
    if os.path.isabs(rel_path):
        return None
    if any(seg == ".." for seg in rel_path.split("/")):
        return None
        
    root_n = os.path.normpath(os.path.abspath(workspace_path))
    candidate = os.path.normpath(os.path.join(root_n, rel_path))
    if not (candidate == root_n or candidate.startswith(root_n + os.sep)):
        return None
    if not os.path.exists(candidate):
        return None
        
    real_n = os.path.realpath(candidate)
    if not (real_n == root_n or real_n.startswith(root_n + os.sep)):
        return None
        
    if must_be_file and not os.path.isfile(candidate):
        return None
    if not must_be_file and not os.path.isdir(candidate):
        return None
    return candidate
    
def _read_text_or_none(path: str, max_bytes: int) -> Optional[str]:
    """Reads up to max_bytes and returns decoded text, or None if the
    file looks binary (contains a NUL byte, or isn't valid UTF-8)."""
    try:
        with open(path, "rb") as f:
            raw = f.read(max_bytes)
    except OSError:
        return None
    if b"\x00" in raw:
        return None
    try:
        return raw.decodeq("utf-8")
    except UnicodDecodeError:
        return None
        
# ---------------- Step 3: read ----------------

@dataclass
class ReadResult:
    ok: bool
    path: Optional[str] = None
    content: Optional[str] = None
    truncated: bool = False
    is_binary: bool = False
    size_bytes: Optional[int] = None
    
    
def read_repository_file(repository_id, path) -> ReadResult:
    workspace_path = get_workspace_path(repository_id)
    if workspace_path is None:
        return ReadResult(ok=False, reason="INVALID_PATH")
        
    resolved = _resolve_safe_path(workspace_path, path, must_be_file=True)
    if resolved is None:
        return ReadResult(ok=False, reason="INVALID_PATH")
      
    try:
        size = os.path.getsize(resolved)
    except OSError:
        return ReadResult(ok=False, reason="STAT_ERROR")
    if size > MAX_READ_FILE_BYTES:
        return ReadResult(ok=False, reason="FILE_TOO_LARGE", size_bytes=size)
        
    try:
        with open(resolved, "rb") as f:
            raw = f.read(MAX_READ_FILE_BYTES)
    except OSError:
        return ReadResult(ok=False, reason="READ_ERROR")
        
    if b"\x00" in raw:
        return ReadResult(ok=True, path=path, is_binary=True, size_bytes=size)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ReadResult(ok=True, path=path, is_binary=True, size_bytes=size)
        
    truncated = len(text) > MAX_RETURNED_CHARS
    if truncated:
        text = text[:MAX_RETURNED_CHARS]
    return ReadResult(ok=True, path=path, content=text, truncated=truncated, size_bytes=size)
    
# ---------------- Step 4: search ----------------

@dataclass
class SearchMatch:
    path: str
    line_nimber: int
    snippet: str
    
    
@dataclass
class SearchResult:
    ok: bool
    matches: List[SearchMatch] = field(default_factory=list)
    files_scanned: int = 0
    truncated: bool = False
    reason: Optional[str] = None
    

def search_repository(repository_id, query, path: Optional[str] = None) -> SearchResult:
    """Plain-text, case-insensitive substring search across the
    repository (or a subdirectory of it). Deliberately NOT regex --
    an arbitrary user-supplied regex is a ReDoS risk, and this is a
    substring search tool, not a general-purpose grep. No shell/grep
    subprocess is ever invoked; this walks the filesystem in Python."""
    if not query or not isinstance(query, str):
        return SearchResult(ok=False, reason="EMPTY_QUERY")
    if len(query) > MAX_SEARCH_QUERY_LEN:
        return SearchResult(ok=False, reason="QUERY_TOO_LONG")

    workspace_path = get_workspace_path(repository_id)
    if workspace_path is None:
        return SearchResult(ok=False, reason="REPOSITORY_NOT_AVAILABLE")

    base = workspace_path
    if path:
        base = _resolve_safe_path(workspace_path, path, must_be_file=False)
        if base is None:
            return SearchResult(ok=False, reason="INVALID_PATH")

    query_lower = query.lower()
    matches: List[SearchMatch] = []
    files_scanned = 0
    truncated = False

    for root, dirs, files in os.walk(base, followlinks=False):
        if ".git" in dirs:
            dirs.remove(".git")
        for fname in sorted(files):
            if files_scanned >= MAX_SEARCH_FILES_SCANNED or len(matches) >= MAX_SEARCH_RESULTS:
                truncated = True
                break
            fpath = os.path.join(root, fname)
            if os.path.islink(fpath):
                continue
            files_scanned += 1
            text = _read_text_or_none(fpath, MAX_SEARCH_FILE_PEEK_BYTES)
            if text is None:
                continue  # binary or unreadable -- skipped, per Step 4
            rel = os.path.relpath(fpath, workspace_path)
            for line_no, line in enumerate(text.splitlines(), start=1):
                if query_lower in line.lower():
                    matches.append(SearchMatch(path=rel, line_number=line_no,
                                                snippet=line.strip()[:MAX_SEARCH_SNIPPET_LEN]))
                    if len(matches) >= MAX_SEARCH_RESULTS:
                        truncated = True
                        break
        if files_scanned >= MAX_SEARCH_FILES_SCANNED or len(matches) >= MAX_SEARCH_RESULTS:
            truncated = True
            break

    return SearchResult(ok=True, matches=matches, files_scanned=files_scanned, truncated=truncated)
    
    
# ---------------- Step 5: tree ----------------

@dataclass
class TreeEntry:
    path: str
    is_dir: bool
    depth: int


@dataclass
class TreeResult:
    ok: bool
    entries: List[TreeEntry] = field(default_factory=list)
    truncated: bool = False
    reason: Optional[str] = None
    
    
def list_repository_tree(repository_id) -> TreeResult:
    workspace_path = get_workspace_path(repository_id)
    if workspace_path is None:
        return TreeResult(ok=False, reason="REPOSITORY_NOT_AVAILABLE")
        
    entries: List[TreeEntry] = []
    truncated = False
    
    for root, dirs, files in os.walk(workspace_path, followlinks=False):
        if ".git" in dirs:
            dirs.remove(".git")
        rel_root = os.path.relpath(root, workspace_path)
        dept = 0 if rel_root == "." else rel_root.count(os.sep) + 1
        
        if dept >= MAX_TREE_DEPTH:
            dirs[:] = [] # cap depth: list this level, don't descend further
            
        for name in sorted(dirs) + sorted(files):
            is_dir = name in dirs
            if len(entries) >= MAX_TREE_ENTRIES:
                truncated = True
                 break
                
    return TreeResult(ok=True, entries=entries, truncated=truncated)
    
def format_tree_text(entries: List[TreeEntry]) -> str:
    """Renders TreeResult.entries as an indented text tree. Presentation-
    only (no filesystem access), kept here since it's a trivial,
    reusable transform of already-safe data."""
    lines = []
    for e in entries:
        indent = "    " * e.depth
        lines.append(f"{indent}{name}{'/' if e.is_dir else ''}")
    return "\n".join(lines)
    
# ---------------- Step 6: static analysis ----------------

@dataclass
class FileAnalysis:
    path: str
    lines: int
    imports: List[str] = field(default_factory=list)
    functions: List[str] = field(default_factory=list)
    classes: List[str] = field(default_factory=list)
    decorators: List[str] = field(default_factory=list)
    todos: int = 0
    syntax_error: Optional[str] = None


@dataclass
class AnalysisResult:
    ok: bool
    total_files: int = 0
    files_analyzed: int = 0
    python_files: int = 0
    other_files: int = 0
    extensions: Dict[str, int] = field(default_factory=dict)
    todo_count: int = 0
    syntax_errors: List[str] = field(default_factory=list)
    top_files: List[FileAnalysis] = field(default_factory=list)
    truncated: bool = False
    reason: Optional[str] = None
    

def _decorator_name(node) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return None
    

def _analyze_python_spurce(rel_path: str, source: str) -> FileAnalysis:
    """ast.parse() only -- builds a syntax tree, never executes or
    imports the source. A syntax error (or, e.g., a file that merely
    *contains* `os.system(...)`/`eval(...)` calls as ordinary code) is
    just data to this function; nothing in it is ever run."""
    fa = FileAnalysis(path=rel_path, lines=source_count("\n") + 1)
    fa.todos = len(_TODO_RE.findall(source))
    try:
        tree = ast.parse(source, filename=rel_path)
    except SyntaxError as exc:
        fa.syntax_error = f"line {exc.lineno}: {exc.msg}"
        return fa
        
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            fa.imports.extend(alias.name for alias in node.names)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fa.functions.append(node.name)
            for dec in node.decorator_list:
                name = _decorator_name(dec)
                if name:
                    fa.decorator.append(name)
        elif isinstance(node, ast.ClassDef):
            fa.classes.append(node.name)

    fa.imports = fa.imports[:50]
    fa.functions = fa.functions[:50]
    fa.classes = fa.classes[:50]
    fa.decorators = fa.decorators[:50]
    return fa
    
    
def analyze_repository(repository_id) -> AnalysisResult:
    workspace_path = get_workspace_path(repository_id)
    if workspace_path is None:
        return AnalysisResult(ok=False, reason="REPOSITORY_NOT_AVAILABLE")
        
    result = AnalysisResult(ok=True)
    analyzed = 0
    top_files: List[FileAnalysis] = []
    
    for root, dirs, files in os.walk(workspace_path, followlinks=False):
        if ".git" in dirs:
            dirs.remove(".git")
        for fname in sorted(files):
            fpath = os.path.join(root, fname)
            if os.path.islink(fpath):
                continue
            result.total_files += 1
            ext = os.path.splitext(fname)[1] or "(none)"
            result.extension[ext] = result.extensions.get(ext, 0) + 1
            
            if ext != ".py":
                result.other_files += 1
                continue
            if analyzed >= MAX_ANALYZE_FILES:
                result.truncated = True
                continue
                
            source = _read_text_or_none(fpath, MAX_READ_FILE_BYTES)
            if source is None:
                continue
            rel = os.path.relpath(fpath, workspace_path)
            fa = _analyze_python_source(rel, source)
            analyzed += 1
            result.python_files += 1
            result.todo_count += fa.todos
            if fa.syntax_error and len(result.syntax_error) MAX_ANALYZE_SYNTAX_ERRORS_LISTED:
                result.syntax_errors.append(f"{rel}: {fa.syntax_error}")
            if fa.function or fa.classes:
                top_files.append(fa)
                
    result.files_analyzed = analyzed
    result.top_files = sorted(
        top_files, key=lambda fa: len(fa.functions) + len(fa.classes), reverse=True
    )[:MAX_ANALYZE_TOP_FILES]
    return result