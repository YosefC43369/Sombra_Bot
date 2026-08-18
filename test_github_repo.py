"""
test_github_repo.py — unit test suite for github_repo.py.

Same isolation pattern as test_scope_policy.py/test_findings.py: every
test gets a fresh tempfile SQLite DB (security.DB_PATH / gr.DB_PATH
monkeypatched) and a fresh tempdir workspace root (gr.WORKSPACE_ROOT
monkeypatched). `git` is never actually invoked — subprocess.run is
mocked in every test that reaches the clone path, and no test in this
file touches the network. A handful of real (non-network) filesystem
operations are exercised directly against the tempdir workspace root
(symlink stripping, size/count, cleanup) since those don't need git at
all.

Hardening-pass additions (see github_repo.py's HARDENING PASS changes)
are grouped under their own headers below and cross-referenced to the
checklist item they cover.
"""

import os
import time
import shutil
import asyncio
import tempfile
import unittest
import subprocess
from unittest.mock import patch

import security
import github_repo as gr


def _mock_completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class GithubRepoTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db_path = db_path
        security.DB_PATH = db_path
        gr.DB_PATH = db_path
        security.security_db_init()
        gr.github_repo_db_init()

        self._workspace_root = tempfile.mkdtemp(prefix="gh_ws_root_")
        gr.WORKSPACE_ROOT = self._workspace_root

        gr._active_clone_count = 0
        gr.MAX_CONCURRENT_CLONES = 2
        gr.MAX_FILE_COUNT = 5000
        gr.MAX_REPOSITORY_SIZE_BYTES = 250 * 1024 * 1024
        gr.MAX_TOTAL_WORKSPACE_BYTES = 2048 * 1024 * 1024
        gr.MAX_CLONE_TIME_SECONDS = 120
        gr.GIT_METADATA_TIMEOUT_SECONDS = 10

    def tearDown(self):
        try:
            os.remove(self._db_path)
        except OSError:
            pass
        shutil.rmtree(self._workspace_root, ignore_errors=True)

    # ---- helpers ----

    def _write_fake_clone(self, workspace_path, num_files=3, file_size=10):
        os.makedirs(workspace_path, exist_ok=True)
        os.makedirs(os.path.join(workspace_path, ".git"), exist_ok=True)
        with open(os.path.join(workspace_path, ".git", "HEAD"), "w") as f:
            f.write("ref: refs/heads/main\n")
        for i in range(num_files):
            with open(os.path.join(workspace_path, f"file{i}.txt"), "w") as f:
                f.write("x" * file_size)

    def _fake_run_factory(self, num_files=1, file_size=1, branch="main"):
        """Standard fake subprocess.run: clone writes files, rev-parse
        commands succeed with fixed output. Reused by most tests below."""
        def fake_run(cmd, **kwargs):
            if cmd[1] == "clone":
                self._write_fake_clone(cmd[-1], num_files=num_files, file_size=file_size)
                return _mock_completed(0)
            if "--abbrev-ref" in cmd:
                return _mock_completed(0, stdout=f"{branch}\n")
            if "rev-parse" in cmd:
                return _mock_completed(0, stdout="deadbeef1234\n")
            return _mock_completed(0)
        return fake_run

    def _insert_repo_row(self, workspace_id, status="READY", size_bytes=1,
                          chat_id=1, created_by=1, created_at=None, expires_at=None):
        """Directly seed a github_repositories row, bypassing clone_repository
        — used by tests that need to construct a specific DB state (a
        forged workspace_id, an already-full quota, a stale CLONING row,
        etc.) without going through a real clone."""
        now = int(time.time())
        created_at = now if created_at is None else created_at
        expires_at = now + 999999 if expires_at is None else expires_at
        conn = gr._conn()
        cur = conn.execute(
            "INSERT INTO github_repositories "
            "(chat_id, created_by, owner, name, clone_url, workspace_id, status, "
            "size_bytes, created_at, expires_at) "
            "VALUES (?, ?, 'owner', 'seeded', 'https://github.com/owner/seeded.git', "
            "?, ?, ?, ?, ?)",
            (chat_id, created_by, workspace_id, status, size_bytes, created_at, expires_at),
        )
        conn.commit()
        repository_id = cur.lastrowid
        conn.close()
        return repository_id

    # ================= validate_repository_url (items 1-8) =================

    def test_01_valid_github_url(self):
        r = gr.validate_repository_url("https://github.com/octocat/Hello-World")
        self.assertIsNotNone(r)
        self.assertEqual(r.owner, "octocat")
        self.assertEqual(r.name, "Hello-World")
        self.assertEqual(r.clone_url, "https://github.com/octocat/Hello-World.git")

    def test_02_invalid_garbage_url(self):
        self.assertIsNone(gr.validate_repository_url("not a url at all"))
        self.assertIsNone(gr.validate_repository_url(""))
        self.assertIsNone(gr.validate_repository_url(None))

    def test_03_non_github_url(self):
        self.assertIsNone(gr.validate_repository_url("https://gitlab.com/owner/repo"))
        self.assertIsNone(gr.validate_repository_url("https://github.com.evil.com/owner/repo"))
        self.assertIsNone(gr.validate_repository_url("https://evil.com/github.com/owner/repo"))

    def test_04_dot_git_url(self):
        r = gr.validate_repository_url("https://github.com/owner/repository.git")
        self.assertIsNotNone(r)
        self.assertEqual(r.name, "repository")
        self.assertEqual(r.clone_url, "https://github.com/owner/repository.git")

    def test_05_malformed_repository_path(self):
        self.assertIsNone(gr.validate_repository_url("https://github.com/owner/repo/blob/main/x.py"))
        self.assertIsNone(gr.validate_repository_url("https://github.com/owner"))
        self.assertIsNone(gr.validate_repository_url("https://github.com/"))
        self.assertIsNone(gr.validate_repository_url("https://github.com/owner/repo?x=1"))
        self.assertIsNone(gr.validate_repository_url("https://github.com/owner/repo#frag"))

    def test_06_path_traversal_in_url(self):
        self.assertIsNone(gr.validate_repository_url("https://github.com/../../etc/passwd"))
        self.assertIsNone(gr.validate_repository_url("https://github.com/owner/../../../etc"))

    def test_07_localhost_and_internal_ip_rejected(self):
        self.assertIsNone(gr.validate_repository_url("http://localhost/owner/repo"))
        self.assertIsNone(gr.validate_repository_url("https://localhost/owner/repo"))
        self.assertIsNone(gr.validate_repository_url("https://127.0.0.1/owner/repo"))
        self.assertIsNone(gr.validate_repository_url("https://192.168.1.10/owner/repo"))
        self.assertIsNone(gr.validate_repository_url("https://169.254.169.254/owner/repo"))
        # userinfo trick: hostname parses as evil.com, "github.com" becomes username
        self.assertIsNone(gr.validate_repository_url("https://github.com@evil.com/owner/repo"))

    def test_08_unsupported_protocol_rejected(self):
        self.assertIsNone(gr.validate_repository_url("ssh://git@github.com/owner/repo.git"))
        self.assertIsNone(gr.validate_repository_url("git://github.com/owner/repo.git"))
        self.assertIsNone(gr.validate_repository_url("file:///etc/passwd"))
        self.assertIsNone(gr.validate_repository_url("ftp://github.com/owner/repo"))
        self.assertIsNone(gr.validate_repository_url("http://github.com/owner/repo"))  # http, not https

    # ================= workspace isolation (item 9 / item 6) =================

    def test_09_workspace_isolation_unique_dirs(self):
        _id1, path1 = gr._new_workspace_path()
        _id2, path2 = gr._new_workspace_path()
        self.assertNotEqual(path1, path2)
        self.assertTrue(gr._is_within_workspace_root(path1))
        self.assertTrue(gr._is_within_workspace_root(path2))
        self.assertFalse(gr._is_within_workspace_root("/etc/passwd"))
        self.assertFalse(gr._is_within_workspace_root(os.path.join(self._workspace_root, "..", "escape")))

    def test_is_within_rejects_relative_and_absolute_traversal(self):
        root = self._workspace_root
        self.assertFalse(gr._is_within(os.path.join(root, "..", "escape"), root))
        self.assertFalse(gr._is_within("/etc/passwd", root))
        self.assertTrue(gr._is_within(os.path.join(root, "sub", "file.txt"), root))
        self.assertTrue(gr._is_within(root, root))  # root itself counts as within

    def test_is_within_rejects_sibling_directory_prefix_collision(self):
        """A naive `target.startswith(root)` check (without the os.sep
        suffix) would wrongly accept a sibling directory whose name merely
        starts with the same characters as root."""
        root = self._workspace_root
        sibling = root + "_evil"
        self.assertFalse(gr._is_within(sibling, root))
        self.assertFalse(gr._is_within_workspace_root(sibling))
        self.assertFalse(gr._is_within(os.path.join(sibling, "file.txt"), root))

    # ================= size / file-count limits (items 10-11) =================

    @patch("github_repo.subprocess.run")
    async def test_10_repository_size_limit_enforced(self, mock_run):
        gr.MAX_REPOSITORY_SIZE_BYTES = 50  # tiny cap so our fake clone exceeds it

        def fake_run(cmd, **kwargs):
            if cmd[1] == "clone":
                workspace_path = cmd[-1]
                self._write_fake_clone(workspace_path, num_files=3, file_size=100)
                return _mock_completed(0)
            return _mock_completed(0, stdout="main")
        mock_run.side_effect = fake_run

        result = await gr.clone_repository("https://github.com/owner/bigrepo", chat_id=1, created_by=99)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "REPOSITORY_TOO_LARGE")
        info = gr.get_repository_info(result.repository_id)
        self.assertEqual(info["status"], "FAILED")
        self.assertFalse(os.path.exists(os.path.join(self._workspace_root, info["workspace_id"])))
        self.assertEqual(gr._active_clone_count, 0)  # item 4: slot released after size failure

    @patch("github_repo.subprocess.run")
    async def test_11_file_count_limit_enforced(self, mock_run):
        gr.MAX_FILE_COUNT = 2  # tiny cap

        def fake_run(cmd, **kwargs):
            if cmd[1] == "clone":
                workspace_path = cmd[-1]
                self._write_fake_clone(workspace_path, num_files=5, file_size=1)
                return _mock_completed(0)
            return _mock_completed(0, stdout="main")
        mock_run.side_effect = fake_run

        result = await gr.clone_repository("https://github.com/owner/manyfiles", chat_id=1, created_by=99)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "FILE_COUNT_EXCEEDED")
        self.assertEqual(gr._active_clone_count, 0)  # item 4: slot released after file-count failure

    # ================= timeout / clone failure / cleanup (items 12-14) =================

    @patch("github_repo.subprocess.run")
    async def test_12_clone_timeout(self, mock_run):
        def fake_run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=1)
        mock_run.side_effect = fake_run

        result = await gr.clone_repository("https://github.com/owner/slowrepo", chat_id=1, created_by=99)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "CLONE_TIMEOUT")
        info = gr.get_repository_info(result.repository_id)
        self.assertEqual(info["status"], "FAILED")
        self.assertEqual(gr._active_clone_count, 0)  # item 4: slot released after timeout

    @patch("github_repo.subprocess.run")
    async def test_13_clone_failure_nonzero_exit(self, mock_run):
        mock_run.return_value = _mock_completed(128, stderr="fatal: repository not found")
        result = await gr.clone_repository("https://github.com/owner/doesnotexist", chat_id=1, created_by=99)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "CLONE_FAILED")
        self.assertIn("not found", result.detail)
        self.assertEqual(gr._active_clone_count, 0)  # item 4: slot released after git failure

    @patch("github_repo.subprocess.run")
    async def test_14_cleanup_after_failure_removes_directory(self, mock_run):
        captured = {}

        def fake_run(cmd, **kwargs):
            if cmd[1] == "clone":
                workspace_path = cmd[-1]
                captured["path"] = workspace_path
                os.makedirs(workspace_path, exist_ok=True)
                with open(os.path.join(workspace_path, "partial"), "w") as f:
                    f.write("partial clone data")
                return _mock_completed(1, stderr="fatal: early termination")
            return _mock_completed(0)
        mock_run.side_effect = fake_run

        result = await gr.clone_repository("https://github.com/owner/failrepo", chat_id=1, created_by=99)
        self.assertFalse(result.ok)
        self.assertTrue(captured["path"].startswith(self._workspace_root))
        self.assertFalse(os.path.exists(captured["path"]))

    # ================= concurrency limit (item 15) =================

    async def test_15_concurrent_clone_limit(self):
        gr.MAX_CONCURRENT_CLONES = 1
        ok1 = await gr._try_acquire_clone_slot()
        self.assertTrue(ok1)
        ok2 = await gr._try_acquire_clone_slot()
        self.assertFalse(ok2)
        await gr._release_clone_slot()
        ok3 = await gr._try_acquire_clone_slot()
        self.assertTrue(ok3)

    @patch("github_repo.subprocess.run")
    async def test_15b_clone_repository_rejects_when_slots_full(self, mock_run):
        gr.MAX_CONCURRENT_CLONES = 1
        gr._active_clone_count = 1  # simulate an in-flight clone
        result = await gr.clone_repository("https://github.com/owner/repo", chat_id=1, created_by=99)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "TOO_MANY_CONCURRENT_CLONES")
        mock_run.assert_not_called()

    # ================= repository metadata (item 16) =================

    @patch("github_repo.subprocess.run")
    async def test_16_repository_metadata_persisted(self, mock_run):
        mock_run.side_effect = self._fake_run_factory(num_files=2, file_size=5)

        result = await gr.clone_repository("https://github.com/octocat/Hello-World", chat_id=42, created_by=7)
        self.assertTrue(result.ok)
        info = gr.get_repository_info(result.repository_id)
        self.assertEqual(info["owner"], "octocat")
        self.assertEqual(info["name"], "Hello-World")
        self.assertEqual(info["status"], "READY")
        self.assertEqual(info["branch"], "main")
        self.assertEqual(info["commit_sha"], "deadbeef1234")
        self.assertEqual(info["file_count"], 2)
        self.assertTrue(gr.repository_exists(result.repository_id))
        self.assertIsNotNone(gr.get_workspace_path(result.repository_id))

    # ================= audit logging (item 17 / item 10) =================

    @patch("github_repo.subprocess.run")
    async def test_17_audit_logging_written(self, mock_run):
        mock_run.side_effect = self._fake_run_factory(num_files=1, file_size=1)

        result = await gr.clone_repository("https://github.com/owner/audited", chat_id=5, created_by=11)
        self.assertTrue(result.ok)
        log = security.get_recent_audit_log(chat_id=5, limit=20)
        actions = [row["action"] for row in log]
        self.assertIn("GITHUB_CLONE_STARTED", actions)
        self.assertIn("GITHUB_CLONE_COMPLETED", actions)

    @patch("github_repo.subprocess.run")
    async def test_17b_audit_logging_on_failure(self, mock_run):
        mock_run.return_value = _mock_completed(128, stderr="fatal: not found")
        result = await gr.clone_repository("https://github.com/owner/missing", chat_id=6, created_by=11)
        self.assertFalse(result.ok)
        log = security.get_recent_audit_log(chat_id=6, limit=20)
        actions = [row["action"] for row in log]
        self.assertIn("GITHUB_CLONE_FAILED", actions)

    @patch("github_repo.subprocess.run")
    async def test_17c_audit_logging_on_ttl_expiry(self, mock_run):
        """item 10 fix: repository expiry was the one lifecycle event that
        wasn't calling write_audit_log() at all."""
        mock_run.side_effect = self._fake_run_factory(num_files=1, file_size=1)

        result = await gr.clone_repository("https://github.com/owner/expiring-audit", chat_id=9, created_by=1)
        self.assertTrue(result.ok)

        conn = gr._conn()
        conn.execute("UPDATE github_repositories SET expires_at=? WHERE repository_id=?",
                     (int(time.time()) - 10, result.repository_id))
        conn.commit()
        conn.close()

        gr._sweep_expired_once()
        log = security.get_recent_audit_log(chat_id=9, limit=20)
        actions = [row["action"] for row in log]
        self.assertIn("GITHUB_REPO_EXPIRED", actions)

    # ================= subprocess safety (items 19-20 / item 7) =================

    def test_19_git_invocation_never_uses_shell(self):
        with patch("github_repo.subprocess.run") as mock_run:
            mock_run.return_value = _mock_completed(0)
            gr._run_git_clone("https://github.com/owner/repo.git", "/tmp/whatever")
            args, kwargs = mock_run.call_args
            self.assertNotIn("shell", kwargs)
            self.assertIsInstance(args[0], list)
            self.assertIn("--", args[0])
            self.assertEqual(kwargs.get("env", {}).get("GIT_TERMINAL_PROMPT"), "0")

    def test_20_no_forbidden_execution_tokens_in_module(self):
        """Static guardrail: this module must never contain a call that
        could execute cloned repository content."""
        with open(os.path.join(os.path.dirname(gr.__file__), "github_repo.py")) as f:
            src = f.read()
        for forbidden in ("os.system(", "shell=True", "importlib.import_module",
                           "eval(", "exec(", "pip install", "npm install", "os.popen("):
            self.assertNotIn(forbidden, src, f"forbidden token found: {forbidden!r}")

    # ============ git metadata subprocess: timeout + safety (item 3 / item 8) ============

    def test_get_branch_has_timeout_and_never_raises_on_timeout(self):
        with patch("github_repo.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd=["git"], timeout=1)) as mock_run:
            result = gr._get_branch("/tmp/whatever")
        self.assertIsNone(result)
        mock_run.assert_called_once()

    def test_get_commit_sha_has_timeout_and_never_raises_on_timeout(self):
        with patch("github_repo.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd=["git"], timeout=1)) as mock_run:
            result = gr._get_commit_sha("/tmp/whatever")
        self.assertIsNone(result)
        mock_run.assert_called_once()

    def test_get_branch_never_raises_on_oserror(self):
        with patch("github_repo.subprocess.run", side_effect=OSError("git binary vanished")):
            result = gr._get_branch("/tmp/whatever")
        self.assertIsNone(result)

    def test_metadata_lookups_pass_the_dedicated_timeout_config(self):
        with patch("github_repo.subprocess.run") as mock_run:
            mock_run.return_value = _mock_completed(0, stdout="main\n")
            gr._get_branch("/tmp/whatever")
            gr._get_commit_sha("/tmp/whatever")
        for call in mock_run.call_args_list:
            self.assertEqual(call.kwargs.get("timeout"), gr.GIT_METADATA_TIMEOUT_SECONDS)
            # item 8: cwd/workspace containment via `-C <workspace_path>`, not
            # via subprocess cwd=, so the working directory of the bot
            # process itself is never changed by these calls
            self.assertIn("-C", call.args[0])

    @patch("github_repo.subprocess.run")
    async def test_clone_reaches_ready_when_metadata_lookup_times_out(self, mock_run):
        """item 8: metadata failure after a successful, validated clone must
        be deterministic (READY here, with branch/commit left null) and
        must never leave the row stuck at CLONING."""
        def fake_run(cmd, **kwargs):
            if cmd[1] == "clone":
                self._write_fake_clone(cmd[-1], num_files=1, file_size=1)
                return _mock_completed(0)
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=1)
        mock_run.side_effect = fake_run

        result = await gr.clone_repository("https://github.com/owner/nometa", chat_id=1, created_by=1)
        self.assertTrue(result.ok)
        info = gr.get_repository_info(result.repository_id)
        self.assertEqual(info["status"], "READY")
        self.assertIsNone(info["branch"])
        self.assertIsNone(info["commit_sha"])
        self.assertEqual(gr._active_clone_count, 0)

    # ================= symlink escape protection (item 6) =================

    def test_symlink_pointing_outside_workspace_is_stripped(self):
        _wsid, workspace_path = gr._new_workspace_path()
        os.makedirs(workspace_path)
        outside_target = tempfile.mkdtemp(prefix="gh_outside_")
        try:
            with open(os.path.join(outside_target, "secret.txt"), "w") as f:
                f.write("should not be reachable")
            link_path = os.path.join(workspace_path, "escape_link")
            os.symlink(outside_target, link_path)

            with open(os.path.join(workspace_path, "normal.txt"), "w") as f:
                f.write("ok")

            removed = gr._strip_unsafe_symlinks(workspace_path)
            self.assertEqual(removed, 1)
            self.assertFalse(os.path.exists(link_path) or os.path.islink(link_path))
            self.assertTrue(os.path.exists(os.path.join(workspace_path, "normal.txt")))
        finally:
            shutil.rmtree(outside_target, ignore_errors=True)

    def test_symlink_pointing_inside_workspace_is_kept(self):
        _wsid, workspace_path = gr._new_workspace_path()
        os.makedirs(workspace_path)
        with open(os.path.join(workspace_path, "real.txt"), "w") as f:
            f.write("data")
        link_path = os.path.join(workspace_path, "internal_link")
        os.symlink(os.path.join(workspace_path, "real.txt"), link_path)

        removed = gr._strip_unsafe_symlinks(workspace_path)
        self.assertEqual(removed, 0)
        self.assertTrue(os.path.islink(link_path))

    def test_nested_symlink_chain_escaping_workspace_is_stripped(self):
        """A symlink chain (link -> link -> outside file) must still be
        detected: os.path.realpath resolves every hop, not just the first."""
        _wsid, workspace_path = gr._new_workspace_path()
        os.makedirs(workspace_path)
        outside_target = tempfile.mkdtemp(prefix="gh_outside_nested_")
        try:
            secret = os.path.join(outside_target, "secret.txt")
            with open(secret, "w") as f:
                f.write("nope")
            inner_link = os.path.join(outside_target, "inner_link")
            os.symlink(secret, inner_link)  # outside -> outside
            chain_link = os.path.join(workspace_path, "chain_link")
            os.symlink(inner_link, chain_link)  # inside workspace -> outside link -> outside file

            removed = gr._strip_unsafe_symlinks(workspace_path)
            self.assertEqual(removed, 1)
            self.assertFalse(os.path.exists(chain_link) or os.path.islink(chain_link))
        finally:
            shutil.rmtree(outside_target, ignore_errors=True)

    # ================= list_repository_files path traversal (item 6) =================

    @patch("github_repo.subprocess.run")
    async def test_list_files_rejects_subpath_escape(self, mock_run):
        mock_run.side_effect = self._fake_run_factory(num_files=2, file_size=1)

        result = await gr.clone_repository("https://github.com/owner/listable", chat_id=1, created_by=1)
        self.assertTrue(result.ok)

        files_normal = gr.list_repository_files(result.repository_id)
        self.assertGreaterEqual(len(files_normal), 2)

        files_escape = gr.list_repository_files(result.repository_id, subpath="../../../etc")
        # escape attempt is ignored -> falls back to workspace root listing,
        # never raises and never returns a path outside the workspace
        for f in files_escape:
            self.assertFalse(f["path"].startswith(".."))

    @patch("github_repo.subprocess.run")
    async def test_list_files_rejects_absolute_subpath_escape(self, mock_run):
        mock_run.side_effect = self._fake_run_factory(num_files=2, file_size=1)

        result = await gr.clone_repository("https://github.com/owner/listable2", chat_id=1, created_by=1)
        self.assertTrue(result.ok)

        files_escape = gr.list_repository_files(result.repository_id, subpath="/etc")
        for f in files_escape:
            self.assertFalse(os.path.isabs(f["path"]))

    # ========== forged/foreign workspace_id, nonexistent workspace (item 6 / item 9) ==========

    def test_get_workspace_path_rejects_forged_workspace_id_absolute_escape(self):
        """os.path.join(root, "/etc") discards `root` entirely and returns
        "/etc" -- the classic Python path-join footgun. workspace_id is
        always a uuid4().hex in normal operation, but a DB-level forgery
        (or bug elsewhere) must not be trusted."""
        repository_id = self._insert_repo_row(workspace_id="/etc", status="READY")
        self.assertIsNone(gr.get_workspace_path(repository_id))

    def test_list_repository_files_rejects_forged_workspace_id(self):
        repository_id = self._insert_repo_row(workspace_id="/etc", status="READY")
        self.assertEqual(gr.list_repository_files(repository_id), [])

    def test_get_workspace_path_rejects_relative_traversal_workspace_id(self):
        repository_id = self._insert_repo_row(workspace_id="../../../etc", status="READY")
        self.assertIsNone(gr.get_workspace_path(repository_id))

    def test_get_workspace_path_and_list_files_handle_nonexistent_workspace_dir(self):
        """DB says READY, workspace_id looks legitimate, but nothing was
        ever written to disk for it (or it was removed out of band)."""
        repository_id = self._insert_repo_row(workspace_id="ws-never-created", status="READY")
        self.assertIsNone(gr.get_workspace_path(repository_id))
        self.assertEqual(gr.list_repository_files(repository_id), [])

    async def test_repository_id_cannot_reach_another_repositorys_workspace(self):
        """Two distinct repositories always resolve to their own distinct
        workspace_id -- there is no parameter through which one
        repository_id can be pointed at another's files."""
        with patch("github_repo.subprocess.run") as mock_run:
            mock_run.side_effect = self._fake_run_factory(num_files=1, file_size=1)
            r1 = await gr.clone_repository("https://github.com/owner/repoA", chat_id=1, created_by=1)
            r2 = await gr.clone_repository("https://github.com/owner/repoB", chat_id=1, created_by=1)
        self.assertTrue(r1.ok and r2.ok)
        path1 = gr.get_workspace_path(r1.repository_id)
        path2 = gr.get_workspace_path(r2.repository_id)
        self.assertNotEqual(path1, path2)
        files1 = {f["path"] for f in gr.list_repository_files(r1.repository_id)}
        files2 = {f["path"] for f in gr.list_repository_files(r2.repository_id)}
        self.assertTrue(files1 and files2)

    # ================= cleanup_workspace / delete + TTL sweep =================

    @patch("github_repo.subprocess.run")
    async def test_cleanup_workspace_deletes_and_marks_status(self, mock_run):
        mock_run.side_effect = self._fake_run_factory(num_files=1, file_size=1)

        result = await gr.clone_repository("https://github.com/owner/todelete", chat_id=1, created_by=1)
        self.assertTrue(result.ok)
        path = gr.get_workspace_path(result.repository_id)
        self.assertTrue(os.path.isdir(path))

        ok = gr.cleanup_workspace(result.repository_id, actor_user_id=1)
        self.assertTrue(ok)
        self.assertFalse(os.path.exists(path))
        info = gr.get_repository_info(result.repository_id)
        self.assertEqual(info["status"], "DELETED")

    def test_rmtree_safe_refuses_outside_root(self):
        outside = tempfile.mkdtemp(prefix="gh_outside2_")
        try:
            marker = os.path.join(outside, "marker.txt")
            with open(marker, "w") as f:
                f.write("keep me")
            gr._rmtree_safe(outside)
            self.assertTrue(os.path.exists(marker))
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    @patch("github_repo.subprocess.run")
    async def test_ttl_sweep_expires_old_workspace(self, mock_run):
        mock_run.side_effect = self._fake_run_factory(num_files=1, file_size=1)

        result = await gr.clone_repository("https://github.com/owner/expiring", chat_id=1, created_by=1)
        self.assertTrue(result.ok)

        conn = gr._conn()
        conn.execute("UPDATE github_repositories SET expires_at=? WHERE repository_id=?",
                     (int(time.time()) - 10, result.repository_id))
        conn.commit()
        conn.close()

        removed = gr._sweep_expired_once()
        self.assertEqual(removed, 1)
        info = gr.get_repository_info(result.repository_id)
        self.assertEqual(info["status"], "EXPIRED")

    # ===================== total workspace quota (item 1) =====================

    @patch("github_repo.subprocess.run")
    async def test_workspace_quota_exceeded_rejects_before_clone(self, mock_run):
        gr.MAX_REPOSITORY_SIZE_BYTES = 100
        gr.MAX_TOTAL_WORKSPACE_BYTES = 150  # one repo's worth of headroom, not two
        self._insert_repo_row(workspace_id="ws-existing", status="READY", size_bytes=100)

        result = await gr.clone_repository("https://github.com/owner/newrepo", chat_id=1, created_by=1)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "WORKSPACE_QUOTA_EXCEEDED")
        mock_run.assert_not_called()  # rejected before ever touching git/disk
        self.assertEqual(gr._active_clone_count, 0)  # slot acquired then released, not leaked

    @patch("github_repo.subprocess.run")
    async def test_workspace_quota_allows_clone_when_room_available(self, mock_run):
        gr.MAX_REPOSITORY_SIZE_BYTES = 100
        gr.MAX_TOTAL_WORKSPACE_BYTES = 1000  # plenty of headroom
        self._insert_repo_row(workspace_id="ws-existing2", status="READY", size_bytes=100)
        mock_run.side_effect = self._fake_run_factory(num_files=1, file_size=1)

        result = await gr.clone_repository("https://github.com/owner/roomrepo", chat_id=1, created_by=1)
        self.assertTrue(result.ok)

    async def test_fresh_cloning_reservation_counts_towards_quota(self):
        gr._insert_reservation_helper = None  # no-op placeholder (keeps helper list tidy)
        self._insert_repo_row(workspace_id="ws-inflight", status="CLONING",
                               size_bytes=gr.MAX_REPOSITORY_SIZE_BYTES)
        total = gr._workspace_reserved_and_ready_bytes()
        self.assertEqual(total, gr.MAX_REPOSITORY_SIZE_BYTES)

    async def test_stale_cloning_reservation_excluded_from_quota(self):
        """If the process dies mid-clone, nothing will ever revisit that
        CLONING row -- it must not permanently eat into the quota."""
        stale_created_at = int(time.time()) - (gr.MAX_CLONE_TIME_SECONDS * 2) - 10
        self._insert_repo_row(workspace_id="ws-abandoned", status="CLONING",
                               size_bytes=gr.MAX_REPOSITORY_SIZE_BYTES,
                               created_at=stale_created_at)
        total = gr._workspace_reserved_and_ready_bytes()
        self.assertEqual(total, 0)

    def test_failed_deleted_expired_never_count_towards_quota(self):
        self._insert_repo_row(workspace_id="ws-failed", status="FAILED", size_bytes=999)
        self._insert_repo_row(workspace_id="ws-deleted", status="DELETED", size_bytes=999)
        self._insert_repo_row(workspace_id="ws-expired", status="EXPIRED", size_bytes=999)
        self.assertEqual(gr._workspace_reserved_and_ready_bytes(), 0)

    @patch("github_repo.subprocess.run")
    async def test_concurrent_clone_quota_reservation_prevents_overcommit(self, mock_run):
        """item 1: race-condition regression. Two clone_repository() calls
        started together must never both reserve quota that only has room
        for one -- the reservation check+insert has no `await` between
        them, so one of the two concurrent tasks always loses the race
        deterministically rather than both slipping through."""
        gr.MAX_REPOSITORY_SIZE_BYTES = 100
        gr.MAX_TOTAL_WORKSPACE_BYTES = 150  # room for exactly one reservation
        gr.MAX_CONCURRENT_CLONES = 2
        mock_run.side_effect = self._fake_run_factory(num_files=1, file_size=1)

        results = await asyncio.gather(
            gr.clone_repository("https://github.com/owner/race1", chat_id=1, created_by=1),
            gr.clone_repository("https://github.com/owner/race2", chat_id=1, created_by=1),
        )
        oks = [r for r in results if r.ok]
        fails = [r for r in results if not r.ok]
        self.assertEqual(len(oks), 1)
        self.assertEqual(len(fails), 1)
        self.assertEqual(fails[0].reason, "WORKSPACE_QUOTA_EXCEEDED")
        self.assertLessEqual(gr._workspace_reserved_and_ready_bytes(), gr.MAX_TOTAL_WORKSPACE_BYTES)
        self.assertEqual(gr._active_clone_count, 0)  # both slots released, none leaked

    # ============== unexpected exception cleanup (items 4, 5, 9, 13) ==============

    @patch("github_repo.subprocess.run")
    async def test_unexpected_scan_error_is_contained(self, mock_run):
        """Before this hardening pass, an OSError raised while scanning the
        workspace after a successful clone would propagate out of
        clone_repository() uncaught: the clone slot would leak, the DB row
        would stay at CLONING forever, and nothing would be audited."""
        mock_run.side_effect = self._fake_run_factory(num_files=1, file_size=1)

        with patch("github_repo._scan_workspace", side_effect=OSError("simulated disk error")):
            result = await gr.clone_repository("https://github.com/owner/scanerror", chat_id=1, created_by=1)

        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "SCAN_ERROR")
        info = gr.get_repository_info(result.repository_id)
        self.assertEqual(info["status"], "FAILED")
        self.assertNotEqual(info["status"], "CLONING")  # never left stuck (item 9)
        self.assertEqual(gr._active_clone_count, 0)  # item 4: slot released
        log = security.get_recent_audit_log(chat_id=1, limit=20)
        self.assertIn("GITHUB_CLONE_FAILED", [row["action"] for row in log])

    @patch("github_repo.subprocess.run")
    async def test_unexpected_error_does_not_leak_internals_to_result(self, mock_run):
        """item 5: the CloneResult.detail returned to the (eventual)
        Telegram-facing caller must be a generic message, never a raw
        stack trace or filesystem path."""
        mock_run.side_effect = self._fake_run_factory(num_files=1, file_size=1)

        with patch("github_repo._scan_workspace",
                   side_effect=OSError("/very/sensitive/host/path leaked here")):
            result = await gr.clone_repository("https://github.com/owner/leaktest", chat_id=1, created_by=1)

        self.assertFalse(result.ok)
        self.assertNotIn("/very/sensitive/host/path", result.detail or "")

    async def test_unexpected_error_before_db_insert_still_releases_slot(self):
        """If something explodes before a repository_id even exists (e.g.
        the quota check itself), the outer catch-all still has to release
        the slot it already acquired."""
        with patch("github_repo._workspace_reserved_and_ready_bytes",
                   side_effect=RuntimeError("simulated unexpected failure")):
            result = await gr.clone_repository("https://github.com/owner/earlycrash", chat_id=1, created_by=1)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INTERNAL_ERROR")
        self.assertEqual(gr._active_clone_count, 0)

    # ===================== state consistency after failure (item 9) =====================

    @patch("github_repo.subprocess.run")
    async def test_state_consistency_no_ready_with_dangling_path_after_failure(self, mock_run):
        mock_run.return_value = _mock_completed(128, stderr="fatal: not found")
        result = await gr.clone_repository("https://github.com/owner/staterepo", chat_id=1, created_by=1)
        self.assertFalse(result.ok)
        self.assertIsNone(gr.get_workspace_path(result.repository_id))
        self.assertEqual(gr.list_repository_files(result.repository_id), [])

    def test_get_workspace_path_none_for_ready_row_with_directory_removed_out_of_band(self):
        _wsid, workspace_path = gr._new_workspace_path()
        os.makedirs(workspace_path)
        repository_id = self._insert_repo_row(workspace_id=os.path.basename(workspace_path),
                                                status="READY", size_bytes=1)
        self.assertIsNotNone(gr.get_workspace_path(repository_id))

        shutil.rmtree(workspace_path)  # simulate an out-of-band wipe (e.g. host restart)
        self.assertIsNone(gr.get_workspace_path(repository_id))
        self.assertEqual(gr.list_repository_files(repository_id), [])

    # ================= Phase 7: list_repositories_for_chat =================
    # (added for the Telegram /github list command, which needs a
    # chat-scoped listing API -- github_repo.py had no such function
    # before this integration pass.)

    def test_list_repositories_for_chat_most_recent_first(self):
        r1 = self._insert_repo_row(workspace_id="ws1", chat_id=42, status="READY")
        r2 = self._insert_repo_row(workspace_id="ws2", chat_id=42, status="READY")
        r3 = self._insert_repo_row(workspace_id="ws3", chat_id=42, status="DELETED")
        rows = gr.list_repositories_for_chat(42)
        self.assertEqual([row["repository_id"] for row in rows], [r3, r2, r1])

    def test_list_repositories_for_chat_scoped_to_chat_id(self):
        self._insert_repo_row(workspace_id="ws_a", chat_id=1)
        self._insert_repo_row(workspace_id="ws_b", chat_id=2)
        rows_chat1 = gr.list_repositories_for_chat(1)
        self.assertEqual(len(rows_chat1), 1)
        self.assertEqual(rows_chat1[0]["chat_id"], 1)

    def test_list_repositories_for_chat_empty_for_unknown_chat(self):
        self.assertEqual(gr.list_repositories_for_chat(999999), [])

    def test_list_repositories_for_chat_includes_terminal_statuses(self):
        # /github list should show FAILED/DELETED/EXPIRED rows too --
        # matching list_programs()/list_findings()'s "return everything,
        # let the Telegram layer show the [status] tag" style, rather
        # than silently hiding closed repositories.
        self._insert_repo_row(workspace_id="ws_x", chat_id=7, status="FAILED")
        rows = gr.list_repositories_for_chat(7)
        self.assertEqual(rows[0]["status"], "FAILED")

    # ================= Phase 7: sweep_expired_repositories (public wrapper) =================
    # (added so app.py's periodic TTL sweep task has a stable, non-
    # underscore-prefixed entry point instead of reaching into
    # _sweep_expired_once() directly; no new sweep logic is introduced.)

    def test_sweep_expired_repositories_expires_past_ttl_row(self):
        self._insert_repo_row(workspace_id="ws_old", status="READY",
                               expires_at=int(time.time()) - 10)
        self.assertEqual(gr.sweep_expired_repositories(), 1)
        info = gr.get_repository_info(
            gr.list_repositories_for_chat(1)[0]["repository_id"]
        )
        self.assertEqual(info["status"], "EXPIRED")

    def test_sweep_expired_repositories_zero_when_nothing_expired(self):
        self._insert_repo_row(workspace_id="ws_fresh", status="READY",
                               expires_at=int(time.time()) + 999999)
        self.assertEqual(gr.sweep_expired_repositories(), 0)


if __name__ == "__main__":
    unittest.main()