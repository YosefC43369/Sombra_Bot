"""
test_github_repo.py — unit test suite for github_repo.py.

Same isolation pattern as test_scope_policy.py/test_findings.py: every
test gets a fresh tempfile SQLite DB (security.DB_PATH / gr.DB import
monkeypatched) and a fresh tempdir workspace root (gr.WORKSPACE_ROOT
monkeypatched). `git` is never actually invoked — subprocess.run is
mocked in every test that reaches the clone path, and no test in this
file touches the network. A handful of real (non-network) filesystem
operations are exercised directly against the tempdir workspace root
(symlink stripping, size/count, cleanup) since those don't need git at
all.
"""

import os
import time
import shutil
import tempfile
import subprocess
from unittest.mock import path

import security
import github_repo as gr

def _mock_complete(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)
    
class GithubRepoTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close()
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
                
    # ================= validate_repository_url (Phase 3 / items 1-8) =================
    
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
        
    # ================= workspace isolation (item 9) =================

    def test_09_workspace_isolation_unique_dirs(self):
        _id1, path1 = gr._new_workspace_path()
        _id2, path2 = gr._new_workspace_path()
        self.assertNotEqual(path1, path2)
        self.assertTrue(gr._is_within_workspace_root(path1))
        self.assertTrue(gr._is_within_workspace_root(path2))
        self.assertFalse(gr._is_within_workspace_root("/etc/passwd"))
        self.assertFalse(gr._is_within_workspace_root(os.path.join(self._workspace_root, "..", "escape")))

    # ================= size / file-count limits (items 10-11) =================
    
    @path("github_repo.subprocess.run")
    async def test_10_repository_size_limit_enforced(self, mock_run):
        gr.MAX_REPOSITORY_SIZE_BYTES = 50 # tiny cap so our fake clone exceeds it
        
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

    @patch("github_repo.subprocess.run")
    async def test_13_clone_failure_nonzero_exit(self, mock_run):
        mock_run.return_value = _mock_completed(128, stderr="fatal: repository not found")
        result = await gr.clone_repository("https://github.com/owner/doesnotexist", chat_id=1, created_by=99)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "CLONE_FAILED")
        self.assertIn("not found", result.detail)

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
        def fake_run(cmd, **kwargs):
            if cmd[1] == "clone":
                self._write_fake_clone(cmd[-1], num_files=2, file_size=5)
                return _mock_completed(0)
            if "rev-parse" in cmd and "--abbrev-ref" in cmd:
                return _mock_completed(0, stdout="main\n")
            if "rev-parse" in cmd:
                return _mock_completed(0, stdout="deadbeef1234\n")
            return _mock_completed(0)
        mock_run.side_effect = fake_run

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

    # ================= audit logging (item 17) =================

    @patch("github_repo.subprocess.run")
    async def test_17_audit_logging_written(self, mock_run):
        def fake_run(cmd, **kwargs):
            if cmd[1] == "clone":
                self._write_fake_clone(cmd[-1], num_files=1, file_size=1)
                return _mock_completed(0)
            return _mock_completed(0, stdout="main")
        mock_run.side_effect = fake_run

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

    # ================= subprocess safety (items 19-20) =================
    
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
                           "eval(", "exec(", "pip install", "npm install"):
            self.assertNotIn(forbidden, src, f"forbidden token found: {forbidden!r}")

    # ================= symlink escape protection (Phase 5/6, bonus) =================

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

    # ================= list_repository_files path traversal (bonus) =================

    @patch("github_repo.subprocess.run")
    async def test_list_files_rejects_subpath_escape(self, mock_run):
        def fake_run(cmd, **kwargs):
            if cmd[1] == "clone":
                self._write_fake_clone(cmd[-1], num_files=2, file_size=1)
                return _mock_completed(0)
            return _mock_completed(0, stdout="main")
        mock_run.side_effect = fake_run

        result = await gr.clone_repository("https://github.com/owner/listable", chat_id=1, created_by=1)
        self.assertTrue(result.ok)

        files_normal = gr.list_repository_files(result.repository_id)
        self.assertGreaterEqual(len(files_normal), 2)

        files_escape = gr.list_repository_files(result.repository_id, subpath="../../../etc")
        # escape attempt is ignored -> falls back to workspace root listing,
        # never raises and never returns a path outside the workspace
        for f in files_escape:
            self.assertFalse(f["path"].startswith(".."))

    # ================= cleanup_workspace / delete + TTL sweep (Phase 5/7) =================
    
    @patch("github_repo.subprocess.run")
    async def test_cleanup_workspace_deletes_and_marks_status(self, mock_run):
        def fake_run(cmd, **kwargs):
            if cmd[1] == "clone":
                self._write_fake_clone(cmd[-1], num_files=1, file_size=1)
                return _mock_completed(0)
            return _mock_completed(0, stdout="main")
        mock_run.side_effect = fake_run

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
        def fake_run(cmd, **kwargs):
            if cmd[1] == "clone":
                self._write_fake_clone(cmd[-1], num_files=1, file_size=1)
                return _mock_completed(0)
            return _mock_completed(0, stdout="main")
        mock_run.side_effect = fake_run

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


if __name__ == "__main__":
    unittest.main()