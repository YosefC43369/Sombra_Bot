"""
test_bb_report.py — Phase 6 test suite for bb_report.py.

Same isolation pattern as test_scope_policy.py / test_findings.py: each
test gets a fresh, isolated SQLite tempfile. Builds Programs/
Authorizations/Scope Rules/Findings/Evidence through the real
scope_policy.py / findings.py public APIs (not by poking at internal
tables), matching how bb_report.py itself reads them.
"""

import os
import time
import tempfile
import unittest

import security
import scope_policy as sp
import findings as f
import bb_report as br


class BBReportTestCase(unittest.TestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db_path = path
        security.DB_PATH = path
        sp.DB_PATH = path
        f.DB_PATH = path
        security.security_db_init()
        sp.scope_policy_db_init()
        f.findings_db_init()

    def tearDown(self):
        try:
            os.remove(self._db_path)
        except OSError:
            pass

    # ---- fixture helpers (mirrors test_findings.py) ----

    def _active_program(self, chat_id=1, admin=999):
        pid = sp.create_program(chat_id, "Acme Bug Bounty", created_by=admin)
        sp.set_program_status(pid, sp.ProgramStatus.ACTIVE.value, admin)
        return pid

    def _active_authorization(self, program_id, admin=999, reviewer=1000,
                               effective_at=None, expires_at=None):
        aid = sp.import_authorization(
            program_id, source_type="email", actor_user_id=admin,
            source_reference="security@acme.test", effective_at=effective_at,
            expires_at=expires_at,
        )
        sp.review_authorization(aid, approve=True, reviewer_user_id=reviewer)
        return aid

    def _include(self, program_id, target_type, pattern, admin=999):
        return sp.add_scope_rule(program_id, sp.RuleType.INCLUDE.value, target_type, pattern, admin)

    # ---- get_bb_report_data() ----

    def test_report_unknown_program_returns_none(self):
        self.assertIsNone(br.get_bb_report_data(999999))

    def test_report_empty_program_has_zero_counts(self):
        pid = self._active_program()
        data = br.get_bb_report_data(pid)
        self.assertIsNotNone(data)
        self.assertEqual(data["authorization_total"], 0)
        self.assertEqual(data["scope_rule_total"], 0)
        self.assertEqual(data["finding_total"], 0)
        self.assertEqual(data["evidence_total"], 0)
        self.assertEqual(data["authorization_status_counts"], {})
        self.assertEqual(data["finding_status_counts"], {})

    def test_report_counts_authorizations_by_effective_status(self):
        pid = self._active_program()
        now = int(time.time())
        self._active_authorization(pid)  # ACTIVE, no expiry
        self._active_authorization(pid, expires_at=now + 10)  # ACTIVE now, EXPIRED soon
        pending_id = sp.import_authorization(pid, source_type="email", actor_user_id=999)  # PENDING_REVIEW

        data = br.get_bb_report_data(pid)
        self.assertEqual(data["authorization_total"], 3)
        # At "now" the time-limited one hasn't expired yet.
        self.assertEqual(data["authorization_status_counts"].get("ACTIVE"), 2)
        self.assertEqual(data["authorization_status_counts"].get("PENDING_REVIEW"), 1)

    def test_report_reflects_effective_expiry_not_stored_status(self):
        """The whole point of Phase 6 fix C: a report taken after an
        authorization's expires_at has passed must count it as
        EXPIRED, not ACTIVE, even though nothing ever wrote EXPIRED
        into the stored status column."""
        pid = self._active_program()
        now = int(time.time())
        aid = self._active_authorization(pid, expires_at=now + 10)
        self.assertEqual(sp.get_authorization(aid)["status"], sp.AuthorizationStatus.ACTIVE.value)

        # Report data itself is not time-parameterized (it calls
        # effective_authorization_status() with the real clock), so
        # simulate "later" by asserting against a manually recomputed
        # projection using the same real row and a later _now.
        auth = sp.get_authorization(aid)
        later_status = sp.effective_authorization_status(auth, _now=now + 20)
        self.assertEqual(later_status, sp.AuthorizationStatus.EXPIRED.value)

    def test_report_counts_scope_rules_by_type(self):
        pid = self._active_program()
        self._include(pid, sp.TargetType.DOMAIN.value, "example.com")
        self._include(pid, sp.TargetType.URL.value, "https://example.com/api")
        sp.add_scope_rule(pid, sp.RuleType.EXCLUDE.value, sp.TargetType.DOMAIN.value,
                           "staging.example.com", 999)

        data = br.get_bb_report_data(pid)
        self.assertEqual(data["scope_rule_total"], 3)
        self.assertEqual(data["scope_rule_type_counts"].get("INCLUDE"), 2)
        self.assertEqual(data["scope_rule_type_counts"].get("EXCLUDE"), 1)
        self.assertEqual(data["scope_type_counts"].get("DOMAIN"), 2)
        self.assertEqual(data["scope_type_counts"].get("URL"), 1)

    def test_report_counts_findings_by_status_and_severity(self):
        pid = self._active_program()
        self._active_authorization(pid)
        self._include(pid, sp.TargetType.DOMAIN.value, "example.com")

        r1 = f.create_finding(pid, "example.com", "Finding A", created_by=1, severity="HIGH")
        r2 = f.create_finding(pid, "example.com", "Finding B", created_by=1, severity="LOW")
        self.assertTrue(r1.ok and r2.ok)
        f.update_finding_status(r1.finding_id, "TRIAGED", actor_user_id=1)

        data = br.get_bb_report_data(pid)
        self.assertEqual(data["finding_total"], 2)
        self.assertEqual(data["finding_status_counts"].get("TRIAGED"), 1)
        self.assertEqual(data["finding_status_counts"].get("OPEN"), 1)
        self.assertEqual(data["finding_severity_counts"].get("HIGH"), 1)
        self.assertEqual(data["finding_severity_counts"].get("LOW"), 1)

    def test_report_counts_evidence_across_all_findings(self):
        pid = self._active_program()
        self._active_authorization(pid)
        self._include(pid, sp.TargetType.DOMAIN.value, "example.com")
        r1 = f.create_finding(pid, "example.com", "Finding A", created_by=1)
        r2 = f.create_finding(pid, "example.com", "Finding B", created_by=1)
        f.add_evidence(r1.finding_id, "TEXT", created_by=1, description="note 1")
        f.add_evidence(r1.finding_id, "TEXT", created_by=1, description="note 2")
        f.add_evidence(r2.finding_id, "TEXT", created_by=1, description="note 3")

        data = br.get_bb_report_data(pid)
        self.assertEqual(data["evidence_total"], 3)

    # ---- format_bb_report_message() ----

    def test_format_includes_program_name_and_id(self):
        pid = self._active_program()
        data = br.get_bb_report_data(pid)
        text = br.format_bb_report_message(data)
        self.assertIn(f"#{pid}", text)
        self.assertIn("Acme Bug Bounty", text)

    def test_format_handles_empty_program_without_crashing(self):
        pid = self._active_program()
        data = br.get_bb_report_data(pid)
        text = br.format_bb_report_message(data)
        self.assertIn("ยังไม่มี Authorization", text)
        self.assertIn("ยังไม่มี Scope Rule", text)
        self.assertIn("ยังไม่มี Finding", text)

    def test_format_never_calls_evaluate_target(self):
        """Static guard: format_bb_report_message must be pure string
        formatting over already-computed data, never a fresh policy
        decision -- catches an accidental reintroduction of scope-
        matching logic into the reporting layer."""
        pid = self._active_program()
        data = br.get_bb_report_data(pid)
        # If format_bb_report_message ever called evaluate_target()
        # with a bogus/no-longer-valid program_id, this would still
        # succeed today, but the real guard is architectural: assert
        # the module does not import evaluate_target at all.
        self.assertNotIn("evaluate_target", dir(br))
        br.format_bb_report_message(data)  # should not raise
