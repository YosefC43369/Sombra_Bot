"""
test_scope_policy.py — Phase 4 unit test suite for scope_policy.py itself.

test_findings.py already exercises scope_policy.py through findings.py's
create_finding() integration surface (the path app.py actually calls).
This file is the complement: it drives scope_policy.py's own public API
directly -- create_program/set_program_status, import_authorization/
review_authorization/revoke_authorization, add_scope_rule/remove_scope_rule,
normalize_target, and evaluate_target -- to get unit-level coverage of
paths the integration tests don't reach (Program/Authorization CRUD,
AUTHORIZATION_NOT_EFFECTIVE, direct structural-matching edge cases,
rule-pattern validation). Same isolation pattern as test_findings.py:
every test gets a fresh tempfile SQLite DB.
"""

import os
import time
import tempfile
import unittest

import security
import scope_policy as sp


class ScopePolicyTestCase(unittest.TestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db_path = path
        security.DB_PATH = path
        sp.DB_PATH = path
        security.security_db_init()
        sp.scope_policy_db_init()

    def tearDown(self):
        try:
            os.remove(self._db_path)
        except OSError:
            pass

    # ---- fixture helpers ----

    def _active_program(self, chat_id=1, admin=999):
        pid = sp.create_program(chat_id, "Acme Bug Bounty", created_by=admin)
        sp.set_program_status(pid, sp.ProgramStatus.ACTIVE.value, admin)
        return pid

    def _active_authorization(self, program_id, admin=999, reviewer=1000,
                               effective_at=None, expires_at=None):
        aid = sp.import_authorization(
            program_id, source_type="email", actor_user_id=admin,
            source_reference="security@acme.test", authorization_reference="ACME-2026-01",
            effective_at=effective_at, expires_at=expires_at,
        )
        sp.review_authorization(aid, approve=True, reviewer_user_id=reviewer)
        return aid

    def _include(self, program_id, target_type, pattern, admin=999):
        return sp.add_scope_rule(program_id, sp.RuleType.INCLUDE.value, target_type, pattern, admin)

    def _exclude(self, program_id, target_type, pattern, admin=999):
        return sp.add_scope_rule(program_id, sp.RuleType.EXCLUDE.value, target_type, pattern, admin)

    # ---- Program lifecycle ----

    def test_new_program_defaults_to_paused(self):
        pid = sp.create_program(1, "New Program", created_by=999)
        program = sp.get_program(pid)
        self.assertEqual(program["status"], sp.ProgramStatus.PAUSED.value)

    def test_set_program_status_activates(self):
        pid = sp.create_program(1, "New Program", created_by=999)
        ok = sp.set_program_status(pid, sp.ProgramStatus.ACTIVE.value, 999)
        self.assertTrue(ok)
        self.assertEqual(sp.get_program(pid)["status"], sp.ProgramStatus.ACTIVE.value)

    def test_set_program_status_rejects_invalid_status(self):
        pid = sp.create_program(1, "New Program", created_by=999)
        ok = sp.set_program_status(pid, "NOT_A_REAL_STATUS", 999)
        self.assertFalse(ok)
        self.assertEqual(sp.get_program(pid)["status"], sp.ProgramStatus.PAUSED.value)

    def test_set_program_status_nonexistent_program(self):
        self.assertFalse(sp.set_program_status(999999, sp.ProgramStatus.ACTIVE.value, 999))

    def test_archived_program_cannot_return_to_active(self):
        pid = sp.create_program(1, "New Program", created_by=999)
        sp.set_program_status(pid, sp.ProgramStatus.ARCHIVED.value, 999)
        ok = sp.set_program_status(pid, sp.ProgramStatus.ACTIVE.value, 999)
        self.assertFalse(ok)
        self.assertEqual(sp.get_program(pid)["status"], sp.ProgramStatus.ARCHIVED.value)

    def test_archived_program_cannot_return_to_paused(self):
        pid = sp.create_program(1, "New Program", created_by=999)
        sp.set_program_status(pid, sp.ProgramStatus.ARCHIVED.value, 999)
        ok = sp.set_program_status(pid, sp.ProgramStatus.PAUSED.value, 999)
        self.assertFalse(ok)
        self.assertEqual(sp.get_program(pid)["status"], sp.ProgramStatus.ARCHIVED.value)

    def test_active_program_can_be_paused_then_reactivated(self):
        pid = sp.create_program(1, "New Program", created_by=999)
        sp.set_program_status(pid, sp.ProgramStatus.ACTIVE.value, 999)
        self.assertTrue(sp.set_program_status(pid, sp.ProgramStatus.PAUSED.value, 999))
        self.assertTrue(sp.set_program_status(pid, sp.ProgramStatus.ACTIVE.value, 999))
        self.assertEqual(sp.get_program(pid)["status"], sp.ProgramStatus.ACTIVE.value)

    def test_paused_program_can_be_archived_directly(self):
        pid = sp.create_program(1, "New Program", created_by=999)  # PAUSED by default
        ok = sp.set_program_status(pid, sp.ProgramStatus.ARCHIVED.value, 999)
        self.assertTrue(ok)
        self.assertEqual(sp.get_program(pid)["status"], sp.ProgramStatus.ARCHIVED.value)

    def test_set_program_status_same_status_is_not_a_transition(self):
        pid = sp.create_program(1, "New Program", created_by=999)
        sp.set_program_status(pid, sp.ProgramStatus.ACTIVE.value, 999)
        ok = sp.set_program_status(pid, sp.ProgramStatus.ACTIVE.value, 999)
        self.assertFalse(ok)

    def test_list_programs_scoped_to_chat(self):
        sp.create_program(1, "Chat 1 Program", created_by=999)
        sp.create_program(2, "Chat 2 Program", created_by=999)
        chat1_programs = sp.list_programs(1)
        self.assertEqual(len(chat1_programs), 1)
        self.assertEqual(chat1_programs[0]["name"], "Chat 1 Program")

    def test_get_nonexistent_program_returns_none(self):
        self.assertIsNone(sp.get_program(999999))

    # ---- Authorization lifecycle ----

    def test_import_authorization_starts_pending(self):
        pid = self._active_program()
        aid = sp.import_authorization(pid, source_type="email", actor_user_id=999)
        auth = sp.get_authorization(aid)
        self.assertEqual(auth["status"], sp.AuthorizationStatus.PENDING_REVIEW.value)
        self.assertIsNone(auth["reviewed_by"])
        self.assertIsNone(auth["reviewed_at"])

    def test_import_authorization_unknown_program_fails(self):
        self.assertIsNone(sp.import_authorization(999999, source_type="email", actor_user_id=999))

    def test_review_authorization_approve_sets_active_and_reviewer(self):
        pid = self._active_program()
        aid = sp.import_authorization(pid, source_type="email", actor_user_id=999)
        ok = sp.review_authorization(aid, approve=True, reviewer_user_id=1000, notes="looks legit")
        self.assertTrue(ok)
        auth = sp.get_authorization(aid)
        self.assertEqual(auth["status"], sp.AuthorizationStatus.ACTIVE.value)
        self.assertEqual(auth["reviewed_by"], 1000)
        self.assertIsNotNone(auth["reviewed_at"])

    def test_review_authorization_reject_still_records_reviewer(self):
        pid = self._active_program()
        aid = sp.import_authorization(pid, source_type="email", actor_user_id=999)
        sp.review_authorization(aid, approve=False, reviewer_user_id=1000)
        auth = sp.get_authorization(aid)
        self.assertEqual(auth["status"], sp.AuthorizationStatus.REJECTED.value)
        self.assertEqual(auth["reviewed_by"], 1000)  # accountable even on rejection

    def test_review_authorization_cannot_be_redone(self):
        pid = self._active_program()
        aid = sp.import_authorization(pid, source_type="email", actor_user_id=999)
        sp.review_authorization(aid, approve=False, reviewer_user_id=1000)
        # A REJECTED artifact cannot be laundered into ACTIVE by reviewing again.
        second = sp.review_authorization(aid, approve=True, reviewer_user_id=1000)
        self.assertFalse(second)
        self.assertEqual(sp.get_authorization(aid)["status"], sp.AuthorizationStatus.REJECTED.value)

    def test_revoke_active_authorization(self):
        pid = self._active_program()
        aid = self._active_authorization(pid)
        ok = sp.revoke_authorization(aid, actor_user_id=999)
        self.assertTrue(ok)
        self.assertEqual(sp.get_authorization(aid)["status"], sp.AuthorizationStatus.REVOKED.value)

    def test_revoke_pending_authorization(self):
        pid = self._active_program()
        aid = sp.import_authorization(pid, source_type="email", actor_user_id=999)
        ok = sp.revoke_authorization(aid, actor_user_id=999)
        self.assertTrue(ok)
        self.assertEqual(sp.get_authorization(aid)["status"], sp.AuthorizationStatus.REVOKED.value)

    def test_revoke_already_revoked_fails(self):
        pid = self._active_program()
        aid = self._active_authorization(pid)
        sp.revoke_authorization(aid, actor_user_id=999)
        self.assertFalse(sp.revoke_authorization(aid, actor_user_id=999))

    def test_list_authorizations_scoped_to_program(self):
        pid1 = self._active_program(chat_id=1)
        pid2 = self._active_program(chat_id=2)
        sp.import_authorization(pid1, source_type="email", actor_user_id=999)
        sp.import_authorization(pid2, source_type="email", actor_user_id=999)
        self.assertEqual(len(sp.list_authorizations(pid1)), 1)
        self.assertEqual(len(sp.list_authorizations(pid2)), 1)

    # ---- Scope rule CRUD ----

    def test_add_scope_rule_normalizes_domain(self):
        pid = self._active_program()
        rule_id = self._include(pid, sp.TargetType.DOMAIN.value, "Example.COM.")
        self.assertIsNotNone(rule_id)
        rules = sp.list_scope_rules(pid)
        self.assertEqual(rules[0]["pattern"], "example.com")

    def test_add_scope_rule_url_without_scheme_rejected(self):
        pid = self._active_program()
        rule_id = self._include(pid, sp.TargetType.URL.value, "example.com/api")
        self.assertIsNone(rule_id)

    def test_add_scope_rule_invalid_rule_type_rejected(self):
        pid = self._active_program()
        rule_id = sp.add_scope_rule(pid, "NOT_A_RULE_TYPE", sp.TargetType.DOMAIN.value,
                                     "example.com", 999)
        self.assertIsNone(rule_id)

    def test_add_scope_rule_malformed_pattern_rejected(self):
        pid = self._active_program()
        rule_id = self._include(pid, sp.TargetType.IP.value, "not-an-ip")
        self.assertIsNone(rule_id)

    def test_remove_scope_rule(self):
        pid = self._active_program()
        rule_id = self._include(pid, sp.TargetType.DOMAIN.value, "example.com")
        self.assertTrue(sp.remove_scope_rule(rule_id, 999))
        self.assertEqual(sp.list_scope_rules(pid), [])

    def test_remove_nonexistent_scope_rule(self):
        self.assertFalse(sp.remove_scope_rule(999999, 999))

    # ---- normalize_target: DOMAIN / URL / IP / CIDR ----

    def test_normalize_domain_lowercases_and_strips_trailing_dot(self):
        t = sp.normalize_target("Example.COM.")
        self.assertEqual(t.target_type, sp.TargetType.DOMAIN.value)
        self.assertEqual(t.domain, "example.com")

    def test_normalize_domain_single_label_rejected(self):
        self.assertIsNone(sp.normalize_target("localhost"))

    def test_normalize_domain_invalid_chars_rejected(self):
        self.assertIsNone(sp.normalize_target("exa mple.com"))
        self.assertIsNone(sp.normalize_target("example_.com"))

    def test_normalize_url_extracts_scheme_domain_port_path(self):
        t = sp.normalize_target("https://example.com:8443/api/v1/")
        self.assertEqual(t.target_type, sp.TargetType.URL.value)
        self.assertEqual(t.scheme, "https")
        self.assertEqual(t.domain, "example.com")
        self.assertEqual(t.port, 8443)
        self.assertEqual(t.path, "/api/v1/")

    def test_normalize_url_unsupported_scheme_rejected(self):
        self.assertIsNone(sp.normalize_target("ftp://example.com/"))

    def test_normalize_url_no_hostname_rejected(self):
        self.assertIsNone(sp.normalize_target("https:///path"))

    def test_normalize_ip_v4(self):
        t = sp.normalize_target("192.168.1.1")
        self.assertEqual(t.target_type, sp.TargetType.IP.value)
        self.assertEqual(t.ip, "192.168.1.1")

    def test_normalize_ip_v6(self):
        t = sp.normalize_target("2001:db8::1")
        self.assertEqual(t.target_type, sp.TargetType.IP.value)

    def test_normalize_cidr(self):
        t = sp.normalize_target("10.0.0.0/24")
        self.assertEqual(t.target_type, sp.TargetType.CIDR.value)
        self.assertEqual(t.network, "10.0.0.0/24")

    def test_normalize_malformed_cidr_rejected(self):
        self.assertIsNone(sp.normalize_target("10.0.0.0/999"))

    def test_normalize_empty_and_whitespace_rejected(self):
        self.assertIsNone(sp.normalize_target(""))
        self.assertIsNone(sp.normalize_target("   "))

    # ---- Structural matching: domain boundary ----

    def test_domain_matches_exact(self):
        self.assertTrue(sp._domain_matches("example.com", "example.com"))

    def test_domain_matches_proper_subdomain(self):
        self.assertTrue(sp._domain_matches("example.com", "api.example.com"))

    def test_domain_does_not_match_lookalike_prefix(self):
        # 'evil-example.com' must not match a rule for 'example.com'.
        self.assertFalse(sp._domain_matches("example.com", "evil-example.com"))

    def test_domain_does_not_match_lookalike_suffix(self):
        # 'example.com.evil.test' must not match a rule for 'example.com'
        # via naive substring matching.
        self.assertFalse(sp._domain_matches("example.com", "example.com.evil.test"))

    # ---- Structural matching: URL path boundary ----

    def test_path_prefix_matches_exact_and_subpath(self):
        self.assertTrue(sp._path_is_prefix("/api", "/api"))
        self.assertTrue(sp._path_is_prefix("/api", "/api/v1/users"))

    def test_path_prefix_does_not_match_similar_segment(self):
        # '/apix' must not match a rule scoped to '/api'.
        self.assertFalse(sp._path_is_prefix("/api", "/apix"))

    # ---- Structural matching: IP / CIDR ----

    def test_ip_in_network(self):
        self.assertTrue(sp._ip_in_network("10.0.0.5", "10.0.0.0/24"))
        self.assertFalse(sp._ip_in_network("10.0.1.5", "10.0.0.0/24"))

    def test_nested_cidr_containment(self):
        self.assertTrue(sp._network_in_network("10.0.0.0/24", "10.0.0.0/16"))

    def test_cidr_not_contained_rejected(self):
        self.assertFalse(sp._network_in_network("10.1.0.0/24", "10.0.0.0/16"))

    def test_cidr_different_ip_versions_do_not_match(self):
        self.assertFalse(sp._network_in_network("10.0.0.0/24", "::/0"))

    # ---- evaluate_target: core DENY invariants ----

    def test_evaluate_target_has_no_is_admin_parameter(self):
        import inspect
        params = inspect.signature(sp.evaluate_target).parameters
        self.assertNotIn("is_admin", params)

    def test_unknown_program_denies(self):
        decision = sp.evaluate_target(999999, "example.com")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, sp.Reason.PROGRAM_NOT_FOUND.value)

    def test_paused_program_denies(self):
        pid = sp.create_program(1, "Paused Program", created_by=999)  # PAUSED by default
        self._active_authorization(pid)
        self._include(pid, sp.TargetType.DOMAIN.value, "example.com")
        decision = sp.evaluate_target(pid, "example.com")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, sp.Reason.PROGRAM_NOT_ACTIVE.value)

    def test_archived_program_denies(self):
        pid = self._active_program()
        self._active_authorization(pid)
        self._include(pid, sp.TargetType.DOMAIN.value, "example.com")
        sp.set_program_status(pid, sp.ProgramStatus.ARCHIVED.value, 999)
        decision = sp.evaluate_target(pid, "example.com")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, sp.Reason.PROGRAM_NOT_ACTIVE.value)

    def test_active_program_alone_is_not_authorization(self):
        """Core invariant: an ACTIVE program an admin set up is not
        itself sufficient. With zero Authorization Artifacts, ALLOW
        must never happen no matter who created/activated the program."""
        pid = self._active_program()
        self._include(pid, sp.TargetType.DOMAIN.value, "example.com")
        decision = sp.evaluate_target(pid, "example.com")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, sp.Reason.AUTHORIZATION_NOT_FOUND.value)

    def test_pending_authorization_denies(self):
        pid = self._active_program()
        sp.import_authorization(pid, source_type="email", actor_user_id=999)  # never reviewed
        self._include(pid, sp.TargetType.DOMAIN.value, "example.com")
        decision = sp.evaluate_target(pid, "example.com")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, sp.Reason.AUTHORIZATION_PENDING.value)

    def test_rejected_authorization_denies(self):
        pid = self._active_program()
        aid = sp.import_authorization(pid, source_type="email", actor_user_id=999)
        sp.review_authorization(aid, approve=False, reviewer_user_id=1000)
        self._include(pid, sp.TargetType.DOMAIN.value, "example.com")
        decision = sp.evaluate_target(pid, "example.com")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, sp.Reason.AUTHORIZATION_REJECTED.value)

    def test_revoked_authorization_denies(self):
        pid = self._active_program()
        aid = self._active_authorization(pid)
        sp.revoke_authorization(aid, actor_user_id=999)
        self._include(pid, sp.TargetType.DOMAIN.value, "example.com")
        decision = sp.evaluate_target(pid, "example.com")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, sp.Reason.AUTHORIZATION_REVOKED.value)

    def test_expired_authorization_denies(self):
        pid = self._active_program()
        now = int(time.time())
        self._active_authorization(pid, expires_at=now - 3600)
        self._include(pid, sp.TargetType.DOMAIN.value, "example.com")
        decision = sp.evaluate_target(pid, "example.com", current_time=now)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, sp.Reason.AUTHORIZATION_EXPIRED.value)

    def test_not_yet_effective_authorization_denies(self):
        pid = self._active_program()
        now = int(time.time())
        self._active_authorization(pid, effective_at=now + 3600)
        self._include(pid, sp.TargetType.DOMAIN.value, "example.com")
        decision = sp.evaluate_target(pid, "example.com", current_time=now)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, sp.Reason.AUTHORIZATION_NOT_EFFECTIVE.value)

    def test_status_says_active_but_expiry_still_enforced(self):
        """Even though the stored status is ACTIVE, evaluate_target must
        compute 'valid right now' rather than trust a stale status
        column -- an authorization nobody got around to expiring can't
        grant access past its own expiry."""
        pid = self._active_program()
        now = int(time.time())
        aid = self._active_authorization(pid, expires_at=now + 10)
        self._include(pid, sp.TargetType.DOMAIN.value, "example.com")
        self.assertEqual(sp.get_authorization(aid)["status"], sp.AuthorizationStatus.ACTIVE.value)
        decision = sp.evaluate_target(pid, "example.com", current_time=now + 20)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, sp.Reason.AUTHORIZATION_EXPIRED.value)

    def test_malformed_target_denies(self):
        pid = self._active_program()
        self._active_authorization(pid)
        self._include(pid, sp.TargetType.DOMAIN.value, "example.com")
        decision = sp.evaluate_target(pid, "not a valid target!!")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, sp.Reason.TARGET_INVALID.value)

    # ---- effective_authorization_status() (Phase 6) ----

    def test_effective_status_active_not_expired_stays_active(self):
        pid = self._active_program()
        now = int(time.time())
        aid = self._active_authorization(pid, expires_at=now + 3600)
        auth = sp.get_authorization(aid)
        self.assertEqual(sp.effective_authorization_status(auth, _now=now),
                          sp.AuthorizationStatus.ACTIVE.value)

    def test_effective_status_active_past_expiry_reports_expired(self):
        pid = self._active_program()
        now = int(time.time())
        aid = self._active_authorization(pid, expires_at=now + 10)
        auth = sp.get_authorization(aid)
        # Stored status column is still literally ACTIVE...
        self.assertEqual(auth["status"], sp.AuthorizationStatus.ACTIVE.value)
        # ...but the effective/display status must match what
        # evaluate_target() would actually decide right now.
        self.assertEqual(sp.effective_authorization_status(auth, _now=now + 20),
                          sp.AuthorizationStatus.EXPIRED.value)

    def test_effective_status_active_no_expiry_stays_active(self):
        pid = self._active_program()
        aid = self._active_authorization(pid)  # expires_at=None
        auth = sp.get_authorization(aid)
        self.assertEqual(sp.effective_authorization_status(auth),
                          sp.AuthorizationStatus.ACTIVE.value)

    def test_effective_status_non_active_passes_through_unchanged(self):
        pid = self._active_program()
        aid = sp.import_authorization(pid, source_type="email", actor_user_id=999)
        auth = sp.get_authorization(aid)
        self.assertEqual(auth["status"], sp.AuthorizationStatus.PENDING_REVIEW.value)
        self.assertEqual(sp.effective_authorization_status(auth),
                          sp.AuthorizationStatus.PENDING_REVIEW.value)
        sp.revoke_authorization(aid, actor_user_id=999)
        auth = sp.get_authorization(aid)
        self.assertEqual(sp.effective_authorization_status(auth),
                          sp.AuthorizationStatus.REVOKED.value)

    def test_effective_status_does_not_write_to_database(self):
        """effective_authorization_status() is read-only display logic --
        it must never mutate the stored row."""
        pid = self._active_program()
        now = int(time.time())
        aid = self._active_authorization(pid, expires_at=now + 10)
        sp.effective_authorization_status(sp.get_authorization(aid), _now=now + 20)
        self.assertEqual(sp.get_authorization(aid)["status"], sp.AuthorizationStatus.ACTIVE.value)

    def test_no_scope_rules_denies(self):
        pid = self._active_program()
        self._active_authorization(pid)
        decision = sp.evaluate_target(pid, "example.com")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, sp.Reason.TARGET_OUT_OF_SCOPE.value)

    def test_no_include_match_denies(self):
        pid = self._active_program()
        self._active_authorization(pid)
        self._include(pid, sp.TargetType.DOMAIN.value, "other.com")
        decision = sp.evaluate_target(pid, "example.com")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, sp.Reason.NO_INCLUDE_MATCH.value)

    # ---- INCLUDE / EXCLUDE ----

    def test_include_match_allows(self):
        pid = self._active_program()
        self._active_authorization(pid)
        self._include(pid, sp.TargetType.DOMAIN.value, "example.com")
        decision = sp.evaluate_target(pid, "example.com")
        self.assertTrue(decision.allowed)

    def test_include_subdomain_allows(self):
        pid = self._active_program()
        self._active_authorization(pid)
        self._include(pid, sp.TargetType.DOMAIN.value, "example.com")
        decision = sp.evaluate_target(pid, "api.example.com")
        self.assertTrue(decision.allowed)

    def test_exclude_overrides_include(self):
        pid = self._active_program()
        self._active_authorization(pid)
        self._include(pid, sp.TargetType.DOMAIN.value, "example.com")
        self._exclude(pid, sp.TargetType.DOMAIN.value, "internal.example.com")
        decision = sp.evaluate_target(pid, "internal.example.com")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, sp.Reason.TARGET_EXCLUDED.value)
        # A sibling subdomain not covered by the EXCLUDE rule still matches INCLUDE.
        other = sp.evaluate_target(pid, "api.example.com")
        self.assertTrue(other.allowed)

    def test_exclude_wins_even_when_declared_before_include(self):
        pid = self._active_program()
        self._active_authorization(pid)
        # Order of rule creation must not matter -- EXCLUDE always wins.
        self._exclude(pid, sp.TargetType.DOMAIN.value, "example.com")
        self._include(pid, sp.TargetType.DOMAIN.value, "example.com")
        decision = sp.evaluate_target(pid, "example.com")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, sp.Reason.TARGET_EXCLUDED.value)

    def test_url_include_respects_path_prefix(self):
        pid = self._active_program()
        self._active_authorization(pid)
        self._include(pid, sp.TargetType.URL.value, "https://example.com/api")
        allowed = sp.evaluate_target(pid, "https://example.com/api/v1/users")
        denied = sp.evaluate_target(pid, "https://example.com/apix")
        self.assertTrue(allowed.allowed)
        self.assertFalse(denied.allowed)

    def test_cidr_include_matches_nested_ip_and_network(self):
        pid = self._active_program()
        self._active_authorization(pid)
        self._include(pid, sp.TargetType.CIDR.value, "10.0.0.0/16")
        ip_decision = sp.evaluate_target(pid, "10.0.5.5")
        cidr_decision = sp.evaluate_target(pid, "10.0.5.0/24")
        outside_decision = sp.evaluate_target(pid, "10.1.5.5")
        self.assertTrue(ip_decision.allowed)
        self.assertTrue(cidr_decision.allowed)
        self.assertFalse(outside_decision.allowed)

    def test_multiple_authorizations_one_valid_allows(self):
        """An expired/revoked authorization sitting alongside a valid
        one must not block the valid one from producing ALLOW."""
        pid = self._active_program()
        now = int(time.time())
        self._active_authorization(pid, expires_at=now - 100)  # expired
        self._active_authorization(pid)  # valid
        self._include(pid, sp.TargetType.DOMAIN.value, "example.com")
        decision = sp.evaluate_target(pid, "example.com", current_time=now)
        self.assertTrue(decision.allowed)

    # ---- Migration idempotency ----

    def test_repeated_db_init_is_idempotent_and_preserves_data(self):
        pid = self._active_program()
        self._active_authorization(pid)
        self._include(pid, sp.TargetType.DOMAIN.value, "example.com")
        sp.scope_policy_db_init()
        sp.scope_policy_db_init()
        self.assertIsNotNone(sp.get_program(pid))
        self.assertEqual(len(sp.list_scope_rules(pid)), 1)
        decision = sp.evaluate_target(pid, "example.com")
        self.assertTrue(decision.allowed)


if __name__ == "__main__":
    unittest.main()
