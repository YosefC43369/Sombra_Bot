"""
test_expense.py — Test suite for expense.py (Expense Tracker).

Same isolation pattern as test_wallet.py / test_findings.py /
test_scope_policy.py: every test gets a fresh, isolated SQLite file
(tempfile) via monkeypatching each module's own `DB_PATH` (each
data-layer module does `from security import DB_PATH`, binding the name
into its own namespace at import time, so reassigning security.DB_PATH
alone would not redirect them).

Covers the paths the spec calls out: add, invalid/negative/zero amount,
invalid category, ownership on read/edit/delete, listing, category
filtering, date filtering (today/week/month/custom), edit, delete
(incl. soft-delete semantics), summaries, empty results, and DB-failure
handling. Also pins the two integration invariants that matter most:
recording an expense must NOT move a wallet balance and must NOT settle
a debt entry.
"""

import os
import sqlite3
import tempfile
import unittest
from datetime import date, timedelta
from unittest import mock

import security
import debt_ledger as dl
import wallet as wt
import expense as ex
import expense_report as exr


class ExpenseTestCase(unittest.TestCase):
    CHAT = 1
    ALICE = 100
    BOB = 200

    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db_path = path
        security.DB_PATH = path
        dl.DB_PATH = path
        wt.DB_PATH = path
        ex.DB_PATH = path
        security.security_db_init()
        dl.debt_ledger_db_init()
        wt.wallet_db_init()
        ex.expense_db_init()

    def tearDown(self):
        try:
            os.remove(self._db_path)
        except OSError:
            pass

    def _add(self, user_id=None, baht=100, category="food", description="",
             expense_date=None):
        result = ex.add_expense(
            self.CHAT, self.ALICE if user_id is None else user_id,
            baht * 100, category, description, expense_date=expense_date,
        )
        self.assertTrue(result.ok, msg=result.reason)
        return result.data["expense_id"]

    # ---- Add ----

    def test_add_expense_stores_all_required_fields(self):
        expense_id = self._add(baht=150, category="food", description="ข้าวมันไก่")
        row = ex.get_expense(self.CHAT, expense_id, user_id=self.ALICE)
        self.assertEqual(row["amount_satang"], 15000)
        self.assertEqual(row["category"], "food")
        self.assertEqual(row["description"], "ข้าวมันไก่")
        self.assertEqual(row["user_id"], self.ALICE)
        self.assertEqual(row["expense_date"], ex.today_bangkok_date())
        self.assertIsNotNone(row["created_at"])
        self.assertIsNotNone(row["updated_at"])
        self.assertIsNone(row["deleted_at"])

    def test_add_expense_without_description(self):
        expense_id = self._add(baht=50, category="transport")
        row = ex.get_expense(self.CHAT, expense_id, user_id=self.ALICE)
        self.assertIsNone(row["description"])

    def test_amounts_are_integer_satang_never_float(self):
        expense_id = self._add(baht=1, category="food")
        row = ex.get_expense(self.CHAT, expense_id, user_id=self.ALICE)
        self.assertIsInstance(row["amount_satang"], int)
        self.assertEqual(row["amount_satang"], 100)

    def test_add_rejects_zero_negative_and_non_integer_amounts(self):
        for bad in (0, -1, -5000, None, 12.5, "500", True):
            result = ex.add_expense(self.CHAT, self.ALICE, bad, "food")
            self.assertFalse(result.ok, msg=f"{bad!r} should be rejected")
            self.assertEqual(result.reason, "INVALID_AMOUNT")

    def test_add_rejects_amount_over_cap(self):
        too_big = int(ex.MAX_EXPENSE_AMOUNT * 100) + 1
        result = ex.add_expense(self.CHAT, self.ALICE, too_big, "food")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INVALID_AMOUNT")

    def test_add_rejects_unknown_category(self):
        result = ex.add_expense(self.CHAT, self.ALICE, 10000, "cryptocurrency")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INVALID_CATEGORY")

    def test_add_rejects_overlong_description(self):
        result = ex.add_expense(self.CHAT, self.ALICE, 10000, "food",
                                "x" * (ex.MAX_DESCRIPTION_LEN + 1))
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "DESCRIPTION_TOO_LONG")

    def test_add_rejects_malformed_date(self):
        for bad in ("2026-13-01", "2026-02-31", "01/01/2026", "tomorrow"):
            result = ex.add_expense(self.CHAT, self.ALICE, 10000, "food",
                                    expense_date=bad)
            self.assertFalse(result.ok, msg=f"{bad!r} should be rejected")
            self.assertEqual(result.reason, "INVALID_DATE")

    # ---- Amount parsing ----

    def test_parse_amount_handles_valid_and_rejects_invalid(self):
        self.assertEqual(ex.parse_amount_to_satang("150"), 15000)
        self.assertEqual(ex.parse_amount_to_satang("1,234.50"), 123450)
        self.assertEqual(ex.parse_amount_to_satang("0.01"), 1)
        for bad in (None, "", "   ", "abc", "0", "-50", "NaN", "Infinity",
                    "99999999", "1" * 40):
            self.assertIsNone(ex.parse_amount_to_satang(bad), msg=f"{bad!r}")

    # ---- Categories ----

    def test_category_normalization_accepts_english_thai_and_case(self):
        self.assertEqual(ex.normalize_category("Food"), "food")
        self.assertEqual(ex.normalize_category("FOOD"), "food")
        self.assertEqual(ex.normalize_category("อาหาร"), "food")
        self.assertEqual(ex.normalize_category("  transport  "), "transport")
        self.assertEqual(ex.normalize_category("เดินทาง"), "transport")
        self.assertEqual(ex.normalize_category("ค่ารถ"), "transport")

    def test_category_normalization_rejects_unknown(self):
        for bad in (None, "", "   ", "nonsense", "ค่าอะไรก็ไม่รู้"):
            self.assertIsNone(ex.normalize_category(bad), msg=f"{bad!r}")

    def test_every_category_has_a_renderable_label(self):
        for key in ex.VALID_CATEGORIES:
            label = ex.category_label(key)
            self.assertTrue(label)
            self.assertNotEqual(label, key)  # emoji + Thai, not the bare key

    # ---- Ownership ----

    def test_get_expense_hides_another_users_row(self):
        expense_id = self._add(user_id=self.BOB, baht=100)
        self.assertIsNone(ex.get_expense(self.CHAT, expense_id, user_id=self.ALICE))
        self.assertIsNotNone(ex.get_expense(self.CHAT, expense_id, user_id=self.BOB))

    def test_list_only_returns_callers_own_rows(self):
        self._add(user_id=self.ALICE, baht=100)
        self._add(user_id=self.BOB, baht=999)
        page = ex.list_expenses(self.CHAT, self.ALICE)
        self.assertEqual(page["total_count"], 1)
        self.assertEqual(page["items"][0]["amount_satang"], 10000)

    def test_expenses_are_scoped_per_chat(self):
        self._add(user_id=self.ALICE, baht=100)
        page = ex.list_expenses(chat_id=2, user_id=self.ALICE)
        self.assertEqual(page["total_count"], 0)

    def test_cannot_edit_another_users_expense(self):
        expense_id = self._add(user_id=self.BOB, baht=100)
        result = ex.update_expense(self.CHAT, expense_id, self.ALICE, amount_satang=1)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "NOT_FOUND")
        row = ex.get_expense(self.CHAT, expense_id, user_id=self.BOB)
        self.assertEqual(row["amount_satang"], 10000)  # untouched

    def test_cannot_delete_another_users_expense(self):
        expense_id = self._add(user_id=self.BOB, baht=100)
        result = ex.delete_expense(self.CHAT, expense_id, self.ALICE)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "NOT_FOUND")
        self.assertIsNotNone(ex.get_expense(self.CHAT, expense_id, user_id=self.BOB))

    def test_admin_may_delete_another_users_expense(self):
        expense_id = self._add(user_id=self.BOB, baht=100)
        result = ex.delete_expense(self.CHAT, expense_id, self.ALICE, is_admin_actor=True)
        self.assertTrue(result.ok)
        self.assertIsNone(ex.get_expense(self.CHAT, expense_id, user_id=self.BOB))

    # ---- Edit ----

    def test_edit_amount_category_description_and_date(self):
        expense_id = self._add(baht=100, category="food", description="เดิม")
        result = ex.update_expense(self.CHAT, expense_id, self.ALICE,
                                   amount_satang=25000, category="shopping",
                                   description="ใหม่", expense_date="2026-01-15")
        self.assertTrue(result.ok)
        row = result.data["expense"]
        self.assertEqual(row["amount_satang"], 25000)
        self.assertEqual(row["category"], "shopping")
        self.assertEqual(row["description"], "ใหม่")
        self.assertEqual(row["expense_date"], "2026-01-15")

    def test_edit_only_changes_the_named_field(self):
        expense_id = self._add(baht=100, category="food", description="คงเดิม")
        ex.update_expense(self.CHAT, expense_id, self.ALICE, amount_satang=5000)
        row = ex.get_expense(self.CHAT, expense_id, user_id=self.ALICE)
        self.assertEqual(row["amount_satang"], 5000)
        self.assertEqual(row["category"], "food")
        self.assertEqual(row["description"], "คงเดิม")

    def test_edit_with_no_fields_is_rejected(self):
        expense_id = self._add()
        result = ex.update_expense(self.CHAT, expense_id, self.ALICE)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "NO_CHANGES")

    def test_edit_rejects_invalid_values(self):
        expense_id = self._add()
        self.assertEqual(
            ex.update_expense(self.CHAT, expense_id, self.ALICE, amount_satang=0).reason,
            "INVALID_AMOUNT")
        self.assertEqual(
            ex.update_expense(self.CHAT, expense_id, self.ALICE, amount_satang=-5).reason,
            "INVALID_AMOUNT")
        self.assertEqual(
            ex.update_expense(self.CHAT, expense_id, self.ALICE, category="bogus").reason,
            "INVALID_CATEGORY")
        self.assertEqual(
            ex.update_expense(self.CHAT, expense_id, self.ALICE,
                              expense_date="2026-99-99").reason,
            "INVALID_DATE")

    def test_edit_unknown_id_is_not_found(self):
        result = ex.update_expense(self.CHAT, 999999, self.ALICE, amount_satang=100)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "NOT_FOUND")

    # ---- Delete ----

    def test_delete_removes_row_from_all_reads(self):
        expense_id = self._add(baht=100)
        result = ex.delete_expense(self.CHAT, expense_id, self.ALICE)
        self.assertTrue(result.ok)
        self.assertIsNone(ex.get_expense(self.CHAT, expense_id, user_id=self.ALICE))
        self.assertEqual(ex.list_expenses(self.CHAT, self.ALICE)["total_count"], 0)
        summary = ex.summarize_by_category(self.CHAT, self.ALICE)
        self.assertEqual(summary["grand_total_satang"], 0)

    def test_delete_is_soft_row_survives_for_audit(self):
        expense_id = self._add(baht=100)
        ex.delete_expense(self.CHAT, expense_id, self.ALICE)
        conn = sqlite3.connect(self._db_path)
        row = conn.execute(
            "SELECT deleted_at FROM expenses WHERE expense_id=?", (expense_id,)
        ).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertIsNotNone(row[0])

    def test_delete_twice_is_rejected(self):
        expense_id = self._add()
        ex.delete_expense(self.CHAT, expense_id, self.ALICE)
        second = ex.delete_expense(self.CHAT, expense_id, self.ALICE)
        self.assertFalse(second.ok)
        self.assertEqual(second.reason, "NOT_FOUND")

    def test_cannot_edit_a_deleted_expense(self):
        expense_id = self._add()
        ex.delete_expense(self.CHAT, expense_id, self.ALICE)
        result = ex.update_expense(self.CHAT, expense_id, self.ALICE, amount_satang=100)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "NOT_FOUND")

    def test_delete_unknown_id_is_not_found(self):
        result = ex.delete_expense(self.CHAT, 999999, self.ALICE)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "NOT_FOUND")

    # ---- Listing / pagination ----

    def test_list_is_paginated_newest_first(self):
        today = ex.today_bangkok_date()
        for i in range(5):
            self._add(baht=10 + i, expense_date=today)
        page = ex.list_expenses(self.CHAT, self.ALICE, page=1, page_size=2)
        self.assertEqual(page["total_count"], 5)
        self.assertEqual(page["total_pages"], 3)
        self.assertEqual(len(page["items"]), 2)
        self.assertGreater(page["items"][0]["expense_id"], page["items"][1]["expense_id"])

    def test_list_reports_range_total(self):
        self._add(baht=100)
        self._add(baht=50)
        page = ex.list_expenses(self.CHAT, self.ALICE)
        self.assertEqual(page["total_satang"], 15000)

    def test_list_empty_results(self):
        page = ex.list_expenses(self.CHAT, self.ALICE)
        self.assertEqual(page["total_count"], 0)
        self.assertEqual(page["items"], [])
        self.assertEqual(page["total_satang"], 0)
        self.assertEqual(page["total_pages"], 1)

    # ---- Category filtering ----

    def test_list_filtered_by_category(self):
        self._add(baht=100, category="food")
        self._add(baht=50, category="transport")
        self._add(baht=25, category="food")
        page = ex.list_expenses(self.CHAT, self.ALICE, category="food")
        self.assertEqual(page["total_count"], 2)
        self.assertEqual(page["total_satang"], 12500)

    # ---- Date filtering ----

    def test_list_filtered_by_date_range(self):
        self._add(baht=100, expense_date="2026-01-10")
        self._add(baht=200, expense_date="2026-02-10")
        self._add(baht=300, expense_date="2026-03-10")
        page = ex.list_expenses(self.CHAT, self.ALICE,
                                date_from="2026-02-01", date_to="2026-02-28")
        self.assertEqual(page["total_count"], 1)
        self.assertEqual(page["total_satang"], 20000)

    def test_parse_period_keywords(self):
        today = ex.today_bangkok_date()
        p = ex.parse_period(["today"])
        self.assertEqual((p["date_from"], p["date_to"]), (today, today))

        p = ex.parse_period(["week"])
        start, end = ex.current_week_range()
        self.assertEqual((p["date_from"], p["date_to"]), (start, end))

        p = ex.parse_period(["month"])
        start, end = ex.current_month_range()
        self.assertEqual((p["date_from"], p["date_to"]), (start, end))

    def test_parse_period_defaults_to_this_month(self):
        p = ex.parse_period([])
        start, end = ex.current_month_range()
        self.assertEqual((p["date_from"], p["date_to"]), (start, end))

    def test_parse_period_explicit_month_day_and_custom_range(self):
        p = ex.parse_period(["2026-02"])
        self.assertEqual((p["date_from"], p["date_to"]), ("2026-02-01", "2026-02-28"))

        p = ex.parse_period(["2026-02-14"])
        self.assertEqual((p["date_from"], p["date_to"]), ("2026-02-14", "2026-02-14"))

        p = ex.parse_period(["2026-01-01", "2026-03-31"])
        self.assertEqual((p["date_from"], p["date_to"]), ("2026-01-01", "2026-03-31"))

    def test_parse_period_rejects_invalid_input(self):
        for bad in (["yesterday"], ["2026-13"], ["2026-02-31"], ["01/02/2026"],
                    ["2026-03-31", "2026-01-01"], ["a", "b", "c"], ["2026-01-01", "junk"]):
            self.assertIsNone(ex.parse_period(bad), msg=f"{bad!r}")

    def test_week_range_is_monday_to_sunday(self):
        wednesday = date(2026, 2, 11)
        start, end = ex.current_week_range(today=wednesday)
        self.assertEqual(start, "2026-02-09")  # Monday
        self.assertEqual(end, "2026-02-15")    # Sunday
        self.assertEqual(date.fromisoformat(start).weekday(), 0)
        self.assertEqual(date.fromisoformat(end) - date.fromisoformat(start),
                         timedelta(days=6))

    # ---- Summaries ----

    def test_summary_groups_by_category_biggest_first(self):
        self._add(baht=100, category="food")
        self._add(baht=150, category="food")
        self._add(baht=500, category="shopping")
        self._add(baht=20, category="transport")
        summary = ex.summarize_by_category(self.CHAT, self.ALICE)
        self.assertEqual([c["category"] for c in summary["by_category"]],
                         ["shopping", "food", "transport"])
        self.assertEqual(summary["grand_total_satang"], 77000)
        self.assertEqual(summary["grand_total_count"], 4)
        food = next(c for c in summary["by_category"] if c["category"] == "food")
        self.assertEqual(food["total_satang"], 25000)
        self.assertEqual(food["count"], 2)

    def test_summary_respects_date_range(self):
        self._add(baht=100, expense_date="2026-01-10")
        self._add(baht=200, expense_date="2026-02-10")
        summary = ex.summarize_by_category(self.CHAT, self.ALICE,
                                           date_from="2026-02-01", date_to="2026-02-28")
        self.assertEqual(summary["grand_total_satang"], 20000)

    def test_summary_excludes_other_users(self):
        self._add(user_id=self.ALICE, baht=100)
        self._add(user_id=self.BOB, baht=900)
        summary = ex.summarize_by_category(self.CHAT, self.ALICE)
        self.assertEqual(summary["grand_total_satang"], 10000)

    def test_summary_empty_results(self):
        summary = ex.summarize_by_category(self.CHAT, self.ALICE)
        self.assertEqual(summary["by_category"], [])
        self.assertEqual(summary["grand_total_satang"], 0)
        self.assertEqual(summary["grand_total_count"], 0)

    def test_admin_summary_groups_by_user(self):
        self._add(user_id=self.ALICE, baht=100)
        self._add(user_id=self.BOB, baht=900)
        summary = ex.summarize_all_users_admin(self.CHAT)
        self.assertEqual([u["user_id"] for u in summary["by_user"]],
                         [self.BOB, self.ALICE])
        self.assertEqual(summary["grand_total_satang"], 100000)

    # ---- Integration invariants: expenses must not move money ----

    def test_recording_an_expense_never_changes_the_wallet_balance(self):
        deposit = wt.request_deposit(self.CHAT, self.ALICE, 50000)
        wt.confirm_deposit(self.CHAT, deposit.data["transaction"]["transaction_id"],
                           admin_id=999)
        before = wt.get_wallet(self.CHAT, self.ALICE)["balance_satang"]

        self._add(baht=100, category="food")

        after = wt.get_wallet(self.CHAT, self.ALICE)["balance_satang"]
        self.assertEqual(before, after)
        self.assertEqual(after, 50000)

    def test_recording_an_expense_creates_no_wallet_transaction(self):
        before = wt.list_transactions(self.CHAT, self.ALICE)["total_count"]
        self._add(baht=100)
        after = wt.list_transactions(self.CHAT, self.ALICE)["total_count"]
        self.assertEqual(before, after)

    def test_recording_an_expense_never_settles_a_debt_entry(self):
        entry_id = dl.add_entry(self.CHAT, "สมชาย", 8000, recorded_by=999).entry_id
        self._add(baht=80, category="food", description="จ่ายแทนสมชาย")
        self.assertEqual(dl.get_entry(entry_id)["status"], dl.EntryStatus.UNPAID.value)

    def test_optional_references_are_stored_without_side_effects(self):
        deposit = wt.request_deposit(self.CHAT, self.ALICE, 50000)
        tx_id = deposit.data["transaction"]["transaction_id"]
        wt.confirm_deposit(self.CHAT, tx_id, admin_id=999)
        entry_id = dl.add_entry(self.CHAT, "สมชาย", 8000, recorded_by=999).entry_id

        result = ex.add_expense(self.CHAT, self.ALICE, 8000, "food",
                                wallet_transaction_id=tx_id, debt_entry_id=entry_id)
        self.assertTrue(result.ok)
        row = ex.get_expense(self.CHAT, result.data["expense_id"], user_id=self.ALICE)
        self.assertEqual(row["wallet_transaction_id"], tx_id)
        self.assertEqual(row["debt_entry_id"], entry_id)
        # ...and neither referenced system was mutated
        self.assertEqual(wt.get_wallet(self.CHAT, self.ALICE)["balance_satang"], 50000)
        self.assertEqual(dl.get_entry(entry_id)["status"], dl.EntryStatus.UNPAID.value)

    # ---- Database failure handling ----

    def test_add_returns_db_error_instead_of_raising(self):
        with mock.patch.object(ex, "_tx", side_effect=sqlite3.OperationalError("boom")):
            result = ex.add_expense(self.CHAT, self.ALICE, 10000, "food")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "DB_ERROR")

    def test_update_returns_db_error_instead_of_raising(self):
        expense_id = self._add()
        with mock.patch.object(ex, "_tx", side_effect=sqlite3.OperationalError("boom")):
            result = ex.update_expense(self.CHAT, expense_id, self.ALICE,
                                       amount_satang=100)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "DB_ERROR")

    def test_delete_returns_db_error_instead_of_raising(self):
        expense_id = self._add()
        with mock.patch.object(ex, "_tx", side_effect=sqlite3.OperationalError("boom")):
            result = ex.delete_expense(self.CHAT, expense_id, self.ALICE)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "DB_ERROR")

    # ---- Formatting layer (must never raise on real data) ----

    def test_report_formatters_render_without_error(self):
        self._add(baht=250, category="food", description="ข้าว")
        self._add(baht=120, category="transport", description="BTS")

        page = ex.list_expenses(self.CHAT, self.ALICE)
        summary = ex.summarize_by_category(self.CHAT, self.ALICE)
        self.assertIn("รายจ่าย", exr.format_expense_list(page))
        self.assertIn("รวมทั้งหมด", exr.format_category_summary(summary, "วันนี้"))

        cat_page = ex.list_expenses(self.CHAT, self.ALICE, category="food")
        row = next(c for c in summary["by_category"] if c["category"] == "food")
        self.assertIn("250", exr.format_single_category_report(cat_page, row, "วันนี้"))

        admin = ex.summarize_all_users_admin(self.CHAT)
        self.assertIn("รวมทั้งหมด", exr.format_admin_summary(admin, "วันนี้"))

    def test_formatters_handle_empty_results(self):
        page = ex.list_expenses(self.CHAT, self.ALICE)
        summary = ex.summarize_by_category(self.CHAT, self.ALICE)
        self.assertIn("ไม่มีรายการ", exr.format_expense_list(page))
        self.assertIn("ไม่มีรายการ", exr.format_category_summary(summary))
        self.assertIn("ไม่มีรายการ", exr.format_admin_summary(
            ex.summarize_all_users_admin(self.CHAT)))

    def test_deny_text_covers_every_reason_the_data_layer_emits(self):
        emitted = {"INVALID_AMOUNT", "INVALID_CATEGORY", "INVALID_DATE",
                   "DESCRIPTION_TOO_LONG", "NOT_FOUND", "NO_CHANGES", "DB_ERROR"}
        for reason in emitted:
            text = exr.deny_text(reason)
            self.assertTrue(text.startswith("❌ "))
            self.assertNotIn(reason, text)  # translated, not echoed raw

    def test_format_baht_matches_wallet_conventions(self):
        self.assertEqual(ex.format_baht(15000), "150 บาท")
        self.assertEqual(ex.format_baht(12345), "123.45 บาท")
        self.assertEqual(ex.format_baht(100000000), "1,000,000 บาท")


if __name__ == "__main__":
    unittest.main()
