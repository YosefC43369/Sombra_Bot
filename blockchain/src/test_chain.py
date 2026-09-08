"""
test_chain.py — Test suite for chain.py (Python <-> Rust ledger bridge) and
chain_report.py (Thai formatting).

Same isolation pattern as test_wallet.py / test_expense.py: each test gets a
fresh SQLite file via tempfile and every module's own `DB_PATH` name is
reassigned (each module does `from security import DB_PATH`, which copies
the name at import time, so `security.DB_PATH` alone would not redirect
them). chain.py binds its own `DB_PATH` too and is patched the same way.

Two layers, deliberately split:

* The degraded-mode and formatting tests need no Rust toolchain and run
  everywhere, including CI that has never seen cargo. They cover the
  property that actually protects production: a missing, broken, slow or
  disabled ledger binary must never raise into a Telegram handler.

* The end-to-end tests build real wallet/debt/expense rows through the
  existing public APIs and then anchor and verify them. They are skipped
  unless the binary has been built (`cd blockchain && cargo build
  --release`), rather than failing a test run that was never about the
  ledger.

Nothing here duplicates test_wallet.py or test_expense.py: no wallet
balance, debt status or expense field is re-asserted, only what the ledger
does with rows those suites already prove correct.
"""

import os
import asyncio
import tempfile
import unittest

import security
import debt_ledger as dl
import wallet as wt
import expense as ex
import chain as cn
import chain_report as cnr


def _run(coro):
    """Each test drives its own loop; python-telegram-bot owns the loop in
    production, so nothing here may assume a running one."""
    return asyncio.run(coro)


BINARY_AVAILABLE = cn.find_binary() is not None
REQUIRES_BINARY = unittest.skipUnless(
    BINARY_AVAILABLE,
    "sombra-chain binary not built (cd blockchain && cargo build --release)",
)


class ChainDegradedModeTestCase(unittest.TestCase):
    """The ledger being absent or broken must be survivable, silently."""

    def setUp(self):
        self._binary_env = cn.CHAIN_BINARY_ENV
        self._enabled = cn.CHAIN_ENABLED
        self._candidates = cn._CANDIDATE_PATHS
        # Point every discovery route at something that cannot exist.
        cn.CHAIN_BINARY_ENV = ""
        cn._CANDIDATE_PATHS = (os.path.join(tempfile.gettempdir(), "sombra-chain-absent"),)

    def tearDown(self):
        cn.CHAIN_BINARY_ENV = self._binary_env
        cn.CHAIN_ENABLED = self._enabled
        cn._CANDIDATE_PATHS = self._candidates

    def test_missing_binary_is_reported_not_raised(self):
        for coro in (
            cn.get_status(),
            cn.verify_chain(),
            cn.reconcile(),
            cn.anchor_now(),
            cn.get_block(1),
            cn.find_transaction("1"),
        ):
            result = _run(coro)
            self.assertFalse(result.ok)
            self.assertEqual(result.reason, "CHAIN_UNAVAILABLE")

    def test_db_init_never_raises_without_a_binary(self):
        result = cn.chain_db_init()
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "CHAIN_UNAVAILABLE")

    def test_disabled_short_circuits_before_touching_the_filesystem(self):
        cn.CHAIN_ENABLED = False
        self.assertEqual(_run(cn.get_status()).reason, "CHAIN_DISABLED")
        self.assertEqual(cn.chain_db_init().reason, "CHAIN_DISABLED")
        self.assertFalse(cn.is_available())

    def test_background_loop_exits_immediately_when_disabled(self):
        cn.CHAIN_ENABLED = False
        _run(cn.chain_background_loop())  # must return, not hang

    def test_garbage_output_is_reported_as_bad_output(self):
        result = cn._decode(b"not json at all", b"", 0)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "CHAIN_BAD_OUTPUT")

    def test_empty_output_is_reported(self):
        result = cn._decode(b"", b"boom", 1)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "CHAIN_NO_OUTPUT")

    def test_error_json_is_surfaced_with_its_code(self):
        result = cn._decode(b'{"ok": false, "error": "DB_ERROR", "detail": "locked"}', b"", 1)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "DB_ERROR")

    def test_success_json_is_passed_through(self):
        result = cn._decode(b'{"ok": true, "anchored": 3, "height": 9}', b"", 0)
        self.assertTrue(result.ok)
        self.assertEqual(result.data["anchored"], 3)


class ChainReportTestCase(unittest.TestCase):
    """Formatting must survive partial payloads: a degraded ledger still
    reaches these functions."""

    def test_every_deny_reason_has_thai_text(self):
        for reason in ("CHAIN_UNAVAILABLE", "CHAIN_TIMEOUT", "CHAIN_DISABLED",
                       "BLOCK_NOT_FOUND", "TRANSACTION_NOT_FOUND", "DB_ERROR"):
            self.assertNotEqual(cnr.deny_text(reason), "❌ " + reason)

    def test_unknown_reason_degrades_to_the_raw_code(self):
        self.assertEqual(cnr.deny_text("WAT"), "❌ WAT")

    def test_satang_formatting_matches_the_wallet_convention(self):
        self.assertEqual(cnr.format_baht(25000), wt.format_baht(25000))
        self.assertEqual(cnr.format_baht(25050), wt.format_baht(25050))
        self.assertEqual(cnr.format_baht(None), "-")

    def test_status_of_an_uninitialized_chain(self):
        self.assertIn("ยังไม่ได้เริ่มต้น", cnr.format_status({"initialized": False}))

    def test_healthy_verify_and_failed_verify_read_differently(self):
        healthy = cnr.format_verify({"ok": True, "blocks_checked": 2,
                                     "transactions_checked": 3, "tip_hash": "a" * 64})
        broken = cnr.format_verify({
            "ok": False, "blocks_checked": 2, "transactions_checked": 3,
            "problem_count": 1,
            "problems": [{"height": 1, "kind": "TAMPERED_TRANSACTION", "detail": ""}],
        })
        self.assertIn("✅", healthy)
        self.assertIn("🚨", broken)
        self.assertIn("ถูกแก้ไข", broken)

    def test_empty_transaction_match_list_is_a_not_found_message(self):
        self.assertEqual(cnr.format_transaction_matches([]),
                         cnr.deny_text("TRANSACTION_NOT_FOUND"))

    def test_anchor_result_distinguishes_work_from_no_work(self):
        self.assertIn("ไม่มีรายการใหม่", cnr.format_anchor_result({"anchored": 0}))
        self.assertIn("#7", cnr.format_anchor_result({"anchored": 4, "height": 7}))

    def test_admin_deduction_and_credit_do_not_read_alike(self):
        """wallet.py stores both as a positive amount_satang; only the two
        balance fields carry the sign, so the ledger view must use them."""
        deduction = {"tx_type": "adjustment", "tx_ref": "wallet_tx:9", "amount_satang": 50000,
                     "source": "wallet_tx", "source_row_id": 9, "block_height": 3,
                     "occurred_at": 1767000000, "payload_hash": "a" * 64,
                     "metadata": {"balance_before_satang": 80000,
                                  "balance_after_satang": 30000, "status": "completed"}}
        credit = dict(deduction, tx_ref="wallet_tx:10")
        credit["metadata"] = {"balance_before_satang": 30000,
                              "balance_after_satang": 80000, "status": "completed"}
        self.assertIn("−", cnr.format_transaction_matches([deduction]))
        self.assertIn("+", cnr.format_transaction_matches([credit]))
        self.assertNotEqual(cnr.format_transaction_matches([deduction]),
                            cnr.format_transaction_matches([credit]))

    def test_cancelled_status_is_shown_on_a_wallet_anchor(self):
        tx = {"tx_type": "withdrawal", "tx_ref": "wallet_tx:4", "amount_satang": 20000,
              "source": "wallet_tx", "source_row_id": 4, "block_height": 2,
              "occurred_at": 1767000000, "payload_hash": "b" * 64,
              "metadata": {"balance_before_satang": 50000,
                           "balance_after_satang": 30000, "status": "cancelled"}}
        self.assertIn("ยกเลิก", cnr.format_transaction_matches([tx]))

    def test_debt_and_expense_anchors_carry_no_direction(self):
        tx = {"tx_type": "debt_signed", "tx_ref": "debt_entry:7:signed", "amount_satang": 25000,
              "source": "debt_entry", "source_row_id": 7, "block_height": 2,
              "occurred_at": 1767000000, "payload_hash": "c" * 64,
              "metadata": {"debtor_name": "สมชาย"}}
        rendered = cnr.format_transaction_matches([tx])
        self.assertNotIn("−", rendered)
        self.assertNotIn("+", rendered)

    def test_formatters_tolerate_missing_keys(self):
        cnr.format_block({})
        cnr.format_block({"block": {"transactions": [{"tx_type": "deposit"}]}})
        cnr.format_reconcile({"ok": True})
        cnr.format_status({"initialized": True})


@REQUIRES_BINARY
class ChainEndToEndTestCase(unittest.TestCase):
    """Real rows through the real Python APIs, then the real Rust binary."""

    CHAT = 1

    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db_path = path
        self._saved = (security.DB_PATH, dl.DB_PATH, wt.DB_PATH, ex.DB_PATH, cn.DB_PATH)
        security.DB_PATH = path
        dl.DB_PATH = path
        wt.DB_PATH = path
        ex.DB_PATH = path
        cn.DB_PATH = path
        security.security_db_init()
        dl.debt_ledger_db_init()
        wt.wallet_db_init()
        ex.expense_db_init()
        cn.chain_db_init()

    def tearDown(self):
        (security.DB_PATH, dl.DB_PATH, wt.DB_PATH, ex.DB_PATH, cn.DB_PATH) = self._saved
        try:
            os.remove(self._db_path)
        except OSError:
            pass

    def _fund(self, user_id, baht):
        result = wt.request_deposit(self.CHAT, user_id, baht * 100)
        self.assertTrue(result.ok)
        confirmed = wt.confirm_deposit(
            self.CHAT, result.data["transaction"]["transaction_id"], admin_id=999
        )
        self.assertTrue(confirmed.ok)

    def test_genesis_exists_after_init(self):
        status = _run(cn.get_status())
        self.assertTrue(status.ok)
        self.assertTrue(status.data["initialized"])
        self.assertEqual(status.data["height"], 0)

    def test_wallet_activity_is_anchored_and_verifies(self):
        self._fund(100, 500)
        transfer = wt.transfer(self.CHAT, 100, 200, 10000)
        self.assertTrue(transfer.ok)

        anchored = _run(cn.anchor_now())
        self.assertTrue(anchored.ok)
        self.assertGreaterEqual(anchored.data["anchored"], 3)

        report = _run(cn.verify_chain())
        self.assertTrue(report.ok)
        self.assertTrue(report.data["ok"], report.data.get("problems"))

    def test_anchoring_is_idempotent(self):
        self._fund(100, 100)
        first = _run(cn.anchor_now())
        self.assertGreater(first.data["anchored"], 0)
        second = _run(cn.anchor_now())
        self.assertEqual(second.data["anchored"], 0)

    def test_paying_a_debt_from_the_wallet_anchors_both_sides(self):
        self._fund(100, 500)
        signed = dl.add_entry(self.CHAT, "สมชาย", 25000, recorded_by=999,
                              item_description="กาแฟ")
        self.assertTrue(signed.ok)
        entry_id = signed.entry_id
        paid = wt.pay_debt_with_wallet(self.CHAT, entry_id, 100)
        self.assertTrue(paid.ok)

        _run(cn.anchor_now())
        found = _run(cn.find_transaction(f"debt_entry:{entry_id}"))
        self.assertTrue(found.ok)
        kinds = {m["tx_type"] for m in found.data["matches"]}
        self.assertIn("debt_signed", kinds)
        self.assertIn("debt_paid", kinds)

    def test_expense_is_anchored_without_touching_the_wallet(self):
        self._fund(100, 500)
        before = wt.get_wallet(self.CHAT, 100)["balance_satang"]
        added = ex.add_expense(self.CHAT, 100, 15000, "food", "ข้าวมันไก่")
        self.assertTrue(added.ok)

        _run(cn.anchor_now())
        after = wt.get_wallet(self.CHAT, 100)["balance_satang"]
        self.assertEqual(before, after, "anchoring an expense must not move a balance")

        found = _run(cn.find_transaction(f"expense:{added.data['expense_id']}"))
        self.assertTrue(found.ok)
        self.assertEqual(found.data["matches"][0]["tx_type"], "expense_added")

    def test_reconcile_is_clean_for_untouched_rows(self):
        self._fund(100, 250)
        _run(cn.anchor_now())
        report = _run(cn.reconcile())
        self.assertTrue(report.data["ok"], report.data.get("problems"))

    def test_pending_wallet_rows_are_not_anchored_until_they_settle(self):
        pending = wt.request_deposit(self.CHAT, 100, 20000)
        self.assertTrue(pending.ok)
        _run(cn.anchor_now())

        tx_id = pending.data["transaction"]["transaction_id"]
        self.assertFalse(_run(cn.find_transaction(f"wallet_tx:{tx_id}")).ok)

        wt.confirm_deposit(self.CHAT, tx_id, admin_id=999)
        _run(cn.anchor_now())
        self.assertTrue(_run(cn.find_transaction(f"wallet_tx:{tx_id}")).ok)

    def test_a_rejected_wallet_operation_leaves_no_ledger_record(self):
        """The consistency property that matters: wallet.py rolls the whole
        transaction back on INSUFFICIENT_BALANCE, so there is no committed row
        for the ledger to anchor and therefore no phantom chain entry."""
        self._fund(100, 10)
        before = _run(cn.get_status()).data["transaction_count"]

        failed = wt.transfer(self.CHAT, 100, 200, 999999999)
        self.assertFalse(failed.ok)
        self.assertEqual(failed.reason, "INSUFFICIENT_BALANCE")

        _run(cn.anchor_now())
        after = _run(cn.get_status()).data["transaction_count"]
        self.assertEqual(before, after, "a rolled-back transfer must not anchor")
        self.assertTrue(_run(cn.verify_chain()).data["ok"])

    def test_ledger_survives_a_restart_and_still_validates(self):
        """Every chain.py call spawns a fresh process that reads the chain off
        disk, so this also covers the bot restarting: nothing is held in
        memory between calls."""
        self._fund(100, 300)
        anchored = _run(cn.anchor_now())
        height = anchored.data["height"]
        count = _run(cn.get_status()).data["transaction_count"]
        self.assertGreater(count, 0)

        # Re-run chain_db_init() exactly as main() does on every boot: it must
        # find the existing chain rather than laying a second genesis over it.
        reinit = cn.chain_db_init()
        self.assertTrue(reinit.ok)
        self.assertFalse(reinit.data["genesis_created"])

        after = _run(cn.get_status())
        self.assertEqual(after.data["height"], height)
        self.assertEqual(after.data["transaction_count"], count)
        self.assertTrue(_run(cn.verify_chain()).data["ok"])

    def test_block_lookup_returns_its_transactions(self):
        self._fund(100, 100)
        anchored = _run(cn.anchor_now())
        block = _run(cn.get_block(anchored.data["height"]))
        self.assertTrue(block.ok)
        self.assertEqual(len(block.data["block"]["transactions"]),
                         block.data["block"]["tx_count"])

    def test_missing_block_and_transaction_are_reported(self):
        self.assertEqual(_run(cn.get_block(9999)).reason, "BLOCK_NOT_FOUND")
        self.assertEqual(_run(cn.find_transaction("wallet_tx:9999")).reason,
                         "TRANSACTION_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()