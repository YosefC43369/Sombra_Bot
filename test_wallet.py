"""
test_wallet.py — Test suite for wallet.py (Wallet / Payment / Transaction
Ledger), plus its one deliberate cross-module integration point with
debt_ledger.py (pay_debt_with_wallet).

Same isolation pattern as test_findings.py / test_scope_policy.py: every
test gets a fresh, isolated SQLite file (tempfile) via monkeypatching
each module's own `DB_PATH` name (every data-layer module here does
`from security import DB_PATH`, which copies the name into its own
module namespace at import time -- reassigning `security.DB_PATH`
alone would NOT redirect wallet.py/debt_ledger.py's own already-bound
`DB_PATH`, so all three must be set explicitly, same as
test_findings.py already does for security/scope_policy/findings).

Exercises wallet.py through its real public API only (get_wallet,
request_deposit/confirm_deposit/reject_deposit, request_withdrawal/
approve_withdrawal/reject_withdrawal/cancel_withdrawal, transfer,
create_payment_request/pay_payment_request/cancel_payment_request,
pay_debt_with_wallet, admin_adjust, list_transactions/
list_all_transactions_admin) -- never pokes at internal tables directly,
matching the rest of this repo's test conventions.
"""

import os
import time
import tempfile
import threading
import unittest
from decimal import Decimal

import security
import debt_ledger as dl
import wallet as wt


class WalletTestCase(unittest.TestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db_path = path
        security.DB_PATH = path
        dl.DB_PATH = path
        wt.DB_PATH = path
        security.security_db_init()
        dl.debt_ledger_db_init()
        wt.wallet_db_init()

    def tearDown(self):
        try:
            os.remove(self._db_path)
        except OSError:
            pass

    # ---- fixture helpers ----

    CHAT = 1

    def _fund(self, user_id: int, baht: int) -> None:
        """Test-only convenience: get a user's balance up to `baht` via a
        real request_deposit()+confirm_deposit() round trip (never pokes
        the wallets table directly) so every fixture still exercises the
        real deposit path."""
        satang = baht * 100
        result = wt.request_deposit(self.CHAT, user_id, satang)
        self.assertTrue(result.ok)
        tx_id = result.data["transaction"]["transaction_id"]
        confirmed = wt.confirm_deposit(self.CHAT, tx_id, admin_id=999)
        self.assertTrue(confirmed.ok)

    # ---- Wallet creation / balance ----

    def test_wallet_lazily_created_with_zero_balance(self):
        wallet_row = wt.get_wallet(self.CHAT, user_id=100)
        self.assertEqual(wallet_row["balance_satang"], 0)
        self.assertEqual(wallet_row["chat_id"], self.CHAT)
        self.assertEqual(wallet_row["user_id"], 100)

    def test_balance_reflects_confirmed_deposit(self):
        self._fund(100, baht=50)
        wallet_row = wt.get_wallet(self.CHAT, 100)
        self.assertEqual(wallet_row["balance_satang"], 5000)

    def test_wallets_are_scoped_per_chat(self):
        self._fund(100, baht=50)
        other_chat_wallet = wt.get_wallet(chat_id=2, user_id=100)
        self.assertEqual(other_chat_wallet["balance_satang"], 0)

    # ---- Deposit ----

    def test_deposit_request_does_not_credit_until_confirmed(self):
        result = wt.request_deposit(self.CHAT, 100, 5000)
        self.assertTrue(result.ok)
        self.assertEqual(result.data["transaction"]["status"], wt.TxStatus.PENDING.value)
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 0)

    def test_deposit_confirm_credits_balance(self):
        result = wt.request_deposit(self.CHAT, 100, 5000)
        tx_id = result.data["transaction"]["transaction_id"]
        confirmed = wt.confirm_deposit(self.CHAT, tx_id, admin_id=999)
        self.assertTrue(confirmed.ok)
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 5000)

    def test_deposit_confirm_twice_is_rejected(self):
        result = wt.request_deposit(self.CHAT, 100, 5000)
        tx_id = result.data["transaction"]["transaction_id"]
        wt.confirm_deposit(self.CHAT, tx_id, admin_id=999)
        second = wt.confirm_deposit(self.CHAT, tx_id, admin_id=999)
        self.assertFalse(second.ok)
        self.assertEqual(second.reason, "ALREADY_PROCESSED")
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 5000)

    def test_deposit_reject_never_credits(self):
        result = wt.request_deposit(self.CHAT, 100, 5000)
        tx_id = result.data["transaction"]["transaction_id"]
        rejected = wt.reject_deposit(self.CHAT, tx_id, admin_id=999, reason="ยังไม่เห็นเงินเข้า")
        self.assertTrue(rejected.ok)
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 0)

    def test_deposit_invalid_amount_rejected(self):
        for bad in (0, -100, None):
            result = wt.request_deposit(self.CHAT, 100, bad)
            self.assertFalse(result.ok)
            self.assertEqual(result.reason, "INVALID_AMOUNT")

    def test_parse_amount_rejects_garbage_and_absurd_input(self):
        self.assertIsNone(wt.parse_amount_to_satang(None))
        self.assertIsNone(wt.parse_amount_to_satang(""))
        self.assertIsNone(wt.parse_amount_to_satang("abc"))
        self.assertIsNone(wt.parse_amount_to_satang("0"))
        self.assertIsNone(wt.parse_amount_to_satang("-50"))
        self.assertIsNone(wt.parse_amount_to_satang("99999999"))  # > MAX_TX_AMOUNT
        self.assertEqual(wt.parse_amount_to_satang("1,234.50"), 123450)

    # ---- Withdrawal ----

    def test_withdrawal_request_holds_funds_immediately(self):
        self._fund(100, baht=100)
        result = wt.request_withdrawal(self.CHAT, 100, 3000)
        self.assertTrue(result.ok)
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 7000)

    def test_withdrawal_insufficient_balance_leaves_balance_unchanged(self):
        self._fund(100, baht=10)
        result = wt.request_withdrawal(self.CHAT, 100, 5000)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INSUFFICIENT_BALANCE")
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 1000)

    def test_withdrawal_approve_finalizes_without_changing_balance_again(self):
        self._fund(100, baht=100)
        req = wt.request_withdrawal(self.CHAT, 100, 3000)
        approved = wt.approve_withdrawal(self.CHAT, req.data["request_id"], admin_id=999)
        self.assertTrue(approved.ok)
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 7000)

    def test_withdrawal_reject_refunds_the_hold(self):
        self._fund(100, baht=100)
        req = wt.request_withdrawal(self.CHAT, 100, 3000)
        rejected = wt.reject_withdrawal(self.CHAT, req.data["request_id"], admin_id=999,
                                         reason="ข้อมูลบัญชีไม่ถูกต้อง")
        self.assertTrue(rejected.ok)
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 10000)

    def test_withdrawal_self_cancel_refunds_the_hold(self):
        self._fund(100, baht=100)
        req = wt.request_withdrawal(self.CHAT, 100, 3000)
        cancelled = wt.cancel_withdrawal(self.CHAT, req.data["request_id"], user_id=100)
        self.assertTrue(cancelled.ok)
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 10000)

    def test_withdrawal_cancel_by_someone_else_is_forbidden(self):
        self._fund(100, baht=100)
        req = wt.request_withdrawal(self.CHAT, 100, 3000)
        result = wt.cancel_withdrawal(self.CHAT, req.data["request_id"], user_id=200)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "FORBIDDEN")
        # hold must still be in place -- a stranger's rejected cancel must
        # not accidentally refund the original owner's held funds either
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 7000)

    # ---- Transfer ----

    def test_transfer_moves_money_atomically(self):
        self._fund(100, baht=100)
        result = wt.transfer(self.CHAT, sender_id=100, recipient_id=200, amount_satang=2500)
        self.assertTrue(result.ok)
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 7500)
        self.assertEqual(wt.get_wallet(self.CHAT, 200)["balance_satang"], 2500)

    def test_transfer_insufficient_balance_moves_nothing(self):
        self._fund(100, baht=10)
        result = wt.transfer(self.CHAT, sender_id=100, recipient_id=200, amount_satang=5000)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INSUFFICIENT_BALANCE")
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 1000)
        self.assertEqual(wt.get_wallet(self.CHAT, 200)["balance_satang"], 0)

    def test_self_transfer_not_allowed(self):
        self._fund(100, baht=100)
        result = wt.transfer(self.CHAT, sender_id=100, recipient_id=100, amount_satang=1000)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "SELF_TRANSFER_NOT_ALLOWED")

    def test_duplicate_transfer_with_same_idempotency_key_applies_once(self):
        self._fund(100, baht=100)
        r1 = wt.transfer(self.CHAT, 100, 200, 2000, idempotency_key="upd-42")
        r2 = wt.transfer(self.CHAT, 100, 200, 2000, idempotency_key="upd-42")
        self.assertTrue(r1.ok)
        self.assertTrue(r2.ok)
        self.assertTrue(r2.data.get("already_processed"))
        # money must have moved exactly once, not twice
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 8000)
        self.assertEqual(wt.get_wallet(self.CHAT, 200)["balance_satang"], 2000)

    def test_concurrent_transfers_never_overdraw_the_sender(self):
        """20 threads each try to transfer 10 บาท out of a wallet funded
        with only 100 บาท. At most 10 can succeed; the ones that don't
        must fail cleanly (INSUFFICIENT_BALANCE) rather than raced into
        a negative balance -- this is what BEGIN IMMEDIATE + the
        conditional `WHERE balance_satang >= ?` UPDATE in wallet.py's
        _debit() are specifically for."""
        self._fund(100, baht=100)
        results = []
        lock = threading.Lock()

        def attempt(i):
            r = wt.transfer(self.CHAT, 100, 900 + i, amount_satang=1000)
            with lock:
                results.append(r)

        threads = [threading.Thread(target=attempt, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        succeeded = [r for r in results if r.ok]
        failed = [r for r in results if not r.ok]
        self.assertEqual(len(succeeded), 10)
        self.assertEqual(len(failed), 10)
        self.assertTrue(all(r.reason == "INSUFFICIENT_BALANCE" for r in failed))
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 0)
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"],
                          wt.recompute_balance(self.CHAT, 100))

    # ---- Payment requests ("bills") ----

    def test_open_payment_request_can_be_paid_by_anyone(self):
        self._fund(200, baht=100)
        created = wt.create_payment_request(self.CHAT, requested_by=100, amount_satang=2000,
                                             description="ค่าข้าวเที่ยง")
        self.assertTrue(created.ok)
        paid = wt.pay_payment_request(self.CHAT, created.data["payment_id"], payer_user_id=200)
        self.assertTrue(paid.ok)
        self.assertEqual(wt.get_wallet(self.CHAT, 200)["balance_satang"], 8000)
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 2000)

    def test_targeted_payment_request_rejects_wrong_payer(self):
        self._fund(200, baht=100)
        self._fund(300, baht=100)
        created = wt.create_payment_request(self.CHAT, requested_by=100, amount_satang=2000,
                                             payer_user_id=200)
        result = wt.pay_payment_request(self.CHAT, created.data["payment_id"], payer_user_id=300)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "FORBIDDEN")

    def test_self_payment_request_not_allowed(self):
        result = wt.create_payment_request(self.CHAT, requested_by=100, amount_satang=2000,
                                            payer_user_id=100)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "SELF_PAYMENT_NOT_ALLOWED")

    def test_duplicate_bill_payment_with_same_idempotency_key_applies_once(self):
        self._fund(200, baht=100)
        created = wt.create_payment_request(self.CHAT, requested_by=100, amount_satang=2000)
        pid = created.data["payment_id"]
        r1 = wt.pay_payment_request(self.CHAT, pid, payer_user_id=200, idempotency_key="upd-7")
        r2 = wt.pay_payment_request(self.CHAT, pid, payer_user_id=200, idempotency_key="upd-7")
        self.assertTrue(r1.ok)
        self.assertTrue(r2.ok)
        self.assertEqual(wt.get_wallet(self.CHAT, 200)["balance_satang"], 8000)

    def test_bill_cancel_by_non_owner_non_admin_is_forbidden(self):
        created = wt.create_payment_request(self.CHAT, requested_by=100, amount_satang=2000)
        result = wt.cancel_payment_request(self.CHAT, created.data["payment_id"], actor_id=999,
                                            is_admin_actor=False)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "FORBIDDEN")

    def test_bill_cancel_by_admin_succeeds_even_if_not_owner(self):
        created = wt.create_payment_request(self.CHAT, requested_by=100, amount_satang=2000)
        result = wt.cancel_payment_request(self.CHAT, created.data["payment_id"], actor_id=999,
                                            is_admin_actor=True)
        self.assertTrue(result.ok)

    def test_cannot_pay_a_cancelled_bill(self):
        self._fund(200, baht=100)
        created = wt.create_payment_request(self.CHAT, requested_by=100, amount_satang=2000)
        wt.cancel_payment_request(self.CHAT, created.data["payment_id"], actor_id=100)
        result = wt.pay_payment_request(self.CHAT, created.data["payment_id"], payer_user_id=200)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "ALREADY_PROCESSED")

    # ---- Admin manual adjustment ----

    def test_admin_credit_adjustment(self):
        result = wt.admin_adjust(self.CHAT, target_user_id=100, delta_satang=5000,
                                  admin_id=999, reason="ชดเชยระบบล่ม")
        self.assertTrue(result.ok)
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 5000)

    def test_admin_debit_adjustment_insufficient_balance(self):
        self._fund(100, baht=10)
        result = wt.admin_adjust(self.CHAT, target_user_id=100, delta_satang=-5000,
                                  admin_id=999, reason="แก้ไขยอดผิดพลาด")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INSUFFICIENT_BALANCE")
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 1000)

    def test_admin_adjustment_requires_a_reason(self):
        result = wt.admin_adjust(self.CHAT, target_user_id=100, delta_satang=1000,
                                  admin_id=999, reason="   ")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "REASON_REQUIRED")

    def test_admin_adjustment_rejects_zero_amount(self):
        result = wt.admin_adjust(self.CHAT, target_user_id=100, delta_satang=0,
                                  admin_id=999, reason="เหตุผล")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INVALID_AMOUNT")

    # ---- Transaction history ----

    def test_history_is_paginated_newest_first(self):
        self._fund(100, baht=100)
        for i in range(3):
            wt.transfer(self.CHAT, 100, 200, 100, idempotency_key=f"h-{i}")
        page = wt.list_transactions(self.CHAT, 100, page=1, page_size=2)
        self.assertEqual(page["total_count"], 4)  # 1 deposit + 3 transfer_out
        self.assertEqual(len(page["items"]), 2)
        self.assertGreater(page["items"][0]["transaction_id"], page["items"][1]["transaction_id"])

    def test_admin_can_list_all_transactions_filtered_by_user(self):
        self._fund(100, baht=50)
        self._fund(200, baht=50)
        page = wt.list_all_transactions_admin(self.CHAT, user_id=100)
        self.assertEqual(page["total_count"], 1)
        self.assertEqual(page["items"][0]["user_id"], 100)

    # ---- Debt-ledger integration (pay_debt_with_wallet) ----

    def _debt_entry(self, name="สมชาย", baht=80):
        result = dl.add_entry(self.CHAT, name, baht * 100, recorded_by=999,
                               item_description="ข้าวกล่อง")
        self.assertTrue(result.ok)
        return result.entry_id

    def test_debt_payment_debits_wallet_and_marks_entry_paid_atomically(self):
        self._fund(100, baht=100)
        entry_id = self._debt_entry(baht=80)
        result = wt.pay_debt_with_wallet(self.CHAT, entry_id, payer_user_id=100)
        self.assertTrue(result.ok)
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 2000)
        entry = dl.get_entry(entry_id)
        self.assertEqual(entry["status"], dl.EntryStatus.PAID.value)
        self.assertEqual(entry["paid_by"], 100)

    def test_debt_payment_insufficient_balance_leaves_entry_unpaid(self):
        self._fund(100, baht=10)
        entry_id = self._debt_entry(baht=80)
        result = wt.pay_debt_with_wallet(self.CHAT, entry_id, payer_user_id=100)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INSUFFICIENT_BALANCE")
        entry = dl.get_entry(entry_id)
        self.assertEqual(entry["status"], dl.EntryStatus.UNPAID.value)
        # the (failed) attempted debit must have been rolled back, not partially applied
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 1000)

    def test_cannot_pay_an_already_paid_debt_entry_via_wallet(self):
        self._fund(100, baht=100)
        entry_id = self._debt_entry(baht=80)
        dl.mark_entry_paid(entry_id, actor_user_id=999)
        result = wt.pay_debt_with_wallet(self.CHAT, entry_id, payer_user_id=100)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "ALREADY_PAID")
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 10000)

    def test_debt_payment_for_unknown_entry_is_rejected(self):
        self._fund(100, baht=100)
        result = wt.pay_debt_with_wallet(self.CHAT, entry_id=999999, payer_user_id=100)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "ENTRY_NOT_FOUND")

    def test_duplicate_debt_payment_with_same_idempotency_key_applies_once(self):
        self._fund(100, baht=100)
        entry_id = self._debt_entry(baht=80)
        r1 = wt.pay_debt_with_wallet(self.CHAT, entry_id, payer_user_id=100,
                                      idempotency_key="upd-99")
        r2 = wt.pay_debt_with_wallet(self.CHAT, entry_id, payer_user_id=100,
                                      idempotency_key="upd-99")
        self.assertTrue(r1.ok)
        self.assertTrue(r2.ok)
        self.assertEqual(wt.get_wallet(self.CHAT, 100)["balance_satang"], 2000)

    def test_concurrent_debt_payment_attempts_only_one_wins(self):
        """Two chat members race to pay off the same debt entry at the
        same time -- only one wallet should ever be debited, and the
        entry must end up paid exactly once (Requirement #8's atomicity,
        under real concurrency rather than just sequential calls)."""
        self._fund(100, baht=100)
        self._fund(200, baht=100)
        entry_id = self._debt_entry(baht=80)
        results = []
        lock = threading.Lock()

        def attempt(payer_id):
            r = wt.pay_debt_with_wallet(self.CHAT, entry_id, payer_user_id=payer_id)
            with lock:
                results.append((payer_id, r))

        threads = [threading.Thread(target=attempt, args=(uid,)) for uid in (100, 200)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        succeeded = [(uid, r) for uid, r in results if r.ok]
        self.assertEqual(len(succeeded), 1)
        winner_id = succeeded[0][0]
        loser_id = 200 if winner_id == 100 else 100
        self.assertEqual(wt.get_wallet(self.CHAT, winner_id)["balance_satang"], 2000)
        self.assertEqual(wt.get_wallet(self.CHAT, loser_id)["balance_satang"], 10000)
        self.assertEqual(dl.get_entry(entry_id)["status"], dl.EntryStatus.PAID.value)


if __name__ == "__main__":
    unittest.main()
