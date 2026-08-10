#!/usr/bin/env python3
import unittest

from rollback_protocol import Anchor, Gate, Head, Reject, Store


H1 = Head(1, "1" * 64)
H2A = Head(2, "a" * 64)
H2B = Head(2, "b" * 64)
H3 = Head(3, "3" * 64)


class RollbackProtocolTests(unittest.TestCase):
    def gate(self):
        return Gate([Store(H1), Store(H1)], Anchor(H1))

    def test_whole_checkpoint_quorum_rollback_is_denied(self):
        gate = self.gate()
        gate.commit(H1, H2A)
        gate.stores[:] = [Store(H1), Store(H1)]
        with self.assertRaisesRegex(Reject, "split or rollback"):
            gate.current()
        with self.assertRaises(Reject):
            gate.commit(H1, H2B)

    def test_anchor_first_crash_is_fail_closed_and_recoverable(self):
        gate = self.gate()
        with self.assertRaises(RuntimeError):
            gate.commit(H1, H2A, crash_after_anchor=True)
        with self.assertRaises(Reject):
            gate.current()
        self.assertEqual(H2A, gate.recover())

    def test_partial_checkpoint_fanout_is_fail_closed_and_recoverable(self):
        gate = self.gate()
        with self.assertRaises(RuntimeError):
            gate.commit(H1, H2A, crash_after_store=0)
        with self.assertRaises(Reject):
            gate.current()
        self.assertEqual(H2A, gate.recover())

    def test_concurrent_sibling_cannot_commit_after_anchor_cas(self):
        gate = self.gate()
        gate.commit(H1, H2A)
        with self.assertRaises(Reject):
            gate.commit(H1, H2B)

    def test_conflicting_equal_size_store_never_repaired_over(self):
        gate = self.gate()
        gate.commit(H1, H2A)
        gate.stores[0].head = H2B
        with self.assertRaisesRegex(Reject, "conflicting"):
            gate.recover()

    def test_monotonic_successor_after_recovery(self):
        gate = self.gate()
        gate.commit(H1, H2A)
        gate.stores[0] = Store(H1)
        self.assertEqual(H2A, gate.recover())
        gate.commit(H2A, H3)
        self.assertEqual(H3, gate.current())


if __name__ == "__main__":
    unittest.main(verbosity=2)

