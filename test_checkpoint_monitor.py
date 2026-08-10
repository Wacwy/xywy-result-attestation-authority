#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

import checkpoint_monitor


class CheckpointMonitorTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pgk-v26-monitor-")
        self.root = Path(self.temp.name) / "monitor"
        self.epoch = "e" * 64
        self.anchor = "a" * 64
        checkpoint_monitor.initialise_for_test(
            self.root, tree_size=1, tree_root_sha256=self.anchor,
            ledger_epoch=self.epoch)

    def tearDown(self): self.temp.cleanup()

    def receipt(self, root: str) -> dict:
        return {"ledger_epoch": self.epoch, "prior_tree_size": 1,
                "prior_tree_root_sha256": self.anchor, "tree_size": 2,
                "tree_root_sha256": root}

    def test_one_successor_advances_state(self):
        receipt = self.receipt("b" * 64)
        out = checkpoint_monitor.advance(
            self.root, receipt, lambda size, root: receipt)
        self.assertEqual(out["tree_root_sha256"], "b" * 64)
        self.assertEqual(checkpoint_monitor.current(self.root), out)

    def test_two_siblings_cannot_both_commit(self):
        barrier = threading.Barrier(2)
        results = []
        lock = threading.Lock()

        def worker(root_char: str):
            receipt = self.receipt(root_char * 64)
            barrier.wait()
            try:
                def verify(size, root):
                    if size != receipt["prior_tree_size"] or root != receipt["prior_tree_root_sha256"]:
                        raise checkpoint_monitor.MonitorReject("stale sibling")
                    return receipt
                checkpoint_monitor.advance(self.root, receipt, verify)
                value = "ALLOW"
            except checkpoint_monitor.MonitorReject:
                value = "DENY"
            with lock: results.append(value)

        threads = [threading.Thread(target=worker, args=(c,)) for c in ("b", "c")]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(sorted(results), ["ALLOW", "DENY"])

    def test_verification_failure_does_not_advance(self):
        receipt = self.receipt("b" * 64)
        with self.assertRaisesRegex(checkpoint_monitor.MonitorReject, "bad signature"):
            checkpoint_monitor.advance(
                self.root, receipt,
                lambda size, root: (_ for _ in ()).throw(
                    checkpoint_monitor.MonitorReject("bad signature")))
        self.assertEqual(checkpoint_monitor.current(self.root)["tree_size"], 1)

    def test_noncanonical_or_rollback_state_fails_closed(self):
        (self.root / "current.json").write_text("{}\n", "ascii")
        with self.assertRaises(checkpoint_monitor.MonitorReject):
            checkpoint_monitor.current(self.root)


if __name__ == "__main__": unittest.main(verbosity=2)
