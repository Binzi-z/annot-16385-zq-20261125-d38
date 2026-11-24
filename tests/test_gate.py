import tempfile
import unittest
from pathlib import Path

from gate.core import (
    ReleaseGate, ReleaseDenied,
    RELEASE_COMMIT, RELEASE_DENIED, QUARANTINED, RECEIPT_RESTORED, REVOCATION,
)
from gate.interleave import run_race, run_crash_after_move, run_crash_after_commit
from gate.modelcheck import check_all
from gate.scale import verify_revocation_reach, TOTAL, SCANNERS

POLICY = "p1"


class TempGateCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)  # LIFO:后注册的先执行,先关闸门再清目录
        self.root = Path(self._tmp.name)

    def make_gate(self):
        gate = ReleaseGate(self.root / "gate")
        self.addCleanup(gate.close)
        return gate


class ApprovalRulesTest(TempGateCase):
    def test_two_distinct_controllers_same_digest_and_policy(self):
        gate = self.make_gate()
        d = gate.admit(b"a")
        gate.scan(d, "scanner-A", 1, POLICY)
        gate.approve(d, "alice", POLICY)
        gate.approve(d, "bob", POLICY)
        commit, receipt = gate.release(d, POLICY)
        self.assertEqual(commit["kind"], RELEASE_COMMIT)
        self.assertTrue((gate.released_dir / d).exists())

    def test_same_controller_twice_is_not_two_approvals(self):
        gate = self.make_gate()
        d = gate.admit(b"a")
        gate.scan(d, "scanner-A", 1, POLICY)
        gate.approve(d, "alice", POLICY)
        gate.approve(d, "alice", POLICY)
        with self.assertRaises(ReleaseDenied) as cm:
            gate.release(d, POLICY)
        self.assertEqual(cm.exception.reason, "approvals")

    def test_approval_for_other_policy_version_does_not_count(self):
        gate = self.make_gate()
        d = gate.admit(b"a")
        gate.scan(d, "scanner-A", 1, POLICY)
        gate.approve(d, "alice", POLICY)
        gate.approve(d, "bob", "p2")  # 策略版本不同
        with self.assertRaises(ReleaseDenied) as cm:
            gate.release(d, POLICY)
        self.assertEqual(cm.exception.reason, "approvals")


class TrustRotationTest(TempGateCase):
    def test_old_generation_scan_rejected_after_rotation(self):
        gate = self.make_gate()
        d = gate.admit(b"a")
        gate.scan(d, "scanner-A", 1, POLICY)
        gate.approve(d, "alice", POLICY)
        gate.approve(d, "bob", POLICY)
        gate.rotate_trust({2})
        with self.assertRaises(ReleaseDenied) as cm:
            gate.release(d, POLICY)
        self.assertEqual(cm.exception.reason, "untrusted-generation")

    def test_new_generation_scan_accepted_after_rotation(self):
        gate = self.make_gate()
        d = gate.admit(b"a")
        gate.scan(d, "scanner-A", 2, POLICY)
        gate.approve(d, "alice", POLICY)
        gate.approve(d, "bob", POLICY)
        gate.rotate_trust({2})
        commit, _ = gate.release(d, POLICY)
        self.assertEqual(commit["kind"], RELEASE_COMMIT)


class RaceTest(unittest.TestCase):
    """撤销与发布同时到达:以提交记录的持久化顺序判定。"""

    def test_revocation_persisted_first_denies_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = run_race(Path(tmp) / "race", revoke_first=True)
        self.assertEqual(out["release"][0], "denied")
        self.assertEqual(out["release"][1], "scanner-revoked")
        self.assertTrue(out["in_quarantine"])
        self.assertFalse(out["in_released"])
        kinds = [r["kind"] for r in out["commit_log"]]
        self.assertNotIn(RELEASE_COMMIT, kinds)
        self.assertIn(RELEASE_DENIED, kinds)
        # 持久化顺序:撤销在拒绝记录之前
        seqs = {r["kind"]: r["seq"] for r in out["commit_log"]}
        self.assertLess(seqs[REVOCATION], seqs[RELEASE_DENIED])
        # 进程日志顺序相反:发布先开始,但它不作数
        msgs = [m for _, _, m in out["proc_log"]]
        self.assertLess(msgs.index("release start " + out["digest"][:8]),
                        msgs.index("revoke scanner-A"))

    def test_commit_persisted_first_stands_despite_later_revocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = run_race(Path(tmp) / "race", revoke_first=False)
        self.assertEqual(out["release"][0], "committed")
        self.assertTrue(out["in_released"])
        seqs = {r["kind"]: r["seq"] for r in out["commit_log"]}
        # 持久化顺序:承诺在撤销之前,承诺有效
        self.assertLess(seqs[RELEASE_COMMIT], seqs[REVOCATION])


class RecoveryTest(unittest.TestCase):
    def test_moved_without_commit_is_quarantined_on_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate, digest = run_crash_after_move(Path(tmp) / "gate")
            self.assertTrue((gate.quarantine_dir / digest).exists())
            self.assertFalse((gate.released_dir / digest).exists())
            kinds = [r["kind"] for r in gate.log.records()]
            self.assertNotIn(RELEASE_COMMIT, kinds)
            self.assertIn(QUARANTINED, kinds)
            gate.log.close()

    def test_commit_without_receipt_returns_original_no_reapproval(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "gate"
            gate, digest = run_crash_after_commit(root)
            records = gate.log.records()
            commits = [r for r in records if r["kind"] == RELEASE_COMMIT]
            self.assertEqual(len(commits), 1)
            # 恢复只补回执,引用原承诺 seq
            restored = [r for r in records if r["kind"] == RECEIPT_RESTORED]
            self.assertEqual(len(restored), 1)
            self.assertEqual(restored[0]["payload"]["commit_seq"],
                             commits[0]["seq"])
            # 撤销扫描源后再发布:只能返回原承诺,不能重新批准
            gate.revoke_scanner("scanner-A")
            commit, receipt = gate.release(digest, POLICY)
            self.assertEqual(commit["seq"], commits[0]["seq"])
            commits_after = [r for r in gate.log.records()
                             if r["kind"] == RELEASE_COMMIT]
            self.assertEqual(len(commits_after), 1)  # 没有新的承诺
            gate.log.close()


class ModelExhaustiveTest(unittest.TestCase):
    def test_all_enumerated_states_match_gate(self):
        rows, mismatches = check_all()
        self.assertEqual(len(rows), 108)
        self.assertEqual(mismatches, [])


class ScaleTest(unittest.TestCase):
    def test_incremental_reach_matches_full_recompute(self):
        report = verify_revocation_reach()
        self.assertEqual(report["total_records"], TOTAL)
        self.assertEqual(report["incremental_touched"], TOTAL // SCANNERS)
        self.assertEqual(report["incremental_accesses"], TOTAL // SCANNERS)
        self.assertEqual(report["full_accesses"], TOTAL)
        self.assertTrue(report["sets_equal"])
        self.assertTrue(report["access_count_matches_touch"])


if __name__ == "__main__":
    unittest.main()
