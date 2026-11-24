"""端到端演示以测试形式运行,生成 out/ 下的可复查审计输出。"""
import json
import unittest
from pathlib import Path

import run_demo


class DemoEndToEndTest(unittest.TestCase):
    def test_demo_produces_reviewable_audit_outputs(self):
        run_demo.main()
        out = run_demo.OUT
        audit = json.loads((out / "audit_report.json").read_text(encoding="utf-8"))
        # 提交记录存在且逐条有序
        lines = (out / "demo" / "commit_log.jsonl").read_text(
            encoding="utf-8").strip().splitlines()
        seqs = [json.loads(line)["seq"] for line in lines]
        self.assertEqual(seqs, sorted(seqs))
        # 交错:撤销先落盘则拒绝,承诺先落盘则承诺有效
        self.assertEqual(audit["race_revoke_first"]["release_result"][0], "denied")
        self.assertEqual(audit["race_release_first"]["release_result"][0], "committed")
        # 恢复:移动未承诺被隔离;承诺未回执只补回执
        self.assertTrue(audit["crash_after_move"]["back_in_quarantine"])
        self.assertTrue(audit["crash_after_commit"]["no_new_commit"])
        # 模型对拍与规模核验
        self.assertEqual(audit["model"]["mismatches"], 0)
        self.assertTrue(audit["scale"]["sets_equal"])
        self.assertTrue((out / "model_states.json").exists())
        self.assertTrue((out / "scale_report.json").exists())


if __name__ == "__main__":
    unittest.main()
