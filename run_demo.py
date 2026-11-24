"""端到端演示:本地发布闸门 + 可复查审计输出。

运行:python run_demo.py
产出(out/ 目录,均可人工复查):
  demo/commit_log.jsonl   基本流程的完整提交记录(权威依据)
  audit_report.json       各场景判定与所依据的 seq
  model_states.json       独立小模型穷举的 108 个可见状态及对拍结果
  scale_report.json       五万条记录撤销触达核验
"""
import json
import shutil
import tempfile
from pathlib import Path

from gate.core import ReleaseGate, RELEASE_COMMIT, REVOCATION
from gate.interleave import run_race, run_crash_after_move, run_crash_after_commit
from gate.modelcheck import check_all
from gate.scale import verify_revocation_reach

OUT = Path(__file__).resolve().parent / "out"
POLICY = "p1"


def demo_basic(root):
    """基本流程:入隔离区 -> 扫描 -> 两名控制人赞同 -> 信任代轮换 -> 发布。"""
    gate = ReleaseGate(root)
    d1 = gate.admit(b"synthetic-artifact-1")
    gate.scan(d1, "scanner-A", trust_gen=1, policy_version=POLICY)
    gate.approve(d1, "alice", POLICY)
    gate.approve(d1, "bob", POLICY)
    commit, receipt = gate.release(d1, POLICY)

    # 信任代滚动更换后,旧代扫描不再作数
    gate.rotate_trust({2})
    d2 = gate.admit(b"synthetic-artifact-2")
    gate.scan(d2, "scanner-A", trust_gen=1, policy_version=POLICY)
    gate.approve(d2, "alice", POLICY)
    gate.approve(d2, "bob", POLICY)
    try:
        gate.release(d2, POLICY)
        d2_outcome = "released(不应发生)"
    except Exception as e:
        d2_outcome = f"denied:{getattr(e, 'reason', e)}"
    gate.scan(d2, "scanner-B", trust_gen=2, policy_version=POLICY)
    commit2, _ = gate.release(d2, POLICY)
    gate.log.close()
    return {
        "artifact1": {"digest": d1, "commit_seq": commit["seq"],
                      "receipt_seq": receipt["seq"]},
        "artifact2": {"digest": d2, "old_gen_scan_outcome": d2_outcome,
                      "commit_seq_after_rotation": commit2["seq"]},
    }


def summarize_race(out):
    seqs = {}
    for r in out["commit_log"]:
        seqs.setdefault(r["kind"], r["seq"])
    return {
        "release_result": out["release"],
        "revocation_seq": seqs.get(REVOCATION),
        "commit_seq": seqs.get(RELEASE_COMMIT),
        "proc_log_order": [m for _, _, m in out["proc_log"]],
        "in_quarantine": out["in_quarantine"],
        "in_released": out["in_released"],
    }


def main():
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    report = {}

    # 1. 基本流程(提交记录留在 out/demo/commit_log.jsonl)
    report["basic"] = demo_basic(OUT / "demo")

    # 2. 撤销与发布同时到达,两种持久化顺序
    report["race_revoke_first"] = summarize_race(
        run_race(OUT / "race-revoke-first", revoke_first=True))
    report["race_release_first"] = summarize_race(
        run_race(OUT / "race-release-first", revoke_first=False))

    # 3. 两个崩溃窗口的恢复
    g1, d1 = run_crash_after_move(OUT / "crash-after-move")
    report["crash_after_move"] = {
        "digest": d1,
        "back_in_quarantine": (g1.quarantine_dir / d1).exists(),
        "recovery_log": [r for r in g1.log.records()
                         if r["kind"] == "quarantined"],
    }
    g1.log.close()

    g2, d2 = run_crash_after_commit(OUT / "crash-after-commit")
    commits = [r for r in g2.log.records() if r["kind"] == RELEASE_COMMIT]
    restored = [r for r in g2.log.records()
                if r["kind"] == "receipt_restored"]
    # 重启后再次发布:只能返回原承诺
    commit_again, _ = g2.release(d2, POLICY)
    report["crash_after_commit"] = {
        "digest": d2,
        "original_commit_seq": commits[0]["seq"],
        "receipt_restored_ref": restored[0]["payload"]["commit_seq"],
        "re_release_returned_seq": commit_again["seq"],
        "no_new_commit": commit_again["seq"] == commits[0]["seq"],
    }
    g2.log.close()

    # 4. 独立小模型穷举 + 对拍(临时目录,不留垃圾)
    with tempfile.TemporaryDirectory() as tmp:
        rows, mismatches = check_all(Path(tmp))
    report["model"] = {"states": len(rows), "mismatches": len(mismatches)}
    (OUT / "model_states.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")

    # 5. 五万条记录:单扫描源撤销的增量触达 vs 全量重算
    scale = verify_revocation_reach()
    report["scale"] = scale
    (OUT / "scale_report.json").write_text(
        json.dumps(scale, ensure_ascii=False, indent=2), encoding="utf-8")

    (OUT / "audit_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print("审计输出已写入 out/")
    print(f"  基本流程:制品1 承诺 seq={report['basic']['artifact1']['commit_seq']},"
          f"制品2 旧代扫描 {report['basic']['artifact2']['old_gen_scan_outcome']}")
    r1, r2 = report["race_revoke_first"], report["race_release_first"]
    print(f"  交错(撤销先落盘):发布 {r1['release_result']},制品在隔离区={r1['in_quarantine']}")
    print(f"  交错(承诺先落盘):发布 {r2['release_result']},制品在发布区={r2['in_released']}")
    print(f"  崩溃(移动后):回隔离区={report['crash_after_move']['back_in_quarantine']}")
    print(f"  崩溃(承诺后):重发布返回原承诺={report['crash_after_commit']['no_new_commit']}")
    print(f"  模型对拍:{report['model']['states']} 状态,"
          f"不一致 {report['model']['mismatches']} 处")
    print(f"  规模核验:触达 {scale['incremental_touched']}/{scale['total_records']},"
          f"增量访问 {scale['incremental_accesses']} 次,"
          f"全量访问 {scale['full_accesses']} 次,集合一致={scale['sets_equal']}")


if __name__ == "__main__":
    main()
