"""对拍驱动:把模型的每个可见状态在真实闸门上复演一遍,比对结局。

模型本身(gate/model.py)不接触闸门实现;本模块是测试线束,
负责把抽象状态翻译成闸门调用序列。
"""
import tempfile
from pathlib import Path

from .core import ReleaseGate, ReleaseDenied
from .model import enumerate_states

POLICY = "p1"
SCANNER = "scanner-A"


def drive_row(row, root):
    """在 root 下新建闸门,按 row 描述复演场景,返回 (outcome, reason)。"""
    gate = ReleaseGate(root)
    digest = gate.admit(b"artifact-" + repr(sorted(row.items())).encode())
    trusted = set(row["trusted_gens"])
    if trusted != {1}:
        gate.rotate_trust(sorted(trusted))
    if row["scan_gen"] is not None:
        gate.scan(digest, SCANNER, row["scan_gen"], POLICY)
    for controller in sorted(set(row["approvals"])):
        gate.approve(digest, controller, POLICY)
    if row["revocation"] == "before_commit":
        gate.revoke_scanner(SCANNER)
    try:
        gate.release(digest, POLICY)
        outcome, reason = "released", None
    except ReleaseDenied as e:
        outcome, reason = "denied", e.reason
    if row["revocation"] == "after_commit":
        # 撤销落在承诺之后:已落盘的承诺不受影响
        gate.revoke_scanner(SCANNER)
    gate.log.close()
    return outcome, reason


def check_all(root=None):
    """逐行对拍,返回 (rows, mismatches)。root 为 None 时用临时目录。"""
    rows = enumerate_states()
    mismatches = []
    if root is None:
        with tempfile.TemporaryDirectory() as tmp:
            return _run(rows, Path(tmp))
    return _run(rows, Path(root))


def _run(rows, base):
    base.mkdir(parents=True, exist_ok=True)
    mismatches = []
    for i, row in enumerate(rows):
        outcome, reason = drive_row(row, base / f"case-{i:03d}")
        row["actual_outcome"] = outcome
        row["actual_reason"] = reason
        row["match"] = (outcome == row["expected_outcome"]
                        and reason == row["expected_reason"])
        if not row["match"]:
            mismatches.append(row)
    return rows, mismatches
