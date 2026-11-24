"""独立小模型:不依赖闸门实现,纯函数穷举切换信任代时的可见状态。

可见状态由四个独立维度决定:
- scan_gen:      制品持有的通过扫描来自哪个信任代(None/1/2)
- trusted_gens:  当前受信信任代集合(滚动更换的落点)
- approvals:     引用同一摘要与策略版本的赞同控制人集合
- revocation:    扫描源撤销相对发布承诺的持久化顺序

模型只回答一个问题:该制品在闸门处可见的结局是什么。
"""
from itertools import product

RELEASED = "released"
DENIED = "denied"

SCAN_GENS = [None, 1, 2]
TRUSTED_SETS = [frozenset({1}), frozenset({2}), frozenset({1, 2})]
APPROVAL_SETS = [(), ("alice",), ("alice", "alice"), ("alice", "bob")]
REVOCATION_ORDERS = ["none", "before_commit", "after_commit"]


def visible_outcome(scan_gen, trusted_gens, approvals, revocation):
    """返回 (outcome, reason)。判定次序即模型对规则的解释:
    赞同人数 -> 是否有扫描 -> 扫描信任代是否受信 -> 撤销是否先于承诺落盘。
    撤销落在承诺之后不影响已落盘的承诺。"""
    if len(set(approvals)) < 2:
        return DENIED, "approvals"
    if scan_gen is None:
        return DENIED, "no-scan"
    if scan_gen not in trusted_gens:
        return DENIED, "untrusted-generation"
    if revocation == "before_commit":
        return DENIED, "scanner-revoked"
    return RELEASED, None


def enumerate_states():
    """穷举全部 3*3*4*3 = 108 个可见状态。"""
    rows = []
    for scan_gen, trusted, approvals, revocation in product(
            SCAN_GENS, TRUSTED_SETS, APPROVAL_SETS, REVOCATION_ORDERS):
        outcome, reason = visible_outcome(
            scan_gen, trusted, approvals, revocation)
        rows.append({
            "scan_gen": scan_gen,
            "trusted_gens": sorted(trusted),
            "approvals": list(approvals),
            "revocation": revocation,
            "expected_outcome": outcome,
            "expected_reason": reason,
        })
    return rows
