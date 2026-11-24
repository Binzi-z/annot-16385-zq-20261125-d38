"""本地发布闸门核心:提交记录的持久化顺序是唯一权威。

发布三段式:移动制品 -> 承诺落盘 -> 回执落盘。
- 已移动但承诺未落盘(崩溃):恢复时隔离该文件(放回隔离区并记录)。
- 承诺已落盘而回执丢失(崩溃):重启只补回执、返回原承诺,不重新批准。

撤销与发布的竞争:判定与承诺追加在同一把锁(_commit_lock)内完成,
撤销/轮换也走同一把锁,因此提交记录(commit_log.jsonl,逐条 fsync)的
seq 顺序即判定顺序,与进程日志(proc_log)的先后无关。
"""
import hashlib
import itertools
import json
import os
import threading
from pathlib import Path

# 提交记录类型
SCAN = "scan"                     # 扫描结论,携带扫描器信任代
APPROVAL = "approval"             # 控制人赞同,引用制品摘要与策略版本
REVOCATION = "revocation"         # 撤销扫描源
TRUST_ROTATION = "trust_rotation"  # 信任代滚动更换
RELEASE_COMMIT = "release_commit"  # 发布承诺(落盘即生效)
RELEASE_RECEIPT = "release_receipt"  # 发布回执
RELEASE_DENIED = "release_denied"  # 锁内复查未过,已回滚隔离
QUARANTINED = "quarantined"        # 恢复动作:已移动但无承诺,隔离
RECEIPT_RESTORED = "receipt_restored"  # 恢复动作:按原承诺补回执

DEFAULT_TRUSTED_GENS = (1,)


class SimulatedCrash(Exception):
    """测试注入的崩溃:抛出后丢弃本对象即视为进程消亡。"""


class ReleaseDenied(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class CommitLog:
    """追加式持久化提交记录。seq 在锁内分配,写盘并 fsync 后才返回。"""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._records = []
        if self.path.exists():
            with self.path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self._records.append(json.loads(line))
        self._next_seq = self._records[-1]["seq"] + 1 if self._records else 1
        self._f = self.path.open("a", encoding="utf-8")

    def append(self, kind, payload):
        with self._lock:
            rec = {"seq": self._next_seq, "kind": kind, "payload": payload}
            self._f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
            self._f.flush()
            os.fsync(self._f.fileno())
            self._next_seq += 1
            self._records.append(rec)
            return dict(rec)

    def records(self):
        with self._lock:
            return [dict(r) for r in self._records]

    def close(self):
        with self._lock:
            if not self._f.closed:
                self._f.close()


def replay(records):
    """把提交记录重放为判定所需的状态。恢复与锁内复查都以此为准。"""
    st = {
        "scans": {},        # digest -> [payload+seq]
        "approvals": {},    # (digest, policy_version) -> {controller: seq}
        "revoked": {},      # scanner -> 首次撤销 seq
        "trusted_gens": set(DEFAULT_TRUSTED_GENS),
        "commits": {},      # digest -> commit 记录
        "receipts": {},     # digest -> receipt 记录
    }
    for rec in records:
        kind, p = rec["kind"], rec["payload"]
        if kind == SCAN:
            st["scans"].setdefault(p["digest"], []).append({**p, "seq": rec["seq"]})
        elif kind == APPROVAL:
            key = (p["digest"], p["policy_version"])
            st["approvals"].setdefault(key, {})[p["controller"]] = rec["seq"]
        elif kind == REVOCATION:
            st["revoked"].setdefault(p["scanner"], rec["seq"])
        elif kind == TRUST_ROTATION:
            st["trusted_gens"] = set(p["trusted_gens"])
        elif kind == RELEASE_COMMIT:
            st["commits"][p["digest"]] = rec
        elif kind in (RELEASE_RECEIPT, RECEIPT_RESTORED):
            st["receipts"][p["digest"]] = rec
    return st


class ReleaseGate:
    """本地发布闸门。所有判定只依据已落盘的提交记录。"""

    def __init__(self, root):
        self.root = Path(root)
        self.quarantine_dir = self.root / "quarantine"
        self.released_dir = self.root / "released"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.released_dir.mkdir(parents=True, exist_ok=True)
        self.log = CommitLog(self.root / "commit_log.jsonl")
        self._commit_lock = threading.Lock()  # 判定与承诺落盘的唯一序列化点
        self._proc_lock = threading.Lock()
        self._proc_ctr = itertools.count(1)
        self.proc_log = []  # 进程日志:仅用于演示它不作数
        self._state = replay(self.log.records())
        self.recover()

    def close(self):
        self.log.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ---- 进程日志(非权威,只用于对照) ----
    def _plog(self, msg):
        with self._proc_lock:
            self.proc_log.append(
                [next(self._proc_ctr), threading.current_thread().name, msg])

    def _refresh(self):
        self._state = replay(self.log.records())

    # ---- 记录类操作 ----
    def admit(self, data: bytes) -> str:
        """制品进入隔离区,返回其摘要。"""
        digest = hashlib.sha256(data).hexdigest()
        (self.quarantine_dir / digest).write_bytes(data)
        return digest

    def scan(self, digest, scanner, trust_gen, policy_version, passed=True):
        self._plog(f"scan {digest[:8]} scanner={scanner} gen={trust_gen}")
        rec = self.log.append(SCAN, {
            "digest": digest, "scanner": scanner, "trust_gen": trust_gen,
            "policy_version": policy_version, "passed": bool(passed)})
        self._refresh()
        return rec

    def approve(self, digest, controller, policy_version):
        self._plog(f"approve {digest[:8]} by {controller}")
        rec = self.log.append(APPROVAL, {
            "digest": digest, "controller": controller,
            "policy_version": policy_version})
        self._refresh()
        return rec

    def revoke_scanner(self, scanner):
        """撤销扫描源。与发布判定共用一把锁:谁先落盘谁先生效。"""
        self._plog(f"revoke {scanner}")
        with self._commit_lock:
            rec = self.log.append(REVOCATION, {"scanner": scanner})
            self._refresh()
        return rec

    def rotate_trust(self, trusted_gens):
        """信任代滚动更换:此后只有受信代内的扫描可作发布依据。"""
        self._plog(f"rotate-trust {sorted(trusted_gens)}")
        with self._commit_lock:
            rec = self.log.append(TRUST_ROTATION,
                                  {"trusted_gens": sorted(trusted_gens)})
            self._refresh()
        return rec

    # ---- 判定(纯函数,基于已重放状态) ----
    def _eligibility(self, digest, policy_version):
        st = self._state
        approvals = st["approvals"].get((digest, policy_version), {})
        if len(approvals) < 2:
            # 两份赞同须引用同一摘要与策略版本,且出自不同控制人
            return False, "approvals"
        scans = [s for s in st["scans"].get(digest, [])
                 if s["passed"] and s["policy_version"] == policy_version]
        if not scans:
            return False, "no-scan"
        valid = [s for s in scans
                 if s["trust_gen"] in st["trusted_gens"]
                 and s["scanner"] not in st["revoked"]]
        if valid:
            return True, None
        if any(s["trust_gen"] in st["trusted_gens"] for s in scans):
            return False, "scanner-revoked"
        return False, "untrusted-generation"

    # ---- 发布:移动 -> 承诺落盘 -> 回执落盘 ----
    def release(self, digest, policy_version, hooks=None):
        hooks = hooks or {}
        self._plog(f"release start {digest[:8]}")
        if "started" in hooks:
            hooks["started"]()
        self._refresh()
        commit = self._state["commits"].get(digest)
        if commit is not None:
            # 幂等:承诺已落盘,只返回原承诺并补齐回执,绝不重新批准
            receipt = self._ensure_receipt(digest, commit)
            return commit, receipt
        qpath = self.quarantine_dir / digest
        rpath = self.released_dir / digest
        if not qpath.exists():
            raise ReleaseDenied("artifact-missing")
        ok, reason = self._eligibility(digest, policy_version)  # 咨询性预检
        if not ok:
            raise ReleaseDenied(reason)
        # 1. 移动制品出隔离区
        os.replace(qpath, rpath)
        if "after_move" in hooks:
            hooks["after_move"]()
        if "before_lock" in hooks:
            hooks["before_lock"]()
        # 2. 锁内复查 + 承诺落盘:与撤销/轮换同一序列化点
        with self._commit_lock:
            if "inside_lock" in hooks:
                hooks["inside_lock"]()
            self._refresh()
            ok, reason = self._eligibility(digest, policy_version)
            if not ok:
                # 撤销先落盘:回滚移动,重新隔离,并留下可复查记录
                os.replace(rpath, qpath)
                self.log.append(RELEASE_DENIED, {
                    "digest": digest, "policy_version": policy_version,
                    "reason": reason})
                self._refresh()
                raise ReleaseDenied(reason)
            commit = self.log.append(RELEASE_COMMIT, {
                "digest": digest, "policy_version": policy_version})
            self._refresh()
        if "after_commit" in hooks:
            hooks["after_commit"]()
        # 3. 回执落盘
        receipt = self._ensure_receipt(digest, commit)
        return commit, receipt

    def _ensure_receipt(self, digest, commit):
        self._refresh()
        existing = self._state["receipts"].get(digest)
        if existing is not None:
            return existing
        rec = self.log.append(RELEASE_RECEIPT, {
            "digest": digest, "commit_seq": commit["seq"]})
        self._refresh()
        return rec

    # ---- 恢复:重启时调用,只依据已落盘的提交记录 ----
    def recover(self):
        self._refresh()
        actions = []
        # a) 已移动但承诺未落盘 -> 隔离该文件
        for p in sorted(self.released_dir.iterdir()):
            digest = p.name
            if digest not in self._state["commits"]:
                os.replace(p, self.quarantine_dir / digest)
                self.log.append(QUARANTINED, {
                    "digest": digest, "cause": "moved-without-commit"})
                actions.append(("quarantined", digest))
        self._refresh()
        # b) 承诺已落盘而回执丢失 -> 只补回执,返回原承诺,不重新批准
        for digest, commit in sorted(self._state["commits"].items()):
            if digest not in self._state["receipts"]:
                self.log.append(RECEIPT_RESTORED, {
                    "digest": digest, "commit_seq": commit["seq"]})
                actions.append(("receipt-restored", digest))
        self._refresh()
        return actions
