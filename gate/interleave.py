"""两个真实线程 + 屏障控制的撤销/发布交错,以及两个崩溃窗口。

run_race 用 threading.Barrier(2) 让两个线程同时起跑,再用事件把
持久化顺序钉死在指定方向;进程日志顺序则被刻意调成相反方向,
以此证明判定只跟随提交记录的持久化顺序。
"""
import threading

from .core import ReleaseGate, ReleaseDenied, SimulatedCrash

POLICY = "p1"
SCANNER = "scanner-A"


def setup_gate(root):
    """造一个满足发布条件的闸门:一次扫描 + 两名控制人的赞同。"""
    gate = ReleaseGate(root)
    digest = gate.admit(b"race-artifact")
    gate.scan(digest, SCANNER, 1, POLICY)
    gate.approve(digest, "alice", POLICY)
    gate.approve(digest, "bob", POLICY)
    return gate, digest


def run_race(root, revoke_first):
    """撤销与发布同时到达。revoke_first 指定谁先在提交记录里落盘。

    返回 dict:发布结局、提交记录、进程日志、制品位置。
    """
    gate, digest = setup_gate(root)
    barrier = threading.Barrier(2)
    release_started = threading.Event()
    revoked_done = threading.Event()
    release_inside = threading.Event()
    proceed = threading.Event()
    outcome = {}

    def do_release():
        barrier.wait()
        hooks = {"started": release_started.set}
        if revoke_first:
            # 发布已移动制品,在进锁前停下,让撤销先落盘
            hooks["before_lock"] = lambda: revoked_done.wait(10)
        else:
            # 发布进锁后停下,等撤销线程就位(它将阻塞在锁上)
            def inside():
                release_inside.set()
                proceed.wait(10)
            hooks["inside_lock"] = inside
        try:
            commit, _receipt = gate.release(digest, POLICY, hooks=hooks)
            outcome["release"] = ("committed", commit["seq"])
        except ReleaseDenied as e:
            outcome["release"] = ("denied", e.reason)

    def do_revoke():
        barrier.wait()
        if revoke_first:
            # 让"发布开始"先出现在进程日志里,但撤销先落盘
            release_started.wait(10)
            gate.revoke_scanner(SCANNER)
            revoked_done.set()
        else:
            # 等发布进入临界区,放它先落盘,撤销随后排队
            release_inside.wait(10)
            proceed.set()
            gate.revoke_scanner(SCANNER)

    t_rel = threading.Thread(target=do_release, name="release-thread")
    t_rev = threading.Thread(target=do_revoke, name="revoke-thread")
    t_rel.start()
    t_rev.start()
    t_rel.join(30)
    t_rev.join(30)
    assert not t_rel.is_alive() and not t_rev.is_alive(), "交错死锁"

    outcome["digest"] = digest
    outcome["proc_log"] = [list(e) for e in gate.proc_log]
    outcome["commit_log"] = gate.log.records()
    outcome["in_quarantine"] = (gate.quarantine_dir / digest).exists()
    outcome["in_released"] = (gate.released_dir / digest).exists()
    gate.log.close()
    return outcome


def run_crash_after_move(root):
    """崩溃窗口一:制品已移动,承诺未落盘。重启恢复须隔离该文件。"""
    gate, digest = setup_gate(root)

    def boom():
        raise SimulatedCrash()

    try:
        gate.release(digest, POLICY, hooks={"after_move": boom})
        raise AssertionError("应当崩溃")
    except SimulatedCrash:
        pass
    gate.log.close()
    del gate  # 进程消亡,内存状态全部丢失
    recovered = ReleaseGate(root)  # 重启即恢复
    return recovered, digest


def run_crash_after_commit(root):
    """崩溃窗口二:承诺已落盘,回执丢失。重启只能返回原承诺。"""
    gate, digest = setup_gate(root)

    def boom():
        raise SimulatedCrash()

    try:
        gate.release(digest, POLICY, hooks={"after_commit": boom})
        raise AssertionError("应当崩溃")
    except SimulatedCrash:
        pass
    gate.log.close()
    del gate
    recovered = ReleaseGate(root)
    return recovered, digest
