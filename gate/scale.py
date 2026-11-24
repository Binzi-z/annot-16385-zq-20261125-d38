"""五万条制品记录:单个扫描源撤销的增量触达范围、访问计数与全量结果核验。

增量路径凭扫描源索引只触及受影响记录;全量路径逐条重算。
两者给出的受影响集合必须一致,访问计数必须等于各自实际读数。
"""
import hashlib

TOTAL = 50000
SCANNERS = 8


class CountingStore:
    """记录访问次数的只读存储,用于核验访问计数。"""

    def __init__(self, records):
        self._records = records
        self.accesses = 0

    def get(self, i):
        self.accesses += 1
        return self._records[i]

    def __len__(self):
        return len(self._records)


def make_records(n=TOTAL, scanners=SCANNERS):
    """确定性合成 n 条制品记录。"""
    records = []
    for i in range(n):
        records.append({
            "id": i,
            "digest": hashlib.sha256(f"artifact-{i}".encode()).hexdigest(),
            "scanner": f"scanner-{i % scanners}",
            "trust_gen": 1 + (i // 7) % 3,
            "policy_version": f"policy-{1 + i % 4}",
        })
    return records


def build_scanner_index(records):
    """扫描源 -> 制品 id 列表。索引维护属日常开销,不计入撤销触达。"""
    index = {}
    for rec in records:
        index.setdefault(rec["scanner"], []).append(rec["id"])
    return index


def incremental_affected(store, index, scanner):
    """增量触达:只读索引指向的记录。"""
    return sorted(store.get(i)["id"] for i in index[scanner])


def full_affected(store, scanner):
    """全量重算:逐条访问,筛出受影响记录。"""
    return sorted(rec["id"]
                  for rec in (store.get(i) for i in range(len(store)))
                  if rec["scanner"] == scanner)


def verify_revocation_reach(n=TOTAL, revoked_scanner="scanner-3"):
    records = make_records(n)
    index = build_scanner_index(records)

    inc_store = CountingStore(records)
    inc = incremental_affected(inc_store, index, revoked_scanner)

    full_store = CountingStore(records)
    full = full_affected(full_store, revoked_scanner)

    return {
        "total_records": n,
        "revoked_scanner": revoked_scanner,
        "incremental_touched": len(inc),
        "incremental_accesses": inc_store.accesses,
        "full_accesses": full_store.accesses,
        "sets_equal": inc == full,
        "access_count_matches_touch": inc_store.accesses == len(inc),
    }
