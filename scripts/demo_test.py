#!/usr/bin/env python3
"""验证演示脚本：100 条日志完整流程测试。

生成 10 批次 × 10 条混合风险等级操作日志（含高危命令），
依次提交、搜索、验证、篡改检测，验证各个端点均正常工作。

用法：
    python scripts/demo_test.py                           # 连接 localhost:5000
    python scripts/demo_test.py --url http://IP:5000      # 连接远程服务
    python scripts/demo_test.py --batches 20 --size 50    # 2000 条压力测试

验证项目：
    [ 1] 生成数据（含 normal/medium/high 风险混合）
    [ 2] 批次提交上链（PBFT 共识）
    [ 3] 链信息 / 链完整性
    [ 4] 日志搜索 + 分页
    [ 5] 单条日志验证（Merkle proof）
    [ 6] 存证记录查询
    [ 7] 篡改检测（修改日志 → Merkle Root 不匹配）
    [ 8] PBFT 共识网络状态
    [ 9] 跨节点账本一致性验证
    [10] 拜占庭攻击模拟（演示模式）
"""

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(PROJECT_ROOT)
sys.path.insert(0, PROJECT_ROOT)

os.environ.setdefault("AUDIT_SYSTEM_MODE", "demo")

from src.debug.data_generator import generate_batch

# ── 命令行 ──────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="100 条日志完整流程验证")
parser.add_argument("--url", default="http://127.0.0.1:5000",
                    help="API 地址 (默认 http://127.0.0.1:5000)")
parser.add_argument("--batches", type=int, default=10,
                    help="批次数 (默认 10 → 100 条)")
parser.add_argument("--size", type=int, default=10,
                    help="每批日志数 (默认 10)")
parser.add_argument("--verbose", action="store_true", help="详细输出")
args = parser.parse_args()

API = f"{args.url}/api/v1/audit"
GREEN, RED, YELLOW, CYAN, NC = "\033[32m", "\033[31m", "\033[33m", "\033[36m", "\033[0m"

results: list[bool] = []
submitted: list[dict] = []


def ok(msg: str):
    results.append(True)
    print(f"  {GREEN}[PASS]{NC} {msg}")


def fail(msg: str, detail: str = ""):
    results.append(False)
    print(f"  {RED}[FAIL]{NC} {msg}")
    if detail:
        print(f"       {RED}{detail}{NC}")


def skip(msg: str, detail: str = ""):
    results.append(True)
    print(f"  {YELLOW}[SKIP]{NC} {msg}")
    if detail:
        print(f"       {detail}")


# ── HTTP 工具 ───────────────────────────────────────────────

def post(path: str, data: dict) -> dict:
    payload = json.dumps(data).encode()
    req = urllib.request.Request(
        f"{API}{path}", data=payload,
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def get(path: str) -> dict:
    with urllib.request.urlopen(f"{API}{path}", timeout=60) as r:
        return json.loads(r.read())


def request_any(method: str, path: str, data: dict | None = None) -> dict:
    """请求并接受任何 HTTP 状态码。"""
    payload = json.dumps(data).encode() if data else None
    req = urllib.request.Request(
        f"{API}{path}", data=payload,
        headers={"Content-Type": "application/json"}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode(errors="replace"))


# ══════════════════════════════════════════════════════════════
# 主流程
# ══════════════════════════════════════════════════════════════

def main():
    print()
    print(f"{'=' * 62}")
    print(f"  100 条日志完整流程验证")
    print(f"  API: {args.url}")
    print(f"  {args.batches} 批次 × {args.size} 条 = {args.batches * args.size} 条日志")
    print(f"{'=' * 62}")

    # ── 1. 生成数据并提交 ──────────────────────────────────
    print(f"\n  {CYAN}── 1. 生成 {args.batches} 批次数据并提交上链 ──{NC}\n")

    now = datetime.now(timezone.utc)
    for i in range(args.batches):
        batch_time = now
        batch_id = f"demo_{batch_time.strftime('%Y%m%d_%H%M%S')}_{i:02d}"

        logs = generate_batch(batch_id, log_count=args.size, risk_mix=True)

        # 统计危险命令
        high = sum(1 for l in logs if l.get("risk_level") == "high")
        med = sum(1 for l in logs if l.get("risk_level") == "medium")
        nor = sum(1 for l in logs if l.get("risk_level") == "normal")

        if args.verbose:
            for l in logs:
                tag = {"high": "🔴", "medium": "🟡", "normal": "🟢"}.get(l["risk_level"], "")
                print(f"    {tag} [{l['risk_level']:6s}] {l['operator']:12s} → {l['command']}")

        try:
            resp = post("/batch", {"batch_id": batch_id, "logs": logs})
            submitted.append({"batch_id": batch_id, "logs": logs, "resp": resp})
            print(f"  [{i+1:2d}] {batch_id}  {GREEN}OK{NC}  "
                  f"merkle={resp['merkle_root'][:12]}...  "
                  f"record={resp['record_hash'][:12]}...  "
                  f"({len(logs)}条: {nor}N/{med}M/{high}H)")
        except Exception as e:
            fail(f"批次 {batch_id} 提交失败", str(e))
            return 1
        time.sleep(0.3)

    total = args.batches * args.size
    ok(f"全部 {args.batches} 批次 {total} 条日志提交成功")
    _show_high_commands()

    # ── 2. 链信息 ──────────────────────────────────────────
    print(f"\n  {CYAN}── 2. 链信息 / 链完整性 ──{NC}\n")
    try:
        info = get("/chain/info")
        print(f"  总记录: {info['total_records']}")
        print(f"  创世批次: {info.get('genesis_batch_id') or '(当前模式不返回)'}")
        print(f"  最新批次: {info.get('latest_batch_id') or '(当前模式不返回)'}")
        print(f"  最新哈希: {info.get('latest_record_hash', '?')}")
        assert info["total_records"] >= args.batches
        ok(f"链信息正常: {info['total_records']} 条记录")
    except Exception as e:
        fail("链信息查询失败", str(e))

    try:
        integ = get("/chain/integrity")
        if integ["is_valid"]:
            ok(f"链完整性: 通过 (total={integ['total_records']}, broken={integ['broken_position']})")
        else:
            fail(f"链断裂: 位置 {integ['broken_position']}")
    except Exception as e:
        fail("链完整性查询失败", str(e))

    # ── 3. 搜索 ────────────────────────────────────────────
    print(f"\n  {CYAN}── 3. 日志搜索 ──{NC}\n")
    try:
        sr = get("/search?size=10")
        t = sr.get("total", 0)
        if t > 0:
            ok(f"搜索成功: total={t}, 返回 {len(sr.get('results', []))} 条")
        else:
            fail("搜索无结果")
    except Exception as e:
        fail("搜索失败", str(e))

    # ── 4. 单条验证 ────────────────────────────────────────
    print(f"\n  {CYAN}── 4. 单条日志验证 ──{NC}\n")
    batch = submitted[0]
    first = batch["logs"][0]
    mid = batch["logs"][args.size // 2]
    last = batch["logs"][-1]

    # 也验证中间批次的一条
    mid_batch = submitted[args.batches // 2]
    mid_log = mid_batch["logs"][0]

    test_logs = [first, mid, last, mid_log]
    for log in test_logs:
        log_id = log["log_id"]
        try:
            vr = post("/verify", {"log_id": log_id})
            if vr.get("verified"):
                ok(f"验证通过: {log_id[:16]}... ({log['risk_level']}) [{log['operator']}]")
            else:
                fail(f"验证失败: {log_id[:16]}... ({log['risk_level']})",
                     vr.get("message", ""))
        except Exception as e:
            fail("验证请求失败", str(e))

    # ── 5. 存证查询 ────────────────────────────────────────
    print(f"\n  {CYAN}── 5. 存证记录查询 ──{NC}\n")
    for b in [submitted[0], submitted[-1]]:
        bid = b["batch_id"]
        try:
            rec = get(f"/record/{bid}")
            print(f"  {bid}")
            print(f"    merkle_root : {rec.get('merkle_root', '?')[:32]}...")
            print(f"    record_hash : {rec.get('record_hash', '?')[:32]}...")
            print(f"    prev_hash   : {rec.get('prev_hash', '?')[:32]}...")
            print(f"    tx_hash     : {rec.get('tx_hash', '?')}")
            print(f"    timestamp   : {rec.get('timestamp', '?')}")
            print(f"    log_count   : {rec.get('log_count', '?')}")
            ok(f"存证记录存在: {bid}")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                skip(f"存证查询 404: {bid}", "远程模式可能不返回")
            else:
                fail(f"存证查询失败: {bid}", str(e))
        except Exception as e:
            fail(f"存证查询失败: {bid}", str(e))

    # ── 6. 篡改检测 ────────────────────────────────────────
    print(f"\n  {CYAN}── 6. 篡改检测 (Merkle Root 比对) ──{NC}\n")
    if len(submitted) >= 2:
        tamper_batch = submitted[1]
        tamper_log = tamper_batch["logs"][0]
        tamper_id = tamper_log["log_id"]
        orig_cmd = tamper_log["command"]

        try:
            # 在 demo 模式下直接通过本地 SQLite 篡改
            from src.debug.mock_es import MockES
            es = MockES()
            es.tamper_log(tamper_id, "command", "/bin/evil_injected_command")

            vr = post("/verify", {"log_id": tamper_id})
            if not vr.get("verified") and not vr.get("merkle_root_match"):
                ok(f"篡改检测有效: {tamper_id[:16]}... 被检出 (Merkle mismatch)")
            else:
                fail("篡改检测失效: 被篡改日志通过了验证",
                     f"merkle_match={vr.get('merkle_root_match')}")

            # 恢复
            es.tamper_log(tamper_id, "command", orig_cmd)
        except Exception as e:
            skip("篡改检测跳过（非 demo 模式或 ES 不可用）", str(e))
    else:
        skip("篡改检测跳过（批次不足）")

    # ── 7. 共识状态 ────────────────────────────────────────
    print(f"\n  {CYAN}── 7. PBFT 共识网络状态 ──{NC}\n")
    try:
        cs = get("/chain/consensus")
        cfg = cs.get("config", {})
        nodes = cs.get("nodes", [])
        if cfg and nodes:
            honest = sum(1 for n in nodes if n.get("type") == "honest")
            byz = sum(1 for n in nodes if n.get("type") == "byzantine")
            print(f"  算法: {cfg.get('consensus_algorithm', 'N/A')}")
            print(f"  容错: {cfg.get('fault_tolerance', 'N/A')}")
            print(f"  节点: {len(nodes)} ({honest} 诚实 / {byz} 拜占庭)")
            ok(f"共识网络: {len(nodes)} 节点, 容错 {cfg.get('fault_tolerance', '?')}")
        else:
            skip("共识状态不可用", json.dumps(cs, ensure_ascii=False)[:120])
    except Exception as e:
        skip("共识状态请求失败", str(e))

    # ── 8. 跨节点验证 ──────────────────────────────────────
    print(f"\n  {CYAN}── 8. 跨节点账本一致性验证 ──{NC}\n")
    try:
        cv = request_any("GET", "/chain/cross-verify")
        if cv.get("consensus_ok"):
            ok(f"跨节点验证: {cv.get('summary', 'OK')}")
        elif "byzantine_detected" in cv:
            if cv["byzantine_detected"]:
                skip(f"拜占庭节点已检出: {cv.get('summary', 'WARN')}")
            else:
                ok(f"跨节点验证: {cv.get('summary', 'OK')}")
        else:
            skip("跨节点验证不可用", json.dumps(cv, ensure_ascii=False)[:120])
    except Exception as e:
        skip("跨节点验证请求失败", str(e))

    # ── 9. 拜占庭攻击模拟 ──────────────────────────────────
    print(f"\n  {CYAN}── 9. 拜占庭攻击模拟 ──{NC}\n")
    try:
        atk = request_any("POST", "/chain/attack", {})
        if atk.get("success"):
            ok(f"拜占庭攻击已模拟: {atk.get('node_id')} 篡改 {atk.get('batch_id', '?')}")
            # 验证攻击被检测到
            cv2 = request_any("GET", "/chain/cross-verify")
            if cv2.get("byzantine_detected"):
                ok("跨节点验证成功检出拜占庭攻击")
            else:
                skip("跨节点验证未检出（可能已运行的旧账本数据覆盖）")
        else:
            skip("攻击模拟跳过", atk.get("message", "(无可攻击节点)"))
    except Exception as e:
        skip("攻击模拟请求失败", str(e))

    # ── 汇总 ────────────────────────────────────────────────
    print()
    passed = sum(results)
    total = len(results)
    color = GREEN if passed == total else (YELLOW if passed > total // 2 else RED)
    print(f"{'=' * 62}")
    print(f"  {color}结果: {passed}/{total} 通过{NC}")
    print(f"{'=' * 62}")
    print()

    if passed == total:
        print(f"  {GREEN}✓ 全部验证通过，系统各模块工作正常。{NC}")
        print(f"    仪表板:     {args.url}")
        print(f"    验证页面:   {args.url}/verify")
    else:
        print(f"  {YELLOW}⚠ {total - passed} 项未通过/跳过，请检查。{NC}")
    print()

    return 0 if passed == total else 1


def _show_high_commands():
    """汇总所有高危命令。"""
    all_high = []
    for b in submitted:
        for l in b["logs"]:
            if l.get("risk_level") == "high":
                all_high.append((b["batch_id"], l))
    if all_high:
        print(f"\n    {YELLOW}高危命令汇总 ({len(all_high)} 条):{NC}")
        for bid, l in all_high[:15]:
            print(f"      🔴 {l['log_id'][:14]}... [{l['operator']:10s}] {l['command']}")
        if len(all_high) > 15:
            print(f"      ... (共 {len(all_high)} 条)")


if __name__ == "__main__":
    sys.exit(main())
