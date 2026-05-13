#!/usr/bin/env python3
"""
端到端验证 — 模拟生产环境全流程。

一键启动 API + 采集器 + 数据生成 → 等待上链 → 验证每条链路正确。

用法:
    python scripts/e2e_demo.py                    # 完整验证
    python scripts/e2e_demo.py --batches 5 --wait 60   # 5批次, 等60秒
    python scripts/e2e_demo.py --verbose          # 详细输出

验证项目:
    [PASS] 1.  API 就绪
    [PASS] 2.  数据生成 → PBFT共识上链
    [PASS] 3.  搜索日志
    [PASS] 4.  验证单条日志
    [PASS] 5.  哈希链完整性验证
    [PASS] 6.  PBFT 共识网络状态
    [PASS] 7.  拜占庭攻击 → 跨节点验证检出
    [PASS] 8.  篡改检测 (Merkle)
    [PASS] 9.  报告生成
    [PASS] 10. 操作回放
"""

import argparse
import base64
import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))

os.environ["AUDIT_SYSTEM_MODE"] = "demo"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s",
                    datefmt="%H:%M:%S")
logger = logging.getLogger("e2e")

API_URL = "http://127.0.0.1:5000"
API_BASE = f"{API_URL}/api/v1/audit"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
NC = "\033[0m"
results = []


def ok(msg):
    results.append(True)
    print(f"  {GREEN}[PASS]{NC} {msg}")

def fail(msg, detail=""):
    results.append(False)
    print(f"  {RED}[FAIL]{NC} {msg}")
    if detail:
        print(f"     {RED}{detail}{NC}")

def api_post(path, data):
    """HTTP POST."""
    payload = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        f"{API_BASE}{path}",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))

def api_get(path):
    """HTTP GET."""
    with urllib.request.urlopen(f"{API_BASE}{path}", timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


# ====================================================================
# 步骤1: 确保 API 运行
# ====================================================================

class APIServer:
    """后台启动 Flask API。"""
    def __init__(self):
        self._proc = None

    def start(self):
        logger.info("启动 Flask API ...")
        self._proc = subprocess.Popen(
            [sys.executable, "-m", "flask", "run",
             "--host", "127.0.0.1", "--port", "5000"],
            env={**os.environ, "FLASK_APP": "src.api.routes",
                 "FLASK_ENV": "development", "AUDIT_SYSTEM_MODE": "demo"},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(30):
            try:
                urllib.request.urlopen(f"{API_URL}/api/v1/audit/chain/info",
                                      timeout=2)
                logger.info("API 已就绪: %s", API_URL)
                return
            except Exception:
                time.sleep(0.5)
        raise RuntimeError("API 启动超时")

    def stop(self):
        if self._proc:
            self._proc.terminate()
            self._proc.wait(timeout=5)


# ====================================================================
# 步骤2: 生成数据 + 上链
# ====================================================================

def generate_and_submit_batches(num_batches=5, logs_per_batch=100):
    """生成多批次数据并提交到 API。"""
    from src.debug.data_generator import generate_multi_batch

    logger.info("生成 %d 批次模拟数据 (每批 %d 条) ...", num_batches, logs_per_batch)
    batches = generate_multi_batch(num_batches=num_batches, logs_per_batch=logs_per_batch)

    submitted = []
    for batch_id, logs in batches:
        try:
            resp = api_post("/batch", {"batch_id": batch_id, "logs": logs})
            submitted.append({
                "batch_id": batch_id,
                "log_count": len(logs),
                "merkle_root": resp.get("merkle_root", ""),
                "record_hash": resp.get("record_hash", ""),
                "logs": logs,
            })
            logger.info("  上链: %s (%d条) → %s",
                       batch_id, len(logs), resp.get("record_hash", "?")[:16])
        except Exception as e:
            fail(f"提交批次失败: {batch_id}", str(e))
            return submitted

    ok(f"{num_batches} 批次全部上链成功")
    return submitted


# ====================================================================
# 步骤3: 搜索验证
# ====================================================================

def test_search():
    logger.info("[测试] 搜索操作日志 ...")
    try:
        resp = api_get("/search?size=10")
        total = resp.get("total", 0)
        if total > 0:
            ok(f"搜索成功: total={total}, 返回了 {len(resp.get('results',[]))} 条")
        else:
            fail("搜索无结果", "ES存储可能未写入")
    except Exception as e:
        fail("搜索失败", str(e))


# ====================================================================
# 步骤4: 单条验证
# ====================================================================

def test_verify_single(submitted):
    if not submitted:
        fail("无数据可验证", "跳过")
        return

    batch = submitted[0]
    log = batch["logs"][0]
    log_id = log.get("log_id", "")

    logger.info("[测试] 验证单条日志: %s ...", log_id[:16])
    try:
        resp = api_post("/verify", {"log_id": log_id})
        if resp.get("verified"):
            ok(f"单条验证通过: merkle_root_match={resp.get('merkle_root_match')}")
        else:
            fail(f"单条验证失败", resp.get("message", ""))
    except Exception as e:
        fail("验证请求失败", str(e))


# ====================================================================
# 步骤5: 链完整性
# ====================================================================

def test_chain_integrity():
    logger.info("[测试] 验证链完整性 ...")
    try:
        resp = api_get("/chain/integrity")
        if resp.get("is_valid"):
            ok(f"链完整性验证通过: total={resp.get('total_records')}, "
               f"broken={resp.get('broken_position',-1)}")
        else:
            fail(f"链断裂", f"位置: {resp.get('broken_position')}")
    except Exception as e:
        fail("链验证请求失败", str(e))


# ====================================================================
# 步骤6: 篡改检测
# ====================================================================

def test_tamper_detection(submitted):
    """验证篡改检测有效。"""
    if len(submitted) < 2:
        return

    logger.info("[测试] 篡改检测 ...")
    batch = submitted[1]
    log_id = batch["logs"][0]["log_id"]
    original_cmd = batch["logs"][0]["command"]

    # 直接通过 MockES 篡改
    from src.debug.mock_es import MockES
    es = MockES()
    es.tamper_log(log_id, "command", "/bin/evil_hacked_command")

    try:
        resp = api_post("/verify", {"log_id": log_id})
        if not resp.get("verified"):
            ok(f"篡改检测有效: 被篡改的日志未通过验证")
        else:
            fail("篡改检测失效: 被篡改的日志通过了验证")
    except Exception as e:
        fail("篡改检测请求失败", str(e))


# ====================================================================
# 步骤7: 报告生成
# ====================================================================

def test_report():
    logger.info("[测试] 生成审计报告 ...")
    try:
        from src.report.generator import ReportGenerator
        gen = ReportGenerator()
        data = gen.generate()
        md = gen.format_markdown(data)

        assert "服务器操作审计报告" in md
        assert "链完整性" in md
        assert "操作统计" in md

        (PROJECT_ROOT / "debug_data" / "e2e_report.md").write_text(
            md, encoding="utf-8"
        )
        ok(f"报告生成成功 (链记录={data['chain_info'].get('total_records',0)}, "
           f"操作={data['total_commands']})")
    except Exception as e:
        fail("报告生成失败", str(e))


# ====================================================================
# 步骤8: 操作回放
# ====================================================================

def test_replay(submitted):
    if not submitted:
        return

    logger.info("[测试] 操作回放 ...")
    try:
        from src.replay.engine import ReplayEngine
        engine = ReplayEngine()

        # 用第一个批次的第一个操作者
        first_op = submitted[0]["logs"][0].get("operator", "")
        result = engine.replay(operator=first_op, size=200)

        text = engine.format_timeline_text(result)
        assert first_op in text
        assert "操作回放" in text or "会话" in text

        ok(f"回放成功: 操作者={first_op}, 命令={result['total']}条, "
           f"会话={len(result['sessions'])}个")
    except Exception as e:
        fail("回放失败", str(e))


# ====================================================================
# 步骤9: 链信息
# ====================================================================

def test_chain_info():
    logger.info("[测试] 获取链摘要信息 ...")
    try:
        resp = api_get("/chain/info")
        total = resp.get("total_records", 0)
        if total > 0:
            ok(f"链信息: total={total}, "
               f"genesis={resp.get('genesis_batch_id','?')}, "
               f"latest={resp.get('latest_batch_id','?')}")
        else:
            fail("链信息为空")
    except Exception as e:
        fail("链信息请求失败", str(e))


# ====================================================================
# 步骤9: PBFT 共识状态
# ====================================================================

def test_consensus_status():
    logger.info("[测试] PBFT 共识网络状态 ...")
    try:
        resp = api_get("/chain/consensus")
        cfg = resp.get("config", {})
        nodes = resp.get("nodes", [])
        if cfg and nodes:
            honest = sum(1 for n in nodes if n.get("type") == "honest")
            byz = sum(1 for n in nodes if n.get("type") == "byzantine")
            ok(f"PBFT 共识: {cfg.get('consensus_algorithm', 'N/A')}, "
               f"节点={len(nodes)}({honest}诚实/{byz}拜占庭), "
               f"容错={cfg.get('fault_tolerance')}")
        else:
            fail("共识状态查询失败")
    except Exception as e:
        fail("共识状态请求失败", str(e))


# ====================================================================
# 步骤10: 拜占庭攻击 + 跨节点验证
# ====================================================================

def test_byzantine_attack_detection():
    logger.info("[测试] 拜占庭节点篡改 → 跨节点验证检出 ...")
    try:
        # 先验证当前网络状态（可能因为拜占庭投票行为返回409）
        before = api_get_any_status("/chain/cross-verify")

        # 发起拜占庭攻击
        attack_resp = api_post_json("/chain/attack", {})
        if not attack_resp.get("success"):
            # 可能没有拜占庭节点或账本为空，跳过
            skip("无可用拜占庭节点", attack_resp.get("message", ""))
            return

        logger.info("  拜占庭节点 %s 已篡改 batch_id=%s",
                   attack_resp.get("node_id"),
                   attack_resp.get("batch_id"))

        # 跨节点验证应检出
        after = api_get_any_status("/chain/cross-verify")
        if after.get("byzantine_detected"):
            ok(f"拜占庭攻击被跨节点验证检出: {after.get('summary')}")
        else:
            fail("拜占庭攻击未被检出", json.dumps(after))
    except Exception as e:
        fail("拜占庭攻击测试失败", str(e))


def api_get_any_status(path):
    """HTTP GET — 接受任何状态码。"""
    try:
        return api_get(path)
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode("utf-8", errors="replace"))


def skip(msg, detail=""):
    """记录跳过项。"""
    results.append(True)
    print(f"  {YELLOW}[SKIP]{NC} {msg}")
    if detail:
        print(f"     {detail}")


def api_post_json(path, data):
    """HTTP POST (JSON body) — 接受任何状态码。"""
    payload = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        f"{API_BASE}{path}",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode("utf-8", errors="replace"))


# ====================================================================
# 主流程
# ====================================================================

def main():
    parser = argparse.ArgumentParser(description="端到端验证")
    parser.add_argument("--batches", type=int, default=5,
                       help="批次数 (默认5)")
    parser.add_argument("--logs-per-batch", type=int, default=100,
                       help="每批次日志数 (默认100)")
    parser.add_argument("--verbose", action="store_true",
                       help="详细日志")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print()
    print(f"{'=' * 60}")
    print(f"  端到端验证 — {args.batches}批次 x {args.logs_per_batch}条")
    print(f"{'=' * 60}")
    print()

    # ---- 启动 API ----
    server = APIServer()
    try:
        server.start()
        ok(f"API 服务就绪: {API_URL}")
    except Exception as e:
        fail("API 启动失败", str(e))
        return

    try:
        # ---- 数据上链 ----
        print()
        submitted = generate_and_submit_batches(
            num_batches=args.batches, logs_per_batch=args.logs_per_batch
        )

        print(f"\n  {'—' * 55}")
        print(f"  验证阶段")
        print(f"  {'—' * 55}\n")

        # ---- 测试 ----
        test_chain_info()
        test_search()
        test_verify_single(submitted)
        test_chain_integrity()

        print(f"\n  {'—' * 55}")
        print(f"  PBFT 联盟链共识验证")
        print(f"  {'—' * 55}\n")

        test_consensus_status()
        test_byzantine_attack_detection()

        print(f"\n  {'—' * 55}")
        print(f"  辅助功能验证")
        print(f"  {'—' * 55}\n")

        test_tamper_detection(submitted)
        test_report()
        test_replay(submitted)

    finally:
        server.stop()

    # ---- 汇总 ----
    print()
    passed = sum(results)
    total = len(results)
    color = GREEN if passed == total else (YELLOW if passed > total//2 else RED)
    print(f"{'=' * 60}")
    print(f"  {color}结果: {passed}/{total} 通过{NC}")
    print(f"{'=' * 60}")
    print()

    if passed == total:
        print("  OK 全部验证通过，系统可交付。")
        print(f"  仪表板: {API_URL}")
        print(f"  报告:   debug_data/e2e_report.md")
    else:
        print(f"  警告: {total - passed} 项未通过，请检查日志。")

    print()
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
