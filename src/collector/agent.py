from __future__ import annotations
"""采集代理 — 主调度器。

协调日志文件监听、堡垒机接收、解析和转发。

用法:
    # 直接采集模式
    python -m src.collector.agent --mode direct --log-file /var/log/commands.log

    # 堡垒机接收模式
    python -m src.collector.agent --mode bastion --listen-port 5001

    # 混合模式
    python -m src.collector.agent --mode both

    # Debug演示模式（自动生成模拟日志 + 直接采集）
    python -m src.collector.agent --mode demo
"""

import argparse
import logging
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from src.collector.config import (
    COLLECTOR_MODE,
    COLLECTOR_LOG_FILE,
    COLLECTOR_LISTEN_HOST,
    COLLECTOR_LISTEN_PORT,
)
from src.collector.forwarder import BatchForwarder
from src.collector.parser import parse_auto
from src.collector.receiver import BastionReceiver
from src.collector.watcher import LogWatcher

logger = logging.getLogger(__name__)


class CollectorAgent:
    """采集代理主控。

    职责:
        1. 根据模式启动 watcher / receiver / demo 生成器
        2. 将收集到的日志条目交给 forwarder
        3. forwarder 达批次阈值后自动提交到审计 API
    """

    def __init__(self, mode: str = "direct",
                 log_file: str | None = None,
                 api_url: str | None = None,
                 listen_host: str | None = None,
                 listen_port: int | None = None,
                 batch_secs: int | None = None,
                 threshold_fast: int | None = None,
                 threshold_medium: int | None = None,
                 threshold_slow: int | None = None):
        self._mode = mode
        self._log_file = log_file or COLLECTOR_LOG_FILE
        self._listen_host = listen_host or COLLECTOR_LISTEN_HOST
        self._listen_port = listen_port or COLLECTOR_LISTEN_PORT
        self._forwarder = BatchForwarder(
            api_url=api_url,
            batch_secs=batch_secs,
            threshold_fast=threshold_fast,
            threshold_medium=threshold_medium,
            threshold_slow=threshold_slow,
        )
        self._watcher: LogWatcher | None = None
        self._receiver: BastionReceiver | None = None
        self._running = False

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------

    def start(self):
        """启动采集代理。"""
        if self._running:
            return
        self._running = True

        # 1. 转发器始终启动
        self._forwarder.start()

        # 2. 根据模式启动采集源
        if self._mode in ("direct", "both"):
            self._start_watcher()

        if self._mode in ("bastion", "both"):
            self._start_receiver()

        if self._mode == "demo":
            self._start_demo()

        logger.info("采集代理已启动: mode=%s", self._mode)

    def stop(self):
        """停止采集代理。"""
        self._running = False

        if self._watcher:
            self._watcher.stop()
        if self._receiver:
            self._receiver.stop()

        self._forwarder.stop()
        logger.info("采集代理已停止")

    def run_forever(self):
        """运行直到收到终止信号。"""
        self.start()
        print()
        print("=" * 50)
        print(f"  采集代理运行中  mode={self._mode}")
        print(f"  API地址: {self._forwarder._api_url}")
        if self._mode in ("direct", "both"):
            print(f"  监听日志: {self._log_file}")
        if self._mode in ("bastion", "both"):
            print(f"  堡垒机接收: http://{self._listen_host}:{self._listen_port}")
        print("  Ctrl+C 停止")
        print("=" * 50)
        print()

        def _handler(sig, frame):
            logger.info("收到信号 %s，正在停止...", sig)
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)

        try:
            while self._running:
                time.sleep(1)
                # 定时输出状态
        except KeyboardInterrupt:
            self.stop()

    # ------------------------------------------------------------------
    # 内部
    # ------------------------------------------------------------------

    def _start_watcher(self):
        """启动文件监听器，收集到的日志转交 forwarder。"""
        # 确保日志文件存在
        log_path = Path(self._log_file)
        if not log_path.exists():
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.touch()
            logger.info("创建日志文件: %s", self._log_file)

        self._watcher = LogWatcher(self._log_file)
        self._watcher.start()

        # 消费者线程：watcher → forwarder
        import threading
        def _route():
            for entry in self._watcher.iter_entries():
                if self._forwarder:
                    self._forwarder.append(entry)
        t = threading.Thread(target=_route, daemon=True, name="watcher-route")
        t.start()

    def _start_receiver(self):
        """启动堡垒机接收器。"""
        self._receiver = BastionReceiver(
            host=self._listen_host,
            port=self._listen_port,
            forwarder=self._forwarder,  # 直接对接
        )
        self._receiver.start()

    def _start_demo(self):
        """Demo模式 — 使用内置数据生成器定时生成模拟日志。"""
        import threading
        from src.debug.data_generator import (
            generate_log_entry, _operators,
        )

        def _gen():
            count = 0
            while self._running:
                entry = generate_log_entry()
                entry["batch_id"] = None  # forwarder 会填充
                if self._forwarder:
                    self._forwarder.append(entry)
                count += 1
                if count % 50 == 0:
                    logger.info("Demo模式: 已生成 %d 条模拟日志", count)
                time.sleep(2)  # 每 2 秒一条

        t = threading.Thread(target=_gen, daemon=True, name="demo-gen")
        t.start()
        logger.info("Demo模式: 模拟日志生成器已启动 (2s/条)")


# ======================================================================
# 入口
# ======================================================================

def main():
    parser = argparse.ArgumentParser(
        description="日志采集代理 — 直接采集 / 堡垒机接收",
    )
    parser.add_argument("--mode", choices=["direct", "bastion", "both", "demo"],
                        default=COLLECTOR_MODE,
                        help="采集模式 (default: %(default)s)")
    parser.add_argument("--log-file", default=COLLECTOR_LOG_FILE,
                        help="监听日志文件路径 (direct/both 模式)")
    parser.add_argument("--api-url",
                        default="http://127.0.0.1:5000/api/v1/audit/batch",
                        help="审计 API 地址")
    parser.add_argument("--listen-host", default=COLLECTOR_LISTEN_HOST,
                        help="堡垒机接收监听地址")
    parser.add_argument("--listen-port", type=int, default=COLLECTOR_LISTEN_PORT,
                        help="堡垒机接收监听端口")
    parser.add_argument("--batch-secs", type=int, default=300,
                        help="批次时间窗口秒数")
    parser.add_argument("--threshold-fast", type=int, default=300,
                        help="高流量条数阈值")
    parser.add_argument("--threshold-medium", type=int, default=50,
                        help="中流量条数阈值")
    parser.add_argument("--threshold-slow", type=int, default=10,
                        help="低流量条数阈值")

    args = parser.parse_args()

    # 日志配置
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    agent = CollectorAgent(
        mode=args.mode,
        log_file=args.log_file,
        api_url=args.api_url,
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        batch_secs=args.batch_secs,
        threshold_fast=args.threshold_fast,
        threshold_medium=args.threshold_medium,
        threshold_slow=args.threshold_slow,
    )
    agent.run_forever()


if __name__ == "__main__":
    main()
