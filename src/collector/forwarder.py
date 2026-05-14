from __future__ import annotations
"""HTTP 转发器 — 将收集到的日志批量提交到审计 API。

自适应批处理:
    - 5分钟时间窗口为硬上限，到达必定提交
    - 批次数目阈值根据命令到达速率动态调整:
        高流量 (>= 2条/秒) → 攒到 300 条才提交（省交易费）
        中流量 (>=0.5条/秒) → 攒到 50 条提交
        低流量 (< 0.5条/秒) → 攒到 10 条就提交（尽快上链）
"""

import json
import logging
import threading
import time
import urllib.request
import urllib.error
from collections import deque
from datetime import datetime, timezone

from src.collector.config import (
    COLLECTOR_API_URL,
    COLLECTOR_BATCH_SECS,
)

logger = logging.getLogger(__name__)

# 自适应阈值
RATE_WINDOW_SECS = 30      # 速率采样窗口 30 秒
THRESHOLD_FAST = 300       # 高流量时的条数阈值
THRESHOLD_MEDIUM = 50      # 中流量
THRESHOLD_SLOW = 10        # 低流量
RATE_FAST = 2.0            # >= 2条/秒 视为高流量
RATE_MEDIUM = 0.5          # >= 0.5条/秒 视为中流量


class BatchForwarder:
    """自适应批次转发器。"""

    def __init__(self, api_url: str | None = None,
                 batch_secs: int | None = None,
                 threshold_fast: int | None = None,
                 threshold_medium: int | None = None,
                 threshold_slow: int | None = None,
                 max_batch: int | None = None):
        self._api_url = api_url or COLLECTOR_API_URL
        self._batch_secs = batch_secs or COLLECTOR_BATCH_SECS
        # max_batch 快捷参数：同时设置三档为同一值
        if max_batch is not None:
            self._threshold_fast = max_batch
            self._threshold_medium = max_batch
            self._threshold_slow = max_batch
        else:
            self._threshold_fast = threshold_fast or THRESHOLD_FAST
            self._threshold_medium = threshold_medium or THRESHOLD_MEDIUM
            self._threshold_slow = threshold_slow or THRESHOLD_SLOW

        self._buffer: list[dict] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None
        self._submit_history: list[dict] = []

        # 速率跟踪
        self._arrival_timestamps: deque[float] = deque()
        self._last_submit_time = time.time()

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._submit_loop,
                                        daemon=True, name="fwder")
        self._thread.start()
        logger.info("转发器已启动: api=%s, batch_secs=%d, "
                    "threshold(fast=%d, medium=%d, slow=%d)",
                    self._api_url, self._batch_secs,
                    self._threshold_fast, self._threshold_medium,
                    self._threshold_slow)

    def stop(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10.0)
        self._flush()
        logger.info("转发器已停止，共提交 %d 批次", len(self._submit_history))

    # ------------------------------------------------------------------
    # 日志追加 (带速率追踪)
    # ------------------------------------------------------------------

    def append(self, entry: dict):
        with self._lock:
            self._buffer.append(entry)
            self._arrival_timestamps.append(time.time())
        self._maybe_alert(entry)

    def extend(self, entries: list[dict]):
        now = time.time()
        with self._lock:
            self._buffer.extend(entries)
            for _ in entries:
                self._arrival_timestamps.append(now)
        self._maybe_alert_batch(entries)

    def set_alert_engine(self, engine):
        self._alert_engine = engine

    def _maybe_alert(self, entry: dict):
        eng = getattr(self, "_alert_engine", None)
        if eng:
            try:
                eng.check_and_alert(entry)
            except Exception as e:
                logger.warning("告警异常: %s", e)

    def _maybe_alert_batch(self, entries: list[dict]):
        eng = getattr(self, "_alert_engine", None)
        if eng:
            try:
                eng.check_batch_and_alert(entries)
            except Exception as e:
                logger.warning("告警异常: %s", e)

    # ------------------------------------------------------------------
    # 速率计算
    # ------------------------------------------------------------------

    def _compute_rate(self) -> float:
        """计算最近 30 秒的命令到达速率（条/秒）。"""
        now = time.time()
        cutoff = now - RATE_WINDOW_SECS
        # 清理过期的采样点
        while self._arrival_timestamps and self._arrival_timestamps[0] < cutoff:
            self._arrival_timestamps.popleft()
        count = len(self._arrival_timestamps)
        return count / RATE_WINDOW_SECS if count > 0 else 0.0

    def _current_threshold(self) -> int:
        """根据当前速率返回应使用的条数阈值。"""
        rate = self._compute_rate()
        if rate >= RATE_FAST:
            return self._threshold_fast
        elif rate >= RATE_MEDIUM:
            return self._threshold_medium
        else:
            return self._threshold_slow

    # ------------------------------------------------------------------
    # 提交控制
    # ------------------------------------------------------------------

    def _submit_loop(self):
        """自适应提交循环。"""
        while self._running:
            elapsed = time.time() - self._last_submit_time
            buf_size = len(self._buffer)
            threshold = self._current_threshold()

            should_submit = False
            reason = ""

            # 条件1: 时间窗口到期
            if elapsed >= self._batch_secs and buf_size > 0:
                should_submit = True
                reason = "time_window"

            # 条件2: 条数达到当前速率对应的阈值
            elif buf_size >= threshold:
                should_submit = True
                reason = f"count_{threshold}"

            if should_submit:
                rate = self._compute_rate()
                logger.info("触发提交: %s (buf=%d, rate=%.1f/s, elapsed=%ds)",
                            reason, buf_size, rate, int(elapsed))
                self._flush()
                self._last_submit_time = time.time()

            time.sleep(1)

    def _flush(self):
        with self._lock:
            if not self._buffer:
                return
            batch = self._buffer[:]
            self._buffer.clear()

        result = self._submit(batch)
        self._submit_history.append(result)

        count = result.get("log_count", len(batch))
        rh = result.get("record_hash", "N/A")
        bid = result.get("batch_id", "N/A")
        if result.get("success"):
            logger.info("批次提交成功: batch_id=%s, count=%d, record_hash=%s",
                        bid, count, rh)
        else:
            logger.error("批次提交失败: batch_id=%s, error=%s",
                         bid, result.get("error", "unknown"))

    def _submit(self, batch: list[dict]) -> dict:
        batch_id = f"batch_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')}"

        for entry in batch:
            entry.setdefault("batch_id", batch_id)

        payload = json.dumps({"batch_id": batch_id, "logs": batch})

        try:
            req = urllib.request.Request(
                self._api_url,
                data=payload.encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                resp_data["success"] = True
                return resp_data
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return {"success": False, "error": f"HTTP {e.code}: {body}",
                    "batch_id": batch_id, "log_count": len(batch)}
        except Exception as e:
            return {"success": False, "error": str(e),
                    "batch_id": batch_id, "log_count": len(batch)}

    def flush_now(self) -> dict:
        return self._flush()

    @property
    def buffer_size(self) -> int:
        return len(self._buffer)

    @property
    def submit_history(self) -> list[dict]:
        return self._submit_history[:]

    @property
    def current_rate(self) -> float:
        with self._lock:
            return self._compute_rate()
