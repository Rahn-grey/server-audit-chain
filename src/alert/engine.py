from __future__ import annotations
"""告警引擎 — 判定风险等级并触发邮件告警。

集成点:
    - 采集层: collector/forwarder.py 收到日志后调 check_and_alert()
    - API层:   routes.py submit_batch 上链前调 check_batch_and_alert()
"""

import logging
import threading
from datetime import datetime, timezone

from src.alert.config import ALERT_MIN_LEVEL
from src.alert.notifier import MailNotifier

logger = logging.getLogger(__name__)

LEVEL_WEIGHT = {"normal": 0, "medium": 1, "high": 2}


class AlertEngine:
    """告警引擎。

    判定规则:
        - high:   立即单条告警
        - medium: 累积 5 条后批量告警，或 10 分钟后强制告警
        - normal: 不告警
    """

    def __init__(self, notifier: MailNotifier | None = None,
                 min_level: str | None = None,
                 batch_threshold: int = 5,
                 flush_interval_secs: int = 600):
        self._notifier = notifier or MailNotifier()
        self._min_level = min_level or ALERT_MIN_LEVEL
        self._min_weight = LEVEL_WEIGHT.get(self._min_level, 1)
        self._batch_threshold = batch_threshold
        self._flush_interval = flush_interval_secs

        self._buffer: list[dict] = []
        self._lock = threading.Lock()
        self._flush_timer: threading.Timer | None = None

    # ------------------------------------------------------------------
    # 核心入口
    # ------------------------------------------------------------------

    def check_and_alert(self, entry: dict) -> bool:
        """检查单条日志并触发告警。

        Args:
            entry: 日志条目（含 risk_level / operator / command 等字段）。

        Returns:
            是否发送了告警。
        """
        risk = entry.get("risk_level", "normal")
        weight = LEVEL_WEIGHT.get(risk, 0)

        if weight < self._min_weight:
            return False

        if risk == "high":
            # 高危：立即单独告警
            return self._notifier.send_alert(
                subject=f"[HIGH] {entry.get('operator')} 高危操作告警",
                body=self._notifier.format_alert_html(entry),
            )

        # medium：批量缓冲
        with self._lock:
            was_empty = len(self._buffer) == 0
            self._buffer.append(entry)
            count = len(self._buffer)

        # 刚放入第一条中危告警时，启动定时器（10分钟后强制冲刷）
        if was_empty:
            self._start_flush_timer()

        if count >= self._batch_threshold:
            self._flush()

        return True

    def check_batch_and_alert(self, entries: list[dict]):
        """批量检查并告警。"""
        for entry in entries:
            self.check_and_alert(entry)

    # ------------------------------------------------------------------
    # 缓冲冲刷
    # ------------------------------------------------------------------

    def _start_flush_timer(self):
        """启动定时冲刷（10分钟后强制发送中危批量告警）。"""
        self._cancel_flush_timer()
        self._flush_timer = threading.Timer(self._flush_interval, self._flush)
        self._flush_timer.daemon = True
        self._flush_timer.start()
        logger.debug("告警冲刷定时器已启动: %d 秒后强制发送", self._flush_interval)

    def _cancel_flush_timer(self):
        """取消定时冲刷。"""
        if self._flush_timer and self._flush_timer.is_alive():
            self._flush_timer.cancel()
            self._flush_timer = None

    def _flush(self):
        """冲刷缓冲区，发送批量告警邮件。"""
        self._cancel_flush_timer()

        with self._lock:
            if not self._buffer:
                return
            batch = self._buffer[:]
            self._buffer.clear()

        if batch:
            self._notifier.send_alert(
                subject=f"[BATCH] {len(batch)} 条中危操作告警",
                body=self._notifier.format_batch_alert_html(batch),
            )
            logger.info("批量告警已发送: %d 条", len(batch))

    def flush(self):
        """手动冲刷（外部调用）。"""
        self._flush()

    @property
    def buffer_size(self) -> int:
        return len(self._buffer)
