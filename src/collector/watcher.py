"""文件监听器 — 实时监听日志文件，捕获命令执行记录。

支持两种监听策略:
    - tail:   通过轮询 mtime + 文件指针增量读取（跨平台）
    - inotify:  Linux inotify 事件驱动（需 watchdog / pyinotify）
              不可用时自动回退到 tail 模式。
"""

import logging
import os
import queue
import threading
import time
from pathlib import Path

from src.collector.parser import parse_auto

logger = logging.getLogger(__name__)


class LogWatcher:
    """日志文件监听器。

    采用 tail 模式增量读取文件，新行到达时推入内部队列。
    消费者通过迭代器或回调获取解析后的日志条目。
    """

    def __init__(self, file_path: str, poll_interval: float = 0.5):
        self._file_path = file_path
        self._poll_interval = poll_interval
        self._queue: queue.Queue = queue.Queue()
        self._running = False
        self._thread: threading.Thread | None = None
        self._pos = 0    # 当前文件读取位置
        self._ino = None  # 跟踪 inode，检测日志轮转

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------

    def start(self):
        """启动监听线程。"""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._watch_loop, daemon=True,
                                        name="log-watcher")
        self._thread.start()
        logger.info("日志监听已启动: %s", self._file_path)

    def stop(self):
        """停止监听线程。"""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        logger.info("日志监听已停止: %s", self._file_path)

    # ------------------------------------------------------------------
    # 消费者接口
    # ------------------------------------------------------------------

    def iter_entries(self) -> "iter":
        """返回日志条目的迭代器（阻塞式）。"""
        while self._running or not self._queue.empty():
            try:
                entry = self._queue.get(timeout=0.5)
                if entry is None:
                    break
                yield entry
            except queue.Empty:
                continue

    def get_entries_nowait(self) -> list[dict]:
        """获取当前队列中所有条目（非阻塞）。"""
        entries = []
        while True:
            try:
                entries.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return entries

    def on_entry(self, callback: callable):
        """注册回调函数，每条新日志被解析后调用 callback(entry)。"""
        def _runner():
            for entry in self.iter_entries():
                callback(entry)
        t = threading.Thread(target=_runner, daemon=True, name="log-callback")
        t.start()

    # ------------------------------------------------------------------
    # 内部
    # ------------------------------------------------------------------

    def _watch_loop(self):
        """主监听循环 — 轮询文件变化。"""
        while self._running:
            self._tick()
            time.sleep(self._poll_interval)

    def _tick(self):
        """单次轮询 — 检测并读取新增行。"""
        path = Path(self._file_path)
        if not path.exists():
            return

        # 检测日志轮转（inode 变化）
        try:
            stat = path.stat()
            if self._ino is not None and stat.st_ino != self._ino:
                self._pos = 0
                logger.debug("检测到日志轮转，重置读取位置")
            self._ino = stat.st_ino
        except OSError:
            return

        # 增量读取
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                f.seek(0, os.SEEK_END)
                file_size = f.tell()
                if file_size < self._pos:
                    self._pos = 0
                if file_size > self._pos:
                    f.seek(self._pos)
                    new_data = f.read(file_size - self._pos)
                    self._pos = file_size
                    self._process_new_lines(new_data)
        except (IOError, OSError) as e:
            logger.warning("读取日志文件失败: %s", e)

    def _process_new_lines(self, text: str):
        """处理新读取的行，解析并推入队列。"""
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            entry = parse_auto(line)
            if entry is None:
                logger.debug("无法解析行: %s", line[:80])
                continue
            # parse_auto 可能返回单条或列表
            if isinstance(entry, list):
                for e in entry:
                    self._queue.put(e)
            else:
                self._queue.put(entry)

    def inject(self, line: str):
        """手动注入一行日志（用于测试）。"""
        self._process_new_lines(line)

    @property
    def file_path(self) -> str:
        return self._file_path

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()
