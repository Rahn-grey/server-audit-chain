"""堡垒机日志接收器 — 提供 HTTP 端点，等待堡垒机上传日志。

提供两个接口:
    POST /collector/bastion/upload   — 堡垒机上传单条或批量日志
    POST /collector/bastion/push     — 堡垒机批量推送（格式B）

也支持极简模式（不使用 Flask）通过内置 HTTP 服务器运行。

堡垒机推送的数据格式示例:

单条:
    {"user": "zhangsan", "ip": "10.0.0.1",
     "cmd": "rm -rf /tmp/*", "time": "2026-05-13T14:30:00Z"}

批量:
    {"host": "bastion-01", "records": [
        {"user": "...", "ip": "...", "cmd": "...", "time": "..."}, ...]}
"""

import json
import logging
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

from src.collector.parser import parse_auto

logger = logging.getLogger(__name__)


class BastionReceiver:
    """堡垒机日志接收器。

    启动一个轻量 HTTP 服务器，接受堡垒机推送日志。
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 5001,
                 forwarder=None):
        self._host = host
        self._port = port
        self._forwarder = forwarder  # 可选：收到日志直接转交 forwarder
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._received_count = 0

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------

    def start(self):
        """启动 HTTP 服务器（后台线程）。"""
        if self._running:
            return
        self._running = True

        handler = self._make_handler()

        self._server = HTTPServer((self._host, self._port), handler)
        self._thread = threading.Thread(target=self._serve, daemon=True,
                                        name="bastion-recv")
        self._thread.start()
        logger.info("堡垒机接收器已启动: http://%s:%d", self._host, self._port)

    def stop(self):
        """停止 HTTP 服务器。"""
        self._running = False
        if self._server:
            self._server.shutdown()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        logger.info("堡垒机接收器已停止，共接收 %d 条日志", self._received_count)

    def _serve(self):
        """服务器循环。"""
        try:
            self._server.serve_forever(poll_interval=0.5)
        except Exception as e:
            logger.error("堡垒机接收器异常: %s", e)

    # ------------------------------------------------------------------
    # 内部
    # ------------------------------------------------------------------

    def _make_handler(self):
        """创建请求处理器类（闭包绑定 self）。"""
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                logger.debug("bastion http: %s", fmt % args)

            def do_POST(self):
                if self.path not in ("/collector/bastion/upload",
                                     "/collector/bastion/push",
                                     "/bastion/upload", "/bastion/push"):
                    self.send_error(404, "not found")
                    return

                try:
                    content_length = int(self.headers.get("Content-Length", 0))
                    raw_body = self.rfile.read(content_length)
                    body = raw_body.decode("utf-8", errors="replace")
                    data = json.loads(body)
                except json.JSONDecodeError:
                    self.send_error(400, "invalid json")
                    return

                entries = parse_auto(data)

                if entries is None:
                    self.send_error(400, "unsupported format")
                    return

                if isinstance(entries, dict):
                    entries = [entries]

                # 转发到 forwarder
                if outer._forwarder:
                    outer._forwarder.extend(entries)
                outer._received_count += len(entries)

                resp = {
                    "status": "ok",
                    "received": len(entries),
                    "total_received": outer._received_count,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                resp_bytes = json.dumps(resp).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_bytes)))
                self.end_headers()
                self.wfile.write(resp_bytes)

            def do_GET(self):
                if self.path in ("/collector/bastion/health",
                                 "/bastion/health", "/health"):
                    resp = {"status": "healthy",
                            "received_count": outer._received_count}
                    resp_bytes = json.dumps(resp).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(resp_bytes)))
                    self.end_headers()
                    self.wfile.write(resp_bytes)
                else:
                    self.send_error(404, "not found")

        return _Handler

    @property
    def received_count(self) -> int:
        return self._received_count
