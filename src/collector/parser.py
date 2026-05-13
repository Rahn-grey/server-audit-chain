"""日志解析器 — 将各种原始日志格式转换为标准审计格式。

支持的格式:
    raw        — 原始 shell 记录格式: TIMESTAMP|USER|IP|COMMAND|RESULT
    syslog     — rsyslog 格式: <PRI>TIMESTAMP HOSTNAME USER: COMMAND
    bastion    — 堡垒机 JSON 格式: {"user":"...","cmd":"...","time":"..."}
    auditd     — Linux auditd 格式 (type=EXECVE 记录)
"""

import hashlib
import json
import logging
import re
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def classify_risk(command: str) -> str:
    """根据命令内容自动判定风险等级。

    高危关键词: rm -rf, dd, mkfs, fdisk, iptables -F, shutdown, chmod 777, sudo -u root
    中危关键词: systemctl restart, chmod, chown, useradd, usermod, passwd, sysctl
    其余: normal
    """
    cmd_lower = command.strip().lower()

    high_patterns = [
        "rm -rf", "rm -r /", "dd if=", "mkfs.", "fdisk ",
        "iptables -f", "kill -9", "shutdown", "chmod 777",
        "> /dev/sd", "mkfs.ext", "sudo -u root",
        "/etc/shadow", "/etc/sudoers",
    ]
    medium_patterns = [
        "systemctl restart", "systemctl reload", "service ",
        "chmod ", "chown ", "useradd ", "usermod ",
        "passwd ", "sysctl ", "systemctl daemon-reload",
        "docker restart", "docker stop",
    ]

    for p in high_patterns:
        if p in cmd_lower:
            return "high"
    for p in medium_patterns:
        if p in cmd_lower:
            return "medium"
    return "normal"


def make_log_id(timestamp: str, user: str, command: str) -> str:
    """生成日志唯一ID — SHA256(timestamp + user + command) 前16字符。"""
    raw = f"{timestamp}{user}{command}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


# ---------------------------------------------------------------------------
# 格式解析器
# ---------------------------------------------------------------------------

def parse_raw(line: str) -> dict | None:
    """解析管道分隔的原始格式。

    格式: TIMESTAMP|USER|IP|COMMAND|RESULT
    示例: 2026-05-13T14:30:00+00:00|zhangsan|192.168.1.10|rm -rf /tmp/*|success
    """
    try:
        parts = [p.strip() for p in line.strip().split("|")]
        if len(parts) < 5:
            return None
        timestamp, user, ip, command, result = parts[:5]
        risk = classify_risk(command)
        log_id = make_log_id(timestamp, user, command)
        return {
            "log_id": log_id,
            "operator": user,
            "ip": ip,
            "command": command,
            "target": _infer_target(command),
            "result": result,
            "risk_level": risk,
            "timestamp": timestamp,
        }
    except Exception:
        return None


def parse_syslog(line: str) -> dict | None:
    """解析 rsyslog 格式。

    格式: <PRI>TIMESTAMP HOSTNAME USER: COMMAND
    示例: <13>May 13 14:30:00 server01 zhangsan: rm -rf /tmp/*
    """
    try:
        stripped = line.strip()
        # 去掉 <PRI> 前缀
        if stripped.startswith("<"):
            idx = stripped.index(">")
            stripped = stripped[idx + 1 :].strip()

        # 尝试匹配: TIMESTAMP HOSTNAME USER: COMMAND
        match = re.match(
            r"(\S+\s+\d+\s+\S+)\s+(\S+)\s+(\S+):\s+(.+)", stripped
        )
        if match:
            ts_raw, hostname, user, command = match.groups()
            # 转换为 ISO 8601
            try:
                dt = datetime.strptime(ts_raw, "%b %d %H:%M:%S")
                dt = dt.replace(year=datetime.now().year, tzinfo=timezone.utc)
                timestamp = dt.isoformat()
            except ValueError:
                timestamp = datetime.now(timezone.utc).isoformat()

            risk = classify_risk(command)
            log_id = make_log_id(timestamp, user, command)
            return {
                "log_id": log_id,
                "operator": user,
                "ip": hostname,
                "command": command,
                "target": _infer_target(command),
                "result": "unknown",
                "risk_level": risk,
                "timestamp": timestamp,
            }
        return None
    except Exception:
        return None


def parse_bastion(data: dict | str) -> list[dict] | dict | None:
    """解析堡垒机上传的 JSON 格式。

    支持两种堡垒机JSON格式:

    格式A（单条）:
        {"user": "zhangsan", "ip": "10.0.0.1",
         "cmd": "rm -rf /tmp/*", "time": "2026-05-13T14:30:00Z"}

    格式B（批量）:
        {"host": "bastion-01", "records": [
            {"user": "...", "ip": "...", "cmd": "...", "time": "..."}, ...]}

    返回: 单个 dict 或 dict 列表，失败时返回 None。
    """
    try:
        if isinstance(data, str):
            data = json.loads(data)

        # 批量格式
        if "records" in data:
            host = data.get("host", "unknown")
            records = data["records"]
            results = []
            for rec in records:
                parsed = _parse_bastion_single(rec, host)
                if parsed:
                    results.append(parsed)
            return results if results else None

        # 单条格式
        host = data.get("host", data.get("ip", "unknown"))
        return _parse_bastion_single(data, host)
    except (json.JSONDecodeError, TypeError, KeyError):
        return None


def _parse_bastion_single(rec: dict, host: str = "unknown") -> dict | None:
    """解析堡垒机单条记录。"""
    try:
        user = rec.get("user", rec.get("operator", ""))
        ip = rec.get("ip", rec.get("src_ip", host))
        command = rec.get("cmd", rec.get("command", ""))
        timestamp = rec.get("time", rec.get("timestamp",
                       datetime.now(timezone.utc).isoformat()))
        result = rec.get("result", rec.get("exit_code", "unknown"))
        if isinstance(result, int):
            result = "success" if result == 0 else "failed"

        if not user or not command:
            return None

        risk = classify_risk(command)
        log_id = make_log_id(timestamp, user, command)
        return {
            "log_id": log_id,
            "operator": user,
            "ip": ip,
            "command": command,
            "target": _infer_target(command),
            "result": str(result),
            "risk_level": risk,
            "timestamp": timestamp,
        }
    except Exception:
        return None


def parse_auto(line_or_data):
    """自动检测格式并解析。

    返回 list[dict] | dict | None。
    """
    if isinstance(line_or_data, dict):
        return parse_bastion(line_or_data)
    if isinstance(line_or_data, str):
        if line_or_data.strip().startswith("{"):
            return parse_bastion(line_or_data)
        if line_or_data.strip().startswith("<"):
            return parse_syslog(line_or_data)
        if "|" in line_or_data:
            return parse_raw(line_or_data)
        # 尝试作为 JSON 解析
        try:
            data = json.loads(line_or_data)
            if isinstance(data, dict):
                return parse_bastion(data)
        except (json.JSONDecodeError, TypeError):
            pass
    return None


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def _infer_target(command: str) -> str:
    """从命令中推断操作目标路径。"""
    parts = command.strip().split()
    for i, p in enumerate(parts):
        if p.startswith("/") and len(p) > 1:
            return p
        if p.startswith("./") or p.startswith("../"):
            return p
    return "unknown"
