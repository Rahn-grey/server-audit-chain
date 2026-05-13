"""Debug模式模拟数据生成器。

为Debug模式提供一键生成模拟操作日志的功能，
无需真实堡垒机和Fluentd环境。
"""

import hashlib
import random
import time
from datetime import datetime, timedelta, timezone

_operators = [
    "zhangsan", "lisi", "wangwu", "zhaoliu", "sunqi",
    "zhouba", "wujiu", "zhengshi",
]

_normal_commands = [
    "ls -la /data/app/logs/",
    "cat /var/log/nginx/access.log | tail -100",
    "grep 'ERROR' /var/log/app/application.log",
    "tail -f /var/log/syslog",
    "ps aux | grep java",
    "df -h",
    "free -m",
    "top -bn1",
    "netstat -tlnp",
    "du -sh /data/app/",
    "systemctl status nginx",
    "journalctl -u docker -n 50",
    "curl -s http://localhost:8080/health",
    "ping -c 4 8.8.8.8",
    "uptime",
    "who",
    "last | head -20",
]

_medium_commands = [
    "sudo systemctl restart nginx",
    "sudo systemctl reload docker",
    "chmod 755 /data/app/scripts/*.sh",
    "chown -R app:app /data/app/",
    "useradd -m -s /bin/bash deployer",
    "usermod -aG docker jenkins",
    "passwd -l tempuser",
    "sudo service rsyslog restart",
    "sudo systemctl daemon-reload",
    "sysctl -w vm.swappiness=10",
]

_high_commands = [
    "rm -rf /data/temp/*",
    "sudo rm -rf /var/log/old/",
    "dd if=/dev/zero of=/tmp/test bs=1M count=1024",
    "mkfs.ext4 /dev/sdb1",
    "fdisk /dev/sda",
    "sudo iptables -F",
    "kill -9 12345",
    "sudo shutdown -r now",
    "sudo visudo",
    "chmod 777 /etc/shadow",
    "sudo -u root 'echo ALL ALL=(ALL) NOPASSWD:ALL >> /etc/sudoers'",
]

_risk_weights = {
    "normal": _normal_commands,
    "medium": _medium_commands,
    "high": _high_commands,
}

_targets_normal = [
    "/data/app/logs/", "/var/log/nginx/", "/var/log/app/",
    "/var/log/syslog", "/data/app/", "/etc/nginx/",
]

_targets_medium = [
    "/data/app/scripts/", "/etc/systemd/system/",
    "/etc/docker/", "/etc/nginx/",
]

_targets_high = [
    "/data/temp/", "/var/log/old/", "/dev/sda",
    "/etc/shadow", "/etc/sudoers", "/etc/iptables/",
]


def generate_operators(num: int = 5) -> list[str]:
    """生成模拟操作者名单。"""
    return _operators[:num]


def generate_command(risk_level: str = "normal") -> str:
    """根据风险等级生成模拟命令。

    Args:
        risk_level: normal | medium | high

    Returns:
        模拟命令字符串。
    """
    pool = _risk_weights.get(risk_level, _normal_commands)
    return random.choice(pool)


def _select_target(risk_level: str) -> str:
    if risk_level == "high":
        return random.choice(_targets_high)
    elif risk_level == "medium":
        return random.choice(_targets_medium)
    return random.choice(_targets_normal)


def generate_log_entry(operator: str | None = None,
                       risk_level: str = "normal",
                       timestamp: str | None = None) -> dict:
    """生成单条模拟日志。

    Args:
        operator: 操作者，不指定则随机选。
        risk_level: normal | medium | high
        timestamp: ISO 8601时间戳，不指定则自动生成。

    Returns:
        包含日志字段的字典。
    """
    if operator is None:
        operator = random.choice(_operators)
    command = generate_command(risk_level)
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()

    raw = f"{timestamp}{operator}{command}".encode()
    log_id = hashlib.sha256(raw).hexdigest()[:16]

    return {
        "log_id": log_id,
        "operator": operator,
        "ip": f"192.168.1.{random.randint(1, 254)}",
        "command": command,
        "target": _select_target(risk_level),
        "result": random.choice(["success", "success", "success", "failed"]),
        "risk_level": risk_level,
        "timestamp": timestamp,
    }


def generate_batch(batch_id: str, log_count: int = 100,
                   risk_mix: bool = True) -> list[dict]:
    """生成一个批次的模拟日志。

    Args:
        batch_id: 批次标识。
        log_count: 日志条数。
        risk_mix: True时混合风险等级（90%常规、8%敏感、2%高危）。

    Returns:
        日志字典列表。
    """
    logs = []
    for i in range(log_count):
        if risk_mix:
            r = random.random()
            if r < 0.90:
                risk = "normal"
            elif r < 0.98:
                risk = "medium"
            else:
                risk = "high"
        else:
            risk = "normal"

        # 在批次时间窗口内分布时间
        base_time = datetime.now(timezone.utc) - timedelta(hours=1)
        entry_time = base_time + timedelta(seconds=i * 0.3)
        operator = random.choice(_operators)

        log = generate_log_entry(
            operator=operator,
            risk_level=risk,
            timestamp=entry_time.isoformat(),
        )
        log["batch_id"] = batch_id
        logs.append(log)

    return logs


def generate_multi_batch(num_batches: int = 10,
                         logs_per_batch: int = 100) -> list[tuple[str, list[dict]]]:
    """生成多个连续批次的模拟日志。

    Args:
        num_batches: 批次数。
        logs_per_batch: 每批日志数。

    Returns:
        [(batch_id, logs), ...] 列表。
    """
    batches = []
    now = datetime.now(timezone.utc)

    for i in range(num_batches):
        batch_time = now - timedelta(minutes=(num_batches - i) * 5)
        batch_id = f"batch_{batch_time.strftime('%Y%m%d_%H%M')}"
        logs = generate_batch(batch_id, logs_per_batch)
        batches.append((batch_id, logs))

    return batches
