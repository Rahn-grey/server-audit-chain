"""采集层测试。"""

import json
import os
import tempfile
import time
from pathlib import Path

import pytest


# ====================================================================
# 日志解析器测试
# ====================================================================

class TestParser:
    def test_parse_raw_format(self):
        from src.collector.parser import parse_raw
        line = "2026-05-13T14:30:00+00:00|zhangsan|192.168.1.10|rm -rf /tmp/*|success"
        result = parse_raw(line)
        assert result is not None
        assert result["operator"] == "zhangsan"
        assert result["ip"] == "192.168.1.10"
        assert result["command"] == "rm -rf /tmp/*"
        assert result["result"] == "success"
        assert result["risk_level"] == "high"
        assert len(result["log_id"]) == 16
        assert result["target"] == "/tmp/*"

    def test_parse_raw_incomplete(self):
        from src.collector.parser import parse_raw
        assert parse_raw("only|three|fields") is None
        assert parse_raw("") is None

    def test_parse_raw_normal_command(self):
        from src.collector.parser import parse_raw
        line = "2026-05-13T14:30:00Z|lisi|10.0.0.1|ls -la /var/log/|success"
        result = parse_raw(line)
        assert result["risk_level"] == "normal"

    def test_classify_risk_high(self):
        from src.collector.parser import classify_risk
        assert classify_risk("rm -rf /data/temp/") == "high"
        assert classify_risk("sudo rm -rf /var/log/old/") == "high"
        assert classify_risk("dd if=/dev/zero of=/tmp/test") == "high"
        assert classify_risk("mkfs.ext4 /dev/sdb1") == "high"
        assert classify_risk("kill -9 12345") == "high"
        assert classify_risk("shutdown -r now") == "high"
        assert classify_risk("chmod 777 /etc/shadow") == "high"

    def test_classify_risk_medium(self):
        from src.collector.parser import classify_risk
        assert classify_risk("systemctl restart nginx") == "medium"
        assert classify_risk("chmod 755 script.sh") == "medium"
        assert classify_risk("chown -R app:app /data/") == "medium"
        assert classify_risk("useradd -m deployer") == "medium"
        assert classify_risk("passwd -l tempuser") == "medium"
        assert classify_risk("sysctl -w vm.swappiness=10") == "medium"

    def test_classify_risk_normal(self):
        from src.collector.parser import classify_risk
        assert classify_risk("ls -la") == "normal"
        assert classify_risk("cat /var/log/syslog") == "normal"
        assert classify_risk("df -h") == "normal"
        assert classify_risk("who") == "normal"

    def test_parse_syslog_format(self):
        from src.collector.parser import parse_syslog
        line = "<13>May 13 14:30:00 server01 zhangsan: rm -rf /tmp/*"
        result = parse_syslog(line)
        assert result is not None
        assert result["operator"] == "zhangsan"
        assert result["ip"] == "server01"
        assert result["command"] == "rm -rf /tmp/*"
        assert result["risk_level"] == "high"

    def test_parse_syslog_invalid(self):
        from src.collector.parser import parse_syslog
        assert parse_syslog("not a syslog line") is None

    def test_parse_bastion_single(self):
        from src.collector.parser import parse_bastion
        data = {
            "user": "zhangsan",
            "ip": "10.0.0.1",
            "cmd": "systemctl restart nginx",
            "time": "2026-05-13T14:30:00Z",
        }
        result = parse_bastion(data)
        assert result is not None
        assert result["operator"] == "zhangsan"
        assert result["command"] == "systemctl restart nginx"
        assert result["risk_level"] == "medium"

    def test_parse_bastion_batch(self):
        from src.collector.parser import parse_bastion
        data = {
            "host": "bastion-01",
            "records": [
                {"user": "zhangsan", "ip": "10.0.0.1",
                 "cmd": "ls -la", "time": "2026-05-13T14:30:00Z"},
                {"user": "lisi", "ip": "10.0.0.2",
                 "cmd": "rm -rf /tmp/*", "time": "2026-05-13T14:31:00Z"},
            ],
        }
        result = parse_bastion(data)
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["operator"] == "zhangsan"
        assert result[1]["operator"] == "lisi"

    def test_parse_bastion_json_string(self):
        from src.collector.parser import parse_bastion
        data = '{"user":"wangwu","ip":"10.0.0.3","cmd":"df -h","time":"2026-05-13T14:30:00Z"}'
        result = parse_bastion(data)
        assert result is not None
        assert result["operator"] == "wangwu"

    def test_parse_bastion_invalid(self):
        from src.collector.parser import parse_bastion
        assert parse_bastion({"foo": "bar"}) is None
        assert parse_bastion("not json") is None

    def test_parse_auto_raw(self):
        from src.collector.parser import parse_auto
        line = "2026-05-13T14:30:00Z|zhangsan|192.168.1.10|ls -la /tmp|success"
        result = parse_auto(line)
        assert result is not None
        assert result["operator"] == "zhangsan"

    def test_parse_auto_bastion_json(self):
        from src.collector.parser import parse_auto
        data = '{"user":"zhangsan","cmd":"whoami","time":"2026-05-13T14:30:00Z"}'
        result = parse_auto(data)
        assert result is not None
        assert result["operator"] == "zhangsan"

    def test_parse_auto_bastion_dict(self):
        from src.collector.parser import parse_auto
        data = {"user": "zhangsan", "cmd": "whoami"}
        result = parse_auto(data)
        assert result is not None
        assert result["operator"] == "zhangsan"

    def test_make_log_id_deterministic(self):
        from src.collector.parser import make_log_id
        id1 = make_log_id("2026-05-13T14:30:00Z", "zhangsan", "ls -la")
        id2 = make_log_id("2026-05-13T14:30:00Z", "zhangsan", "ls -la")
        assert id1 == id2
        assert len(id1) == 16

    def test_infer_target(self):
        from src.collector.parser import _infer_target
        assert _infer_target("rm -rf /data/temp/") == "/data/temp/"
        assert _infer_target("cat ./config.ini") == "./config.ini"
        assert _infer_target("whoami") == "unknown"


# ====================================================================
# 文件监听器测试
# ====================================================================

class TestLogWatcher:
    def test_inject_and_collect(self):
        from src.collector.watcher import LogWatcher
        w = LogWatcher("/tmp/test_audit.log")

        raw_line = "2026-05-13T14:30:00Z|zhangsan|192.168.1.10|rm -rf /tmp/*|success"
        w.inject(raw_line)
        entries = w.get_entries_nowait()
        assert len(entries) == 1
        assert entries[0]["operator"] == "zhangsan"
        assert entries[0]["risk_level"] == "high"

    def test_inject_invalid_line(self):
        from src.collector.watcher import LogWatcher
        w = LogWatcher("/tmp/test_audit.log")
        w.inject("this is garbage")
        assert len(w.get_entries_nowait()) == 0

    def test_inject_json_line(self):
        from src.collector.watcher import LogWatcher
        w = LogWatcher("/tmp/test_audit.log")
        json_line = '{"user":"lisi","cmd":"df -h","time":"2026-05-13T14:30:00Z","ip":"10.0.0.2"}'
        w.inject(json_line)
        entries = w.get_entries_nowait()
        assert len(entries) == 1
        assert entries[0]["operator"] == "lisi"

    def test_queue_size(self):
        from src.collector.watcher import LogWatcher
        w = LogWatcher("/tmp/test_audit.log")
        for i in range(10):
            w.inject(f"2026-05-13T14:30:0{i}Z|user{i}|10.0.0.{i}|cmd{i}|success")
        assert w.queue_size == 10

    def test_bastion_batch_line_injection(self):
        from src.collector.watcher import LogWatcher
        w = LogWatcher("/tmp/test_audit.log")
        batch = json.dumps({
            "host": "bastion-01",
            "records": [
                {"user": "u1", "cmd": "ls", "time": "2026-05-13T14:30:00Z", "ip": "1.1.1.1"},
                {"user": "u2", "cmd": "who", "time": "2026-05-13T14:30:01Z", "ip": "1.1.1.2"},
            ],
        })
        w.inject(batch)
        entries = w.get_entries_nowait()
        assert len(entries) == 2


# ====================================================================
# 转发器测试
# ====================================================================

class TestBatchForwarder:
    def test_append_and_buffer_size(self):
        from src.collector.forwarder import BatchForwarder
        fw = BatchForwarder(api_url="http://localhost:9999/test",
                          batch_secs=9999, max_batch=50)
        entry = {"log_id": "abc123", "operator": "zhangsan",
                 "command": "ls", "timestamp": "2026-05-13T14:30:00Z"}
        fw.append(entry)
        assert fw.buffer_size == 1
        fw.extend([entry] * 4)
        assert fw.buffer_size == 5

    def test_flush_empty(self):
        from src.collector.forwarder import BatchForwarder
        fw = BatchForwarder(api_url="http://localhost:9999/test")
        assert fw.buffer_size == 0
        # flush 空缓冲区不应报错
        fw._flush()

    def test_flush_produces_batch_id(self):
        from src.collector.forwarder import BatchForwarder
        fw = BatchForwarder(
            api_url="http://127.0.0.1:9999/nonexistent",
            batch_secs=9999,
            max_batch=2,
        )
        fw.append({"log_id": "a", "operator": "z", "command": "ls",
                    "timestamp": "2026-05-13T14:30:00Z"})
        fw._flush()
        history = fw.submit_history
        assert len(history) >= 1
        # 即使API不可达，也应有失败记录
        result = history[-1]
        assert result["success"] is False or "batch_id" in result

    def test_flush_attaches_batch_id(self):
        from src.collector.forwarder import BatchForwarder
        fw = BatchForwarder(
            api_url="http://127.0.0.1:9999/nonexistent",
            batch_secs=9999,
            max_batch=5,
        )
        entry = {"log_id": "a", "operator": "z", "command": "ls",
                 "timestamp": "2026-05-13T14:30:00Z"}
        fw.append(entry)
        fw._flush()
        assert entry.get("batch_id") is not None
        assert entry["batch_id"].startswith("batch_")

    def test_adaptive_threshold_slow_rate(self):
        """低流量应返回 slow 阈值（10）。"""
        from src.collector.forwarder import BatchForwarder
        fw = BatchForwarder(api_url="http://localhost:9999/test",
                          batch_secs=9999,
                          threshold_fast=300, threshold_medium=50,
                          threshold_slow=10)
        # 没有数据，速率为0 → slow
        assert fw._current_threshold() == 10

        # 追加1条（速率极低）→ 仍是 slow
        fw.append({"log_id": "x", "operator": "z", "command": "ls",
                    "timestamp": "2026-05-13T14:30:00Z"})
        assert fw._current_threshold() == 10

    def test_adaptive_threshold_medium_rate(self):
        """中流量应返回 medium 阈值（50）。"""
        from src.collector.forwarder import BatchForwarder
        import time
        fw = BatchForwarder(api_url="http://localhost:9999/test",
                          batch_secs=9999,
                          threshold_fast=300, threshold_medium=50,
                          threshold_slow=10)

        # 模拟 30 秒内 20 条 → 0.67条/秒 → medium
        entry = {"log_id": "x", "operator": "z", "command": "ls",
                 "timestamp": "2026-05-13T14:30:00Z"}
        for _ in range(20):
            fw.append(entry)
        assert fw._current_threshold() == 50

    def test_adaptive_threshold_fast_rate(self):
        """高流量应返回 fast 阈值（300）。"""
        from src.collector.forwarder import BatchForwarder
        fw = BatchForwarder(api_url="http://localhost:9999/test",
                          batch_secs=9999,
                          threshold_fast=300, threshold_medium=50,
                          threshold_slow=10)

        entry = {"log_id": "x", "operator": "z", "command": "ls",
                 "timestamp": "2026-05-13T14:30:00Z"}
        # 模拟 30 秒内 70 条 → 2.3条/秒 → fast
        for _ in range(70):
            fw.append(entry)
        assert fw._current_threshold() == 300

    def test_max_batch_shortcut_sets_all(self):
        """max_batch 参数应设置三档阈值相同。"""
        from src.collector.forwarder import BatchForwarder
        fw = BatchForwarder(api_url="http://localhost:9999/test",
                          batch_secs=9999, max_batch=25)
        assert fw._threshold_fast == 25
        assert fw._threshold_medium == 25
        assert fw._threshold_slow == 25

    def test_current_rate_zero(self):
        """空队列时速率应为0。"""
        from src.collector.forwarder import BatchForwarder
        fw = BatchForwarder(api_url="http://localhost:9999/test",
                          batch_secs=9999)
        assert fw.current_rate == 0.0


# ====================================================================
# 堡垒机接收器测试
# ====================================================================

class TestBastionReceiver:
    def test_receiver_init(self):
        from src.collector.receiver import BastionReceiver
        recv = BastionReceiver(host="127.0.0.1", port=19999)
        assert recv.received_count == 0
        assert recv._host == "127.0.0.1"
        assert recv._port == 19999

    def test_receiver_with_forwarder(self):
        from src.collector.forwarder import BatchForwarder
        from src.collector.receiver import BastionReceiver
        fw = BatchForwarder(api_url="http://localhost:9999/nonexistent",
                          batch_secs=9999)
        recv = BastionReceiver(host="127.0.0.1", port=19998,
                              forwarder=fw)
        assert recv._forwarder is fw


# ====================================================================
# 端到端测试
# ====================================================================

class TestCollectorE2E:
    """端到端：采集 → 解析 → 转发。"""

    def test_watcher_to_forwarder(self):
        """日志进入 watcher 后经过解析直达 forwarder 缓冲区。"""
        from src.collector.watcher import LogWatcher
        from src.collector.forwarder import BatchForwarder

        fw = BatchForwarder(api_url="http://localhost:9999/nonexistent",
                          batch_secs=9999, max_batch=50)
        w = LogWatcher("/tmp/test_audit_e2e.log")

        # 注入一批日志
        for i in range(10):
            w.inject(
                f"2026-05-13T14:30:{i:02d}Z|user_{i}|10.0.0.{i}|cmd_{i}|success"
            )
        entries = w.get_entries_nowait()
        assert len(entries) == 10

        # 推入 forwarder
        fw.extend(entries)
        assert fw.buffer_size == 10
        assert entries[0]["risk_level"] == "normal"

    def test_full_pipeline_raw(self):
        """完整流水线：原始日志行 → 解析 → forwarder 缓冲区。"""
        from src.collector.watcher import LogWatcher
        from src.collector.forwarder import BatchForwarder

        fw = BatchForwarder(api_url="http://localhost:9999/nonexistent",
                          batch_secs=3600, max_batch=100)
        w = LogWatcher("/tmp/test_pipeline.log")

        # 模拟多种格式
        lines = [
            # 原始格式
            "2026-05-13T14:30:00Z|zhangsan|192.168.1.1|rm -rf /tmp/*|success",
            # JSON堡垒机格式
            '{"user":"lisi","cmd":"whoami","time":"2026-05-13T14:31:00Z","ip":"10.0.0.1"}',
            # 原始格式高危
            "2026-05-13T14:32:00Z|wangwu|10.0.0.2|dd if=/dev/zero of=/tmp/test bs=1M count=1024|failed",
        ]
        for line in lines:
            w.inject(line)

        entries = w.get_entries_nowait()
        assert len(entries) == 3, f"Expected 3, got {len(entries)}"

        # 验证解析正确性
        assert entries[0]["operator"] == "zhangsan"
        assert entries[0]["risk_level"] == "high"
        assert entries[1]["operator"] == "lisi"
        assert entries[1]["risk_level"] == "normal"
        assert entries[2]["operator"] == "wangwu"
        assert entries[2]["risk_level"] == "high"
        assert entries[2]["result"] == "failed"

        # 推入 forwarder
        fw.extend(entries)
        assert fw.buffer_size == 3

    def test_bastion_batch_format_in_pipeline(self):
        """堡垒机批量格式完整流水线。"""
        from src.collector.watcher import LogWatcher
        from src.collector.forwarder import BatchForwarder

        fw = BatchForwarder(api_url="http://localhost:9999/nonexistent",
                          batch_secs=3600, max_batch=100)
        w = LogWatcher("/tmp/test_pipeline_bastion.log")

        bastion_batch = json.dumps({
            "host": "prod-bastion-01",
            "records": [
                {"user": "admin1", "ip": "10.1.0.1",
                 "cmd": "systemctl restart app", "time": "2026-05-13T14:00:00Z"},
                {"user": "admin2", "ip": "10.1.0.2",
                 "cmd": "cat /etc/passwd", "time": "2026-05-13T14:01:00Z"},
                {"user": "admin1", "ip": "10.1.0.1",
                 "cmd": "sudo rm -rf /var/log/old/", "time": "2026-05-13T14:02:00Z"},
            ],
        })
        w.inject(bastion_batch)

        entries = w.get_entries_nowait()
        assert len(entries) == 3

        # 风险等级判定
        assert entries[0]["risk_level"] == "medium"  # systemctl restart
        assert entries[1]["risk_level"] == "normal"  # cat
        assert entries[2]["risk_level"] == "high"    # rm -rf

        fw.extend(entries)
        assert fw.buffer_size == 3
