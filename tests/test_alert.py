"""告警模块测试。"""

import os
import pytest


class TestNotifier:
    def test_format_alert_html_high(self):
        from src.alert.notifier import MailNotifier
        n = MailNotifier(host="localhost", user="test", password="test")
        alert = {
            "risk_level": "high",
            "operator": "zhangsan",
            "ip": "192.168.1.10",
            "timestamp": "2026-05-13T14:30:00Z",
            "log_id": "abc123def456",
            "batch_id": "batch_20260513_1430",
            "command": "rm -rf /data/temp/*",
            "result": "success",
        }
        html = n.format_alert_html(alert)
        assert "[HIGH]" in html or "HIGH" in html
        assert "zhangsan" in html
        assert "192.168.1.10" in html
        assert "rm -rf /data/temp/*" in html
        assert "abc123def456" in html

    def test_format_alert_plain(self):
        from src.alert.notifier import MailNotifier
        n = MailNotifier(host="localhost", user="test", password="test")
        alert = {
            "risk_level": "high",
            "operator": "lisi",
            "ip": "10.0.0.1",
            "timestamp": "2026-05-13T14:30:00Z",
            "log_id": "log001",
            "batch_id": "batch001",
            "command": "dd if=/dev/zero of=/tmp/test",
            "result": "failed",
        }
        text = n.format_alert_plain(alert)
        assert "HIGH" in text
        assert "lisi" in text
        assert "dd if=/dev/zero" in text

    def test_format_batch_alert_html(self):
        from src.alert.notifier import MailNotifier
        n = MailNotifier(host="localhost", user="test", password="test")
        alerts = [
            {"risk_level": "medium", "operator": "u1", "ip": "1.1.1.1",
             "command": "chmod 755 script.sh",
             "timestamp": "2026-05-13T14:30:00Z"},
            {"risk_level": "medium", "operator": "u2", "ip": "1.1.1.2",
             "command": "useradd testuser",
             "timestamp": "2026-05-13T14:31:00Z"},
        ]
        html = n.format_batch_alert_html(alerts)
        assert "2 条" in html
        assert "u1" in html
        assert "u2" in html
        assert "chmod 755" in html
        assert "useradd testuser" in html

    def test_send_skips_without_config(self):
        from src.alert.notifier import MailNotifier
        n = MailNotifier(host="localhost", user="", password="")
        result = n.send_alert("test", "body", to_emails="a@b.com")
        assert result is False

    def test_send_skips_without_recipients(self):
        from src.alert.notifier import MailNotifier
        n = MailNotifier(host="localhost", user="user", password="pass")
        result = n.send_alert("test", "body")
        assert result is False


class TestAlertEngine:
    def test_high_alert_triggers_immediately(self):
        """高危告警立即触发。"""
        from src.alert.notifier import MailNotifier
        from src.alert.engine import AlertEngine

        sent = []

        class FakeNotifier(MailNotifier):
            def send_alert(self, subject, body, to_emails=None):
                sent.append({"subject": subject, "body": body})
                return True

        engine = AlertEngine(notifier=FakeNotifier(),
                             min_level="medium")
        entry = {
            "risk_level": "high",
            "operator": "zhangsan",
            "ip": "10.0.0.1",
            "command": "rm -rf /",
            "timestamp": "2026-05-13T14:30:00Z",
            "log_id": "abc",
            "batch_id": "batch_001",
            "result": "success",
        }
        result = engine.check_and_alert(entry)
        assert result is True
        assert len(sent) == 1
        assert "HIGH" in sent[0]["subject"]
        assert "zhangsan" in sent[0]["subject"]

    def test_medium_buffers_then_batch(self):
        """中危告警批量缓冲。"""
        from src.alert.notifier import MailNotifier
        from src.alert.engine import AlertEngine

        sent = []

        class FakeNotifier(MailNotifier):
            def send_alert(self, subject, body, to_emails=None):
                sent.append({"subject": subject, "body": body})
                return True

        engine = AlertEngine(notifier=FakeNotifier(),
                             min_level="medium",
                             batch_threshold=5)
        for i in range(5):
            entry = {
                "risk_level": "medium",
                "operator": f"user_{i}",
                "ip": f"10.0.0.{i}",
                "command": f"chmod 755 file_{i}.sh",
                "timestamp": "2026-05-13T14:30:00Z",
                "log_id": f"log_{i}",
                "batch_id": "batch_001",
                "result": "success",
            }
            engine.check_and_alert(entry)

        # 达到阈值后触发批量告警
        assert len(sent) == 1
        assert "BATCH" in sent[0]["subject"]
        assert "5" in sent[0]["subject"]

    def test_normal_skipped(self):
        """正常操作不告警。"""
        from src.alert.notifier import MailNotifier
        from src.alert.engine import AlertEngine

        sent = []

        class FakeNotifier(MailNotifier):
            def send_alert(self, subject, body, to_emails=None):
                sent.append(1)
                return True

        engine = AlertEngine(notifier=FakeNotifier(),
                             min_level="medium")
        entry = {
            "risk_level": "normal",
            "operator": "zhangsan",
            "command": "ls -la",
            "timestamp": "2026-05-13T14:30:00Z",
            "log_id": "abc",
            "batch_id": "batch_001",
            "result": "success",
        }
        result = engine.check_and_alert(entry)
        assert result is False
        assert len(sent) == 0

    def test_min_level_high_skips_medium(self):
        """min_level=high 时中危不告警。"""
        from src.alert.notifier import MailNotifier
        from src.alert.engine import AlertEngine

        sent = []

        class FakeNotifier(MailNotifier):
            def send_alert(self, subject, body, to_emails=None):
                sent.append(1)
                return True

        engine = AlertEngine(notifier=FakeNotifier(), min_level="high")
        entry = {
            "risk_level": "medium",
            "operator": "zhangsan",
            "command": "chmod 755 script.sh",
            "timestamp": "2026-05-13T14:30:00Z",
            "log_id": "abc",
            "batch_id": "batch_001",
            "result": "success",
        }
        assert engine.check_and_alert(entry) is False
        assert len(sent) == 0

    def test_check_batch_and_alert(self):
        """批量检查方法。"""
        from src.alert.notifier import MailNotifier
        from src.alert.engine import AlertEngine

        sent = []

        class FakeNotifier(MailNotifier):
            def send_alert(self, subject, body, to_emails=None):
                sent.append({"subject": subject, "body": body})
                return True

        engine = AlertEngine(notifier=FakeNotifier(),
                             min_level="medium")
        entries = [
            {"risk_level": "high", "operator": "zhangsan",
             "command": "rm -rf /", "timestamp": "2026-05-13T14:30:00Z",
             "log_id": "abc", "batch_id": "b1", "result": "success",
             "ip": "10.0.0.1"},
            {"risk_level": "normal", "operator": "lisi",
             "command": "who", "timestamp": "2026-05-13T14:31:00Z",
             "log_id": "def", "batch_id": "b1", "result": "success",
             "ip": "10.0.0.2"},
            {"risk_level": "high", "operator": "wangwu",
             "command": "dd if=/dev/zero", "timestamp": "2026-05-13T14:32:00Z",
             "log_id": "ghi", "batch_id": "b1", "result": "success",
             "ip": "10.0.0.3"},
        ]
        engine.check_batch_and_alert(entries)
        # 2条高危各发一封
        assert len(sent) == 2

    def test_flush_empty(self):
        from src.alert.engine import AlertEngine
        engine = AlertEngine(min_level="medium")
        engine.flush()
        assert engine.buffer_size == 0


class TestForwarderAlertIntegration:
    """验证 forwarder 与告警引擎的集成。"""

    def test_forwarder_calls_alert_on_append(self):
        from src.collector.forwarder import BatchForwarder
        from src.alert.notifier import MailNotifier
        from src.alert.engine import AlertEngine

        sent = []

        class FakeNotifier(MailNotifier):
            def send_alert(self, subject, body, to_emails=None):
                sent.append(subject)
                return True

        engine = AlertEngine(notifier=FakeNotifier(), min_level="medium")

        fw = BatchForwarder(api_url="http://localhost:9999/test",
                          batch_secs=9999, max_batch=50)
        fw.set_alert_engine(engine)

        fw.append({
            "risk_level": "high", "operator": "attacker",
            "command": "rm -rf /", "timestamp": "2026-05-13T14:30:00Z",
            "log_id": "xyz", "batch_id": "b1", "result": "success",
            "ip": "10.0.0.99",
        })
        assert len(sent) == 1
        assert "attacker" in sent[0]
