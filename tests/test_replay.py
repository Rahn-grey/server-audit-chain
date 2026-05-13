"""操作回放测试。"""

import pytest


class TestReplayEngine:
    @pytest.fixture
    def engine(self):
        from src.replay.engine import ReplayEngine
        return ReplayEngine()

    def test_replay_empty(self, engine):
        result = engine.replay(operator="nonexistent_user_xyz")
        assert result["operator"] == "nonexistent_user_xyz"
        assert result["total"] == 0
        assert result["sessions"] == []

    def test_split_sessions_empty(self, engine):
        sessions = engine._split_sessions([])
        assert sessions == []

    def test_split_sessions_single(self, engine):
        logs = [
            {"timestamp": "2026-05-13T14:30:00Z", "operator": "u1",
             "command": "ls", "ip": "1.1.1.1", "risk_level": "normal",
             "result": "success", "batch_id": "b1", "log_id": "l1"},
        ]
        sessions = engine._split_sessions(logs, gap_minutes=30)
        assert len(sessions) == 1
        assert sessions[0]["command_count"] == 1

    def test_split_sessions_by_gap(self, engine):
        """空闲超30分钟拆分会话。"""
        logs = [
            {"timestamp": "2026-05-13T14:00:00Z", "operator": "u1",
             "command": "cmd1", "ip": "1.1.1.1", "risk_level": "normal",
             "result": "success", "batch_id": "b1", "log_id": "l1"},
            {"timestamp": "2026-05-13T14:05:00Z", "operator": "u1",
             "command": "cmd2", "ip": "1.1.1.1", "risk_level": "normal",
             "result": "success", "batch_id": "b1", "log_id": "l2"},
            {"timestamp": "2026-05-13T15:00:00Z", "operator": "u1",
             "command": "cmd3", "ip": "1.1.1.1", "risk_level": "high",
             "result": "success", "batch_id": "b1", "log_id": "l3"},
        ]
        sessions = engine._split_sessions(logs, gap_minutes=30)
        assert len(sessions) == 2
        assert sessions[0]["command_count"] == 2
        assert sessions[1]["command_count"] == 1
        assert sessions[1]["risk_high"] == 1

    def test_build_session_stats(self, engine):
        logs = [
            {"timestamp": "2026-05-13T14:00:00Z", "operator": "u1",
             "command": "normal_cmd", "ip": "1.1.1.1", "risk_level": "normal",
             "result": "success", "batch_id": "b1", "log_id": "l1"},
            {"timestamp": "2026-05-13T14:01:00Z", "operator": "u1",
             "command": "chmod 755", "ip": "1.1.1.1", "risk_level": "medium",
             "result": "success", "batch_id": "b1", "log_id": "l2"},
            {"timestamp": "2026-05-13T14:02:00Z", "operator": "u1",
             "command": "rm -rf /tmp", "ip": "1.1.1.1", "risk_level": "high",
             "result": "success", "batch_id": "b1", "log_id": "l3"},
        ]
        sess = engine._build_session(logs)
        assert sess["command_count"] == 3
        assert sess["risk_high"] == 1
        assert sess["risk_medium"] == 1

    def test_format_timeline_text(self, engine):
        result = {
            "operator": "zhangsan",
            "time_range": {"start": "2026-05-13T14:00:00Z",
                           "end": "2026-05-13T14:05:00Z"},
            "total": 2,
            "sessions": [
                {"start": "2026-05-13T14:00:00Z",
                 "end": "2026-05-13T14:05:00Z",
                 "command_count": 2, "risk_high": 1, "risk_medium": 0,
                 "commands": [
                     {"timestamp": "2026-05-13T14:00:00Z", "operator": "zs",
                      "ip": "10.0.0.1", "command": "ls", "risk_level": "normal",
                      "result": "success", "batch_id": "b1", "log_id": "l1"},
                     {"timestamp": "2026-05-13T14:05:00Z", "operator": "zs",
                      "ip": "10.0.0.1", "command": "rm -rf /tmp",
                      "risk_level": "high", "result": "success",
                      "batch_id": "b1", "log_id": "l2"},
                 ]},
            ],
        }
        text = engine.format_timeline_text(result)
        assert "zhangsan" in text
        assert "ls" in text
        assert "rm -rf /tmp" in text
        assert "!!" in text  # 高危标记

    def test_format_timeline_html(self, engine):
        result = {
            "operator": "zhangsan",
            "time_range": {"start": "2026-05-13T14:00:00Z",
                           "end": "2026-05-13T14:01:00Z"},
            "total": 1,
            "sessions": [
                {"start": "2026-05-13T14:00:00Z",
                 "end": "2026-05-13T14:01:00Z",
                 "command_count": 1, "risk_high": 1, "risk_medium": 0,
                 "commands": [
                     {"timestamp": "2026-05-13T14:00:00Z", "operator": "zs",
                      "ip": "10.0.0.1", "command": "rm -rf /", "risk_level": "high",
                      "result": "success", "batch_id": "b1", "log_id": "l1"},
                 ]},
            ],
        }
        html = engine.format_timeline_html(result)
        assert "<html>" in html
        assert "zhangsan" in html
        assert "rm -rf /" in html
        assert "#ffe0e0" in html  # 高危红色背景
