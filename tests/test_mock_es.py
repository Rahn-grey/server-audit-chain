"""MockES自身功能测试。"""

from src.debug.data_generator import generate_batch


class TestMockES:
    def test_search_by_operator(self, mock_es):
        logs = generate_batch("batch_001", log_count=50)
        mock_es.inject_logs(logs)
        result = mock_es.search_logs(operator="zhangsan")
        for log in result.results:
            assert log["operator"] == "zhangsan"

    def test_search_by_keyword(self, mock_es):
        logs = generate_batch("batch_001", log_count=50)
        mock_es.inject_logs(logs)
        result = mock_es.search_logs(keyword="systemctl")
        for log in result.results:
            assert "systemctl" in log["command"]

    def test_search_no_match(self, mock_es):
        logs = generate_batch("batch_001", log_count=10)
        mock_es.inject_logs(logs)
        result = mock_es.search_logs(operator="nonexistent")
        assert result.total == 0

    def test_get_log_by_id(self, mock_es):
        logs = generate_batch("batch_001", log_count=10)
        mock_es.inject_logs(logs)
        log_id = logs[0]["log_id"]
        retrieved = mock_es.get_log_by_id(log_id)
        assert retrieved is not None
        assert retrieved["log_id"] == log_id

    def test_get_logs_by_batch(self, mock_es):
        logs = generate_batch("batch_001", log_count=20)
        mock_es.inject_logs(logs)
        batch_logs = mock_es.get_logs_by_batch("batch_001")
        assert len(batch_logs) == 20

    def test_pagination(self, mock_es):
        logs = generate_batch("batch_001", log_count=50)
        mock_es.inject_logs(logs)
        page1 = mock_es.search_logs(page=1, size=20)
        assert len(page1.results) == 20
        page2 = mock_es.search_logs(page=2, size=20)
        assert len(page2.results) == 20

    def test_tamper_log(self, mock_es):
        logs = generate_batch("batch_001", log_count=10)
        mock_es.inject_logs(logs)
        log_id = logs[0]["log_id"]
        mock_es.tamper_log(log_id, "command", "echo hacked")
        log = mock_es.get_log_by_id(log_id)
        assert log["command"] == "echo hacked"

    def test_reset_logs(self, mock_es):
        logs = generate_batch("batch_001", log_count=10)
        mock_es.inject_logs(logs)
        mock_es.reset_logs()
        assert mock_es.get_all_logs() == []

    def test_search_sorted_by_time_desc(self, mock_es):
        logs = generate_batch("batch_001", log_count=10)
        mock_es.inject_logs(logs)
        result = mock_es.search_logs()
        timestamps = [log["timestamp"] for log in result.results]
        assert timestamps == sorted(timestamps, reverse=True)
