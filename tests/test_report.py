"""报告导出测试。"""

import pytest


class TestReportGenerator:
    @pytest.fixture
    def gen(self):
        from src.report.generator import ReportGenerator
        return ReportGenerator()

    def test_generate_structure(self, gen):
        data = gen.generate()
        assert "generated_at" in data
        assert "chain_info" in data
        assert "integrity" in data
        assert "total_commands" in data
        assert "operators" in data
        assert "risk_distribution" in data
        assert "high_commands" in data

    def test_generate_has_chain_info(self, gen):
        data = gen.generate()
        ci = data["chain_info"]
        assert "total_records" in ci
        assert "genesis_batch_id" in ci

    def test_generate_has_integrity(self, gen):
        data = gen.generate()
        integ = data["integrity"]
        assert "is_valid" in integ
        assert "total_records" in integ

    def test_format_markdown(self, gen):
        data = {
            "generated_at": "2026-05-13T14:30:00Z",
            "chain_info": {
                "total_records": 5,
                "genesis_batch_id": "batch_001",
                "genesis_time": "2026-05-13T10:00:00Z",
                "latest_batch_id": "batch_005",
                "latest_time": "2026-05-13T14:00:00Z",
                "latest_record_hash": "a1b2c3d4e5f6",
            },
            "integrity": {"is_valid": True, "broken_position": -1,
                          "total_records": 5},
            "total_commands": 10,
            "operators": {
                "zhangsan": {"command_count": 6, "high": 2, "medium": 1,
                             "normal": 3, "last_seen": "2026-05-13T14:00:00Z"},
                "lisi": {"command_count": 4, "high": 0, "medium": 1,
                         "normal": 3, "last_seen": "2026-05-13T13:50:00Z"},
            },
            "risk_distribution": {"high": 2, "medium": 2, "normal": 6},
            "high_commands": [
                {"timestamp": "2026-05-13T14:00:00Z", "operator": "zhangsan",
                 "ip": "10.0.0.1", "command": "rm -rf /tmp", "result": "success"},
                {"timestamp": "2026-05-13T13:00:00Z", "operator": "zhangsan",
                 "ip": "10.0.0.1", "command": "dd if=/dev/zero",
                 "result": "failed"},
            ],
            "operator_filter": None,
        }
        md = gen.format_markdown(data)
        assert "服务器操作审计报告" in md
        assert "链完整性" in md
        assert "✅ 完整" in md
        assert "zhangsan" in md
        assert "lisi" in md
        assert "rm -rf /tmp" in md
        assert "高危" in md
        assert "batch_001" in md
        assert "batch_005" in md

    def test_format_markdown_broken_chain(self, gen):
        data = {
            "generated_at": "2026-05-13T14:30:00Z",
            "chain_info": {"total_records": 3, "genesis_batch_id": "b1",
                           "genesis_time": "2026-05-13T10:00:00Z",
                           "latest_batch_id": "b3",
                           "latest_time": "2026-05-13T14:00:00Z",
                           "latest_record_hash": "xxx"},
            "integrity": {"is_valid": False, "broken_position": 1,
                          "total_records": 3},
            "total_commands": 5,
            "operators": {},
            "risk_distribution": {"high": 0, "medium": 0, "normal": 5},
            "high_commands": [],
            "operator_filter": None,
        }
        md = gen.format_markdown(data)
        assert "❌ 断裂" in md
        assert "断裂位置" in md

    def test_format_markdown_no_high_commands(self, gen):
        data = {
            "generated_at": "2026-05-13T14:30:00Z",
            "chain_info": {"total_records": 1, "genesis_batch_id": "b1",
                           "genesis_time": "", "latest_batch_id": "b1",
                           "latest_time": "", "latest_record_hash": "h1"},
            "integrity": {"is_valid": True, "broken_position": -1,
                          "total_records": 1},
            "total_commands": 3,
            "operators": {},
            "risk_distribution": {"high": 0, "medium": 0, "normal": 3},
            "high_commands": [],
            "operator_filter": None,
        }
        md = gen.format_markdown(data)
        assert "高危命令清单" not in md  # 无高危时不显示
