"""审计报告生成器。

生成 Markdown 格式审计报告，包含:
    - 链摘要与完整性状态
    - 操作者行为统计
    - 风险等级分布
    - 高危命令清单
    - 时间趋势

用法:
    python -m src.report.generator --format md
    python -m src.report.generator --format md --output audit.md
    python -m src.report.generator --operator zhangsan --format md
"""

import argparse
import json
import sys
from datetime import datetime, timezone

from src.ledger.contract import AuditContract
from src.storage.query import AuditQuery


class ReportGenerator:
    """审计报告生成器。"""

    def __init__(self):
        self._contract = AuditContract()
        self._query = AuditQuery()

    def generate(self, operator: str | None = None,
                 start_time: str | None = None,
                 end_time: str | None = None) -> dict:
        """收集报告所需的所有数据。

        Returns:
            报告数据字典。
        """
        # 链摘要
        chain_info = self._contract.get_chain_info()
        integrity = self._contract.verify_chain()

        # 操作日志
        log_result = self._query.search_logs(
            operator=operator,
            start_time=start_time,
            end_time=end_time,
            size=10000,
        )
        logs = log_result.get("results", [])

        # 统计
        operators = {}
        risk_count = {"high": 0, "medium": 0, "normal": 0}
        high_commands = []

        for log in logs:
            op = log.get("operator", "unknown")
            if op not in operators:
                operators[op] = {"command_count": 0,
                                 "high": 0, "medium": 0, "normal": 0,
                                 "last_seen": log.get("timestamp", "")}
            operators[op]["command_count"] += 1
            risk = log.get("risk_level", "normal")
            operators[op][risk] = operators[op].get(risk, 0) + 1
            risk_count[risk] = risk_count.get(risk, 0) + 1
            if risk == "high":
                high_commands.append(log)

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "chain_info": chain_info,
            "integrity": integrity,
            "total_commands": log_result.get("total", 0),
            "operators": operators,
            "risk_distribution": risk_count,
            "high_commands": high_commands,
            "operator_filter": operator,
        }

    # ------------------------------------------------------------------
    # Markdown 格式化
    # ------------------------------------------------------------------

    def format_markdown(self, data: dict) -> str:
        """将报告数据渲染为 Markdown。"""
        ci = data["chain_info"]
        integ = data["integrity"]
        rd = data["risk_distribution"]
        total = data["total_commands"]
        high_total = rd.get("high", 0)

        lines = [
            "# 服务器操作审计报告",
            "",
            f"**生成时间**: {data['generated_at'][:19]}",
            "",
            "---",
            "",
            "## 1. 链摘要",
            "",
            f"| 指标 | 值 |",
            f"|------|-----|",
            f"| 存证记录总数 | {ci.get('total_records', 0)} |",
            f"| 创世批次 | {ci.get('genesis_batch_id', 'N/A')} |",
            f"| 创世时间 | {ci.get('genesis_time', 'N/A')[:19] if ci.get('genesis_time') else 'N/A'} |",
            f"| 最新批次 | {ci.get('latest_batch_id', 'N/A')} |",
            f"| 最新上链 | {ci.get('latest_time', 'N/A')[:19] if ci.get('latest_time') else 'N/A'} |",
            f"| 最新存证哈希 | `{ci.get('latest_record_hash', 'N/A')}` |",
            "",
            "## 2. 链完整性",
            "",
            f"| 指标 | 值 |",
            f"|------|-----|",
            f"| 完整性 | {'✅ 完整' if integ.get('is_valid') else '❌ 断裂'} |",
            f"| 断裂位置 | {integ.get('broken_position', 'N/A')} |",
            f"| 链上记录数 | {integ.get('total_records', 0)} |",
            "",
            "## 3. 操作统计",
            "",
            f"- **查询到命令数**: {total}",
            f"- **操作者人数**: {len(data['operators'])}",
            f"- **高危命令数**: {high_total}",
            "",
            "### 3.1 风险等级分布",
            "",
            f"| 等级 | 数量 | 占比 |",
            f"|------|------|------|",
        ]

        for level in ["high", "medium", "normal"]:
            count = rd.get(level, 0)
            pct = f"{count / total * 100:.1f}%" if total > 0 else "0%"
            emoji = {"high": "🔴", "medium": "🟡", "normal": "🟢"}.get(level, "")
            lines.append(f"| {emoji} {level} | {count} | {pct} |")

        lines += [
            "",
            "### 3.2 操作者行为统计",
            "",
            "| 操作者 | 命令数 | 高危 | 中危 | 常规 | 最近活跃 |",
            "|--------|--------|------|------|------|----------|",
        ]

        for op in sorted(data["operators"].keys()):
            stats = data["operators"][op]
            last = stats.get("last_seen", "")[:19]
            lines.append(
                f"| {op} | {stats['command_count']} | "
                f"{stats.get('high',0)} | {stats.get('medium',0)} | "
                f"{stats.get('normal',0)} | {last} |"
            )

        if high_total > 0:
            lines += [
                "",
                "## 4. 高危命令清单",
                "",
                "| 时间 | 操作者 | IP | 命令 | 结果 |",
                "|------|--------|----|------|------|",
            ]
            for hc in data["high_commands"]:
                ts = hc.get("timestamp", "")[:19]
                op = hc.get("operator", "")
                ip = hc.get("ip", "")
                cmd = hc.get("command", "")[:60]
                res = hc.get("result", "")
                lines.append(f"| {ts} | {op} | {ip} | `{cmd}` | {res} |")

        lines += [
            "",
            "---",
            "",
            "*此报告由基于联盟链的服务器操作审计系统自动生成。*",
            "*所有操作记录已在 FISCO BCOS 链上存证，不可篡改。*",
        ]

        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="审计报告生成器")
    parser.add_argument("--operator", default=None, help="聚焦操作者")
    parser.add_argument("--since", default=None, help="起始时间 (ISO 8601)")
    parser.add_argument("--until", default=None, help="结束时间 (ISO 8601)")
    parser.add_argument("--format", choices=["md", "json"], default="md",
                        help="输出格式")
    parser.add_argument("--output", default=None, help="输出文件路径")
    args = parser.parse_args()

    gen = ReportGenerator()
    data = gen.generate(
        operator=args.operator,
        start_time=args.since,
        end_time=args.until,
    )

    if args.format == "json":
        output = json.dumps(data, indent=2, ensure_ascii=False)
    else:
        output = gen.format_markdown(data)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"报告已生成: {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
