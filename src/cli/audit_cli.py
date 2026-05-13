"""审计系统CLI工具。

用法:
    audit-cli search --operator zhangsan --since "..." --until "..." --keyword "rm"
    audit-cli verify --log-id <log_hash_id>
    audit-cli chain-info
    audit-cli chain-verify
    audit-cli record --batch-id <batch_id>
    audit-cli replay --operator zhangsan --since "..." --until "..."
    audit-cli report --format md --output audit_report.md

输出格式支持: table（默认）, json。
"""

import argparse
import json
import sys

from src.storage.query import AuditQuery
from src.replay.engine import ReplayEngine
from src.report.generator import ReportGenerator


def print_table(headers: list, rows: list):
    """以表格形式打印数据。"""
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    sep = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"

    def format_row(cells):
        return "| " + " | ".join(str(c).ljust(w) for c, w in zip(cells, col_widths)) + " |"

    print(sep)
    print(format_row(headers))
    print(sep)
    for row in rows:
        print(format_row(row))
    print(sep)


def cmd_search(args):
    """search子命令：搜索操作日志。"""
    query = AuditQuery()
    result = query.search_logs(
        operator=args.operator,
        start_time=args.since,
        end_time=args.until,
        keyword=args.keyword,
        page=args.page,
        size=args.size,
    )

    if args.format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    logs = result.get("results", [])
    if not logs:
        print("未找到匹配的日志记录。")
        return

    print(f"共 {result['total']} 条结果（显示第 {1 + (args.page - 1) * args.size}~{min(args.page * args.size, result['total'])} 条）\n")
    headers = ["log_id", "operator", "command", "timestamp", "risk_level"]
    rows = []
    for log in logs:
        rows.append([
            log.get("log_id", "")[:12],
            log.get("operator", ""),
            log.get("command", "")[:50],
            log.get("timestamp", "")[:19],
            log.get("risk_level", ""),
        ])
    print_table(headers, rows)


def cmd_verify(args):
    """verify子命令：验证单条日志真伪。"""
    query = AuditQuery()
    result = query.verify_log(args.log_id, args.public_key)

    if args.format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    status = "✓ 验证通过" if result.get("verified") else "✗ 验证失败"
    print(f"\n验证结果: {status}\n")
    for key, value in result.items():
        print(f"  {key}: {value}")


def cmd_chain_info(args):
    """chain-info子命令：获取审计链摘要信息。"""
    query = AuditQuery()
    info = query.get_chain_info()

    if args.format == "json":
        print(json.dumps(info, indent=2, ensure_ascii=False))
        return

    print("\n审计链摘要信息\n")
    for key, value in info.items():
        print(f"  {key}: {value}")
    print()


def cmd_chain_verify(args):
    """chain-verify子命令：验证整条审计链完整性。"""
    query = AuditQuery()
    result = query.verify_chain_integrity()

    if args.format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    is_valid = result.get("is_valid", False)
    status = "✓ 链完整" if is_valid else "✗ 链已断裂"
    print(f"\n整链完整性验证: {status}")
    print(f"  记录总数: {result.get('total_records', 0)}")
    if not is_valid:
        print(f"  断裂位置: 记录索引 {result.get('broken_position', -1)}")
    print()


def cmd_record(args):
    """record子命令：查询链上存证记录。"""
    query = AuditQuery()
    record = query.get_record(args.batch_id)

    if args.format == "json":
        print(json.dumps(record, indent=2, ensure_ascii=False) if record else
              json.dumps({"error": "记录不存在"}))
        return

    if record is None:
        print(f"批次 {args.batch_id} 在链上不存在")
        return

    print(f"\n链上存证记录: {args.batch_id}\n")
    for key, value in record.items():
        val = str(value)
        if len(val) > 80:
            val = val[:40] + "..." + val[-20:]
        print(f"  {key}: {val}")
    print()


def cmd_replay(args):
    """replay子命令：回放操作序列。"""
    engine = ReplayEngine()
    result = engine.replay(
        operator=args.operator,
        start_time=args.since,
        end_time=args.until,
        size=args.size,
    )

    if args.format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(engine.format_timeline_text(result))


def cmd_report(args):
    """report子命令：生成审计报告。"""
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


def main():
    parser = argparse.ArgumentParser(
        description="基于联盟链的服务器操作审计系统 - CLI工具",
    )
    parser.add_argument("--format", choices=["table", "json", "md", "html"],
                        default="table", help="输出格式（默认: table）")

    subparsers = parser.add_subparsers(dest="command", help="子命令")

    # search
    p_search = subparsers.add_parser("search", help="搜索操作日志")
    p_search.add_argument("--operator", help="操作者")
    p_search.add_argument("--since", help="起始时间 (ISO 8601)")
    p_search.add_argument("--until", help="结束时间 (ISO 8601)")
    p_search.add_argument("--keyword", help="命令关键词")
    p_search.add_argument("--page", type=int, default=1, help="页码")
    p_search.add_argument("--size", type=int, default=50, help="每页条数")
    p_search.set_defaults(func=cmd_search)

    # verify
    p_verify = subparsers.add_parser("verify", help="验证单条日志真伪")
    p_verify.add_argument("--log-id", required=True, help="日志ID")
    p_verify.add_argument("--public-key", help="验签公钥PEM文件路径")
    p_verify.set_defaults(func=cmd_verify)

    # chain-info
    p_info = subparsers.add_parser("chain-info", help="获取审计链摘要信息")
    p_info.set_defaults(func=cmd_chain_info)

    # chain-verify
    p_cv = subparsers.add_parser("chain-verify", help="验证整条审计链完整性")
    p_cv.set_defaults(func=cmd_chain_verify)

    # record
    p_rec = subparsers.add_parser("record", help="查询链上存证记录")
    p_rec.add_argument("--batch-id", required=True, help="批次ID")
    p_rec.set_defaults(func=cmd_record)

    # replay
    p_replay = subparsers.add_parser("replay", help="回放操作序列")
    p_replay.add_argument("--operator", help="操作者")
    p_replay.add_argument("--since", help="起始时间 (ISO 8601)")
    p_replay.add_argument("--until", help="结束时间 (ISO 8601)")
    p_replay.add_argument("--size", type=int, default=200)
    p_replay.set_defaults(func=cmd_replay)

    # report
    p_report = subparsers.add_parser("report", help="生成审计报告")
    p_report.add_argument("--operator", help="聚焦操作者")
    p_report.add_argument("--since", help="起始时间 (ISO 8601)")
    p_report.add_argument("--until", help="结束时间 (ISO 8601)")
    p_report.add_argument("--output", help="输出文件路径")
    p_report.set_defaults(func=cmd_report)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
