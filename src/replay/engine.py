"""操作回放引擎。

查询日志并按时间轴输出操作序列，支持 CLI 和编程两种调用方式。

用法:
    python -m src.replay.engine --operator zhangsan --since "..." --until "..."
    python -m src.replay.engine --operator zhangsan --format table|json|html

编程:
    from src.replay.engine import ReplayEngine
    engine = ReplayEngine()
    timeline = engine.replay(operator="zhangsan")
"""

import argparse
import json
import sys
from datetime import datetime, timezone

from src.storage.query import AuditQuery

_RISK_MARK = {"high": "!!", "medium": "! ", "normal": "  "}


class ReplayEngine:
    """操作回放引擎。"""

    def __init__(self):
        self._query = AuditQuery()

    def replay(self, operator: str | None = None,
               start_time: str | None = None,
               end_time: str | None = None,
               page: int = 1, size: int = 200) -> dict:
        """回放操作序列。

        Returns:
            {"operator", "time_range", "total", "sessions": [...]}
        """
        result = self._query.search_logs(
            operator=operator,
            start_time=start_time,
            end_time=end_time,
            page=page, size=size,
        )
        logs = result.get("results", [])
        logs.sort(key=lambda x: x.get("timestamp", ""))

        sessions = self._split_sessions(logs)

        return {
            "operator": operator or "all",
            "time_range": {
                "start": start_time or (logs[0]["timestamp"] if logs else ""),
                "end": end_time or (logs[-1]["timestamp"] if logs else ""),
            },
            "total": result.get("total", 0),
            "sessions": sessions,
        }

    def _split_sessions(self, logs: list[dict],
                        gap_minutes: int = 30) -> list[dict]:
        """按空闲间隔拆分会话。两次命令间隔 > gap_minutes 则切分为新会话。"""
        if not logs:
            return []

        sessions = []
        current_session = []
        prev_ts = None

        for log in logs:
            ts_str = log.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                ts = None

            if prev_ts and ts:
                diff = (ts - prev_ts).total_seconds()
                if diff > gap_minutes * 60:
                    if current_session:
                        sessions.append(self._build_session(current_session))
                    current_session = []
            current_session.append(log)
            prev_ts = ts

        if current_session:
            sessions.append(self._build_session(current_session))
        return sessions

    def _build_session(self, logs: list[dict]) -> dict:
        if not logs:
            return {}
        first = logs[0]
        last = logs[-1]
        high = sum(1 for l in logs if l.get("risk_level") == "high")
        medium = sum(1 for l in logs if l.get("risk_level") == "medium")
        return {
            "start": first.get("timestamp", ""),
            "end": last.get("timestamp", ""),
            "command_count": len(logs),
            "risk_high": high,
            "risk_medium": medium,
            "commands": logs,
        }

    # ------------------------------------------------------------------
    # 格式化
    # ------------------------------------------------------------------

    def format_timeline_text(self, result: dict) -> str:
        """文本时间轴输出。"""
        lines = [
            "=" * 70,
            f"  操作回放 — {result['operator']}",
            f"  时间范围: {result['time_range']['start']} ~ "
            f"{result['time_range']['end']}",
            f"  总操作数: {result['total']}",
            f"  会话数:   {len(result['sessions'])}",
            "=" * 70,
        ]
        for i, sess in enumerate(result["sessions"], 1):
            lines.append(f"\n--- 会话 #{i} ---")
            lines.append(f"  时间: {sess['start'][:19]} ~ {sess['end'][:19]}")
            lines.append(f"  命令: {sess['command_count']} 条 "
                         f"(高危:{sess['risk_high']} 中危:{sess['risk_medium']})")
            lines.append("")

            for j, cmd in enumerate(sess["commands"], 1):
                risk = cmd.get("risk_level", "normal")
                mark = _RISK_MARK.get(risk, "  ")
                ts = cmd.get("timestamp", "")[:19]
                oper = cmd.get("operator", "?")
                ip = cmd.get("ip", "?")
                command = cmd.get("command", "?")
                result = cmd.get("result", "?")
                lines.append(
                    f"  [{mark}] {ts} | {oper}@{ip} | {command} | {result}"
                )
        return "\n".join(lines)

    def format_timeline_html(self, result: dict) -> str:
        """HTML 时间轴输出。"""
        sessions_html = ""
        for i, sess in enumerate(result["sessions"], 1):
            rows = ""
            for cmd in sess["commands"]:
                risk = cmd.get("risk_level", "normal")
                bg = {"high": "#ffe0e0", "medium": "#fff3cd",
                      "normal": "#fff"}.get(risk, "#fff")
                rows += f"""
    <tr style="background:{bg}">
      <td style="border:1px solid #ddd;padding:4px 8px;white-space:nowrap;">
        {cmd.get("timestamp","")[:19]}</td>
      <td style="border:1px solid #ddd;padding:4px 8px;">
        {cmd.get("operator","")}@{cmd.get("ip","")}</td>
      <td style="border:1px solid #ddd;padding:4px 8px;">
        <code>{cmd.get("command","")}</code></td>
      <td style="border:1px solid #ddd;padding:4px 8px;text-align:center;">
        {risk}</td>
      <td style="border:1px solid #ddd;padding:4px 8px;text-align:center;">
        {cmd.get("result","")}</td>
    </tr>"""
            sessions_html += f"""
  <h3>会话 #{i} ({sess['start'][:19]} ~ {sess['end'][:19]})
    — {sess['command_count']} 条命令</h3>
  <table style="border-collapse:collapse;width:100%;font-size:13px;">
    <tr style="background:#f0f0f0;">
      <th style="border:1px solid #ddd;padding:4px;">时间</th>
      <th style="border:1px solid #ddd;padding:4px;">操作者</th>
      <th style="border:1px solid #ddd;padding:4px;">命令</th>
      <th style="border:1px solid #ddd;padding:4px;">风险</th>
      <th style="border:1px solid #ddd;padding:4px;">结果</th>
    </tr>{rows}
  </table>"""

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>操作回放 — {result['operator']}</title></head>
<body style="font-family:monospace;padding:16px;">
  <h2>操作回放 — {result['operator']}</h2>
  <p>时间范围: {result['time_range']['start']} ~ {result['time_range']['end']}
     | 总操作数: {result['total']}</p>
  {sessions_html}
</body></html>"""


# ====================================================================
# CLI 入口
# ====================================================================

def main():
    parser = argparse.ArgumentParser(description="操作回放工具")
    parser.add_argument("--operator", help="操作者", default=None)
    parser.add_argument("--since", help="起始时间 (ISO 8601)", default=None)
    parser.add_argument("--until", help="结束时间 (ISO 8601)", default=None)
    parser.add_argument("--format", choices=["text", "html", "json"],
                        default="text")
    parser.add_argument("--output", help="输出文件", default=None)
    parser.add_argument("--size", type=int, default=200)
    args = parser.parse_args()

    engine = ReplayEngine()
    result = engine.replay(
        operator=args.operator,
        start_time=args.since,
        end_time=args.until,
        size=args.size,
    )

    if args.format == "json":
        output = json.dumps(result, indent=2, ensure_ascii=False)
    elif args.format == "html":
        output = engine.format_timeline_html(result)
    else:
        output = engine.format_timeline_text(result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"已输出到: {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
