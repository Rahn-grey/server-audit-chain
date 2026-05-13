"""报告导出模块。

生成审计报告：摘要统计、操作者行为分析、风险分布、链完整性。

用法:
    python -m src.report.generator --format md                  # 完整报告
    python -m src.report.generator --operator zhangsan --format md  # 个人报告
    python -m src.report.generator --format md --output audit_report.md
"""
