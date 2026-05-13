"""告警模块。

高危命令实时邮件告警。与采集层解耦，可独立部署或嵌入 agent/API。

用法:
    from src.alert.engine import AlertEngine
    engine = AlertEngine(smtp_config)
    engine.check_and_alert(log_entry)
"""
