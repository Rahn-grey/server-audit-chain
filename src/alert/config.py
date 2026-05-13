"""告警配置 — 全部通过环境变量配置。

必需:
    ALERT_SMTP_HOST:     SMTP服务器地址
    ALERT_SMTP_PORT:     SMTP端口 (默认587)
    ALERT_SMTP_USER:     SMTP用户名
    ALERT_SMTP_PASSWORD: SMTP密码
    ALERT_FROM_EMAIL:    发件人地址
    ALERT_TO_EMAILS:     收件人列表，逗号分隔

可选:
    ALERT_MIN_LEVEL:     最低告警等级 (high | medium | normal, 默认medium)
    ALERT_USE_TLS:       是否TLS (默认true)
"""

import os

ALERT_SMTP_HOST = os.environ.get("ALERT_SMTP_HOST", "smtp.qq.com")
ALERT_SMTP_PORT = int(os.environ.get("ALERT_SMTP_PORT", "587"))
ALERT_SMTP_USER = os.environ.get("ALERT_SMTP_USER", "")
ALERT_SMTP_PASSWORD = os.environ.get("ALERT_SMTP_PASSWORD", "")
ALERT_FROM_EMAIL = os.environ.get("ALERT_FROM_EMAIL",
                                   os.environ.get("ALERT_SMTP_USER", ""))
ALERT_TO_EMAILS = os.environ.get("ALERT_TO_EMAILS", "")
ALERT_MIN_LEVEL = os.environ.get("ALERT_MIN_LEVEL", "medium")
ALERT_USE_TLS = os.environ.get("ALERT_USE_TLS", "true").lower() == "true"
