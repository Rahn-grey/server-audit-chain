"""邮件通知器 — SMTP发送告警邮件。"""

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate

from src.alert.config import (
    ALERT_FROM_EMAIL,
    ALERT_SMTP_HOST,
    ALERT_SMTP_PASSWORD,
    ALERT_SMTP_PORT,
    ALERT_SMTP_USER,
    ALERT_TO_EMAILS,
    ALERT_USE_TLS,
)

logger = logging.getLogger(__name__)

_RISK_EMOJI = {"high": "🔴", "medium": "🟡", "normal": "🟢"}


class MailNotifier:
    """SMTP邮件通知器。"""

    def __init__(self, host=None, port=None, user=None, password=None,
                 from_email=None, use_tls=None):
        self._host = host or ALERT_SMTP_HOST
        self._port = port or ALERT_SMTP_PORT
        self._user = user or ALERT_SMTP_USER
        self._password = password or ALERT_SMTP_PASSWORD
        self._from = from_email or ALERT_FROM_EMAIL or self._user
        self._use_tls = use_tls if use_tls is not None else ALERT_USE_TLS

    # ------------------------------------------------------------------
    # 发送
    # ------------------------------------------------------------------

    def send_alert(self, subject: str, body: str,
                   to_emails: str | list[str] | None = None):
        """发送告警邮件。

        Args:
            subject: 邮件主题。
            body: HTML邮件正文。
            to_emails: 收件人（默认使用 ALERT_TO_EMAILS）。
        """
        if not to_emails:
            to_emails = ALERT_TO_EMAILS
        if isinstance(to_emails, str):
            to_emails = [e.strip() for e in to_emails.split(",") if e.strip()]
        if not to_emails:
            logger.warning("未配置收件人，跳过发送")
            return False

        if not self._user or not self._password:
            logger.warning("SMTP未配置用户名密码，跳过发送")
            return False

        msg = MIMEMultipart("alternative")
        msg["From"] = self._from
        msg["To"] = ", ".join(to_emails)
        msg["Subject"] = subject
        msg["Date"] = formatdate(localtime=True)
        msg.attach(MIMEText(body, "html", "utf-8"))

        try:
            server = smtplib.SMTP(self._host, self._port, timeout=15)
            if self._use_tls:
                server.starttls()
            server.login(self._user, self._password)
            server.sendmail(self._from, to_emails, msg.as_string())
            server.quit()
            logger.info("告警邮件已发送: %s -> %s", subject, to_emails)
            return True
        except Exception as e:
            logger.error("邮件发送失败: %s", e)
            return False

    # ------------------------------------------------------------------
    # 格式化
    # ------------------------------------------------------------------

    def format_alert_html(self, alert: dict) -> str:
        """将告警数据渲染为HTML邮件正文。"""
        risk = alert.get("risk_level", "unknown")
        emoji = _RISK_EMOJI.get(risk, "⚪")

        return f"""<!DOCTYPE html>
<html><body style="font-family:monospace;padding:16px;">
  <h2>{emoji} 服务器操作告警 — {risk.upper()} 风险</h2>
  <table style="border-collapse:collapse;width:100%;">
    <tr><td style="padding:6px;border:1px solid #ddd;background:#f5f5f5;">
      <b>操作者</b></td>
      <td style="padding:6px;border:1px solid #ddd;">
        {alert.get("operator", "unknown")}</td></tr>
    <tr><td style="padding:6px;border:1px solid #ddd;background:#f5f5f5;">
      <b>来源IP</b></td>
      <td style="padding:6px;border:1px solid #ddd;">
        {alert.get("ip", "unknown")}</td></tr>
    <tr><td style="padding:6px;border:1px solid #ddd;background:#f5f5f5;">
      <b>时间</b></td>
      <td style="padding:6px;border:1px solid #ddd;">
        {alert.get("timestamp", "unknown")}</td></tr>
    <tr><td style="padding:6px;border:1px solid #ddd;background:#f5f5f5;">
      <b>日志ID</b></td>
      <td style="padding:6px;border:1px solid #ddd;">
        {alert.get("log_id", "unknown")}</td></tr>
    <tr><td style="padding:6px;border:1px solid #ddd;background:#f5f5f5;">
      <b>批次ID</b></td>
      <td style="padding:6px;border:1px solid #ddd;">
        {alert.get("batch_id", "unknown")}</td></tr>
    <tr><td style="padding:6px;border:1px solid #ddd;background:#f5f5f5;">
      <b>执行结果</b></td>
      <td style="padding:6px;border:1px solid #ddd;">
        {alert.get("result", "unknown")}</td></tr>
  </table>
  <div style="margin-top:16px;padding:12px;
              background:{'#ffe0e0' if risk == 'high' else '#fff3cd'};
              border-left:4px solid {'red' if risk == 'high' else 'orange'};">
    <b>命令:</b><br/>
    <code style="font-size:14px;">{alert.get("command", "unknown")}</code>
  </div>
  <p style="color:#999;font-size:12px;margin-top:16px;">
    此邮件由服务器操作审计系统自动生成 | 区块链存证不可篡改</p>
</body></html>"""

    def format_alert_plain(self, alert: dict) -> str:
        """纯文本邮件正文。"""
        risk = alert.get("risk_level", "unknown")
        return (
            f"[{risk.upper()}风险告警]\n"
            f"操作者:   {alert.get('operator', 'unknown')}\n"
            f"来源IP:   {alert.get('ip', 'unknown')}\n"
            f"时间:     {alert.get('timestamp', 'unknown')}\n"
            f"日志ID:   {alert.get('log_id', 'unknown')}\n"
            f"批次ID:   {alert.get('batch_id', 'unknown')}\n"
            f"执行结果: {alert.get('result', 'unknown')}\n"
            f"命令:     {alert.get('command', 'unknown')}\n"
        )

    def format_batch_alert_html(self, alerts: list[dict]) -> str:
        """将多条告警渲染为HTML邮件。"""
        rows = ""
        for a in alerts:
            risk = a.get("risk_level", "unknown")
            emoji = _RISK_EMOJI.get(risk, "⚪")
            rows += f"""
    <tr>
      <td style="padding:4px;border:1px solid #ddd;">{emoji}</td>
      <td style="padding:4px;border:1px solid #ddd;font-size:12px;">
        {a.get("timestamp", "")[:19]}</td>
      <td style="padding:4px;border:1px solid #ddd;">
        {a.get("operator", "")}</td>
      <td style="padding:4px;border:1px solid #ddd;">
        {a.get("ip", "")}</td>
      <td style="padding:4px;border:1px solid #ddd;">
        {a.get("risk_level", "")}</td>
      <td style="padding:4px;border:1px solid #ddd;">
        <code>{a.get("command", "")}</code></td>
    </tr>"""

        return f"""<!DOCTYPE html>
<html><body style="font-family:monospace;padding:16px;">
  <h2>🚨 批量操作告警 — {len(alerts)} 条</h2>
  <table style="border-collapse:collapse;width:100%;">
    <tr style="background:#f5f5f5;">
      <th style="padding:4px;border:1px solid #ddd;"></th>
      <th style="padding:4px;border:1px solid #ddd;">时间</th>
      <th style="padding:4px;border:1px solid #ddd;">操作者</th>
      <th style="padding:4px;border:1px solid #ddd;">IP</th>
      <th style="padding:4px;border:1px solid #ddd;">等级</th>
      <th style="padding:4px;border:1px solid #ddd;">命令</th>
    </tr>{rows}
  </table>
  <p style="color:#999;font-size:12px;margin-top:16px;">
    共 {len(alerts)} 条告警 | 服务器操作审计系统</p>
</body></html>"""
