"""Notification delivery via SMTP, Mailgun (email) or Twilio (SMS).

Backends are chosen by settings (VCM_EMAIL_BACKEND / VCM_SMS_BACKEND). All calls
are best-effort and return a (ok, detail) tuple — callers decide whether a failed
notification should surface to the user. Only the Python stdlib is used (smtplib,
urllib) so no extra runtime dependencies are required.

Designed to underpin future flows such as password reset.
"""
from __future__ import annotations

import smtplib
import urllib.parse
import urllib.request
from email.message import EmailMessage

from .config import get_settings


def email_enabled() -> bool:
    return get_settings().email_backend.lower() in ("smtp", "mailgun")


def sms_enabled() -> bool:
    return get_settings().sms_backend.lower() == "twilio"


def send_email(to: str, subject: str, body: str) -> tuple[bool, str]:
    s = get_settings()
    backend = s.email_backend.lower()
    if not to:
        return False, "no recipient"
    if backend == "smtp":
        return _smtp_send(to, subject, body)
    if backend == "mailgun":
        return _mailgun_send(to, subject, body)
    return False, f"email backend '{backend}' not configured"


def send_sms(to: str, body: str) -> tuple[bool, str]:
    s = get_settings()
    if s.sms_backend.lower() != "twilio":
        return False, f"sms backend '{s.sms_backend}' not configured"
    if not to:
        return False, "no recipient"
    return _twilio_send(to, body)


# --------------------------------------------------------------------------- #
def _from_header() -> str:
    s = get_settings()
    return f"{s.notify_from_name} <{s.notify_from_email}>"


def _smtp_send(to: str, subject: str, body: str) -> tuple[bool, str]:
    s = get_settings()
    if not s.smtp_host:
        return False, "smtp_host not set"
    msg = EmailMessage()
    msg["From"] = _from_header()
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=15) as srv:
            if s.smtp_starttls:
                srv.starttls()
            if s.smtp_user:
                srv.login(s.smtp_user, s.smtp_password)
            srv.send_message(msg)
        return True, "sent"
    except Exception as e:  # noqa: BLE001
        return False, f"smtp error: {e}"


def _mailgun_send(to: str, subject: str, body: str) -> tuple[bool, str]:
    s = get_settings()
    if not (s.mailgun_domain and s.mailgun_api_key):
        return False, "mailgun_domain/api_key not set"
    url = f"{s.mailgun_base_url.rstrip('/')}/v3/{s.mailgun_domain}/messages"
    data = urllib.parse.urlencode({
        "from": _from_header(), "to": to, "subject": subject, "text": body,
    }).encode()
    return _http_post(url, data, basic_auth=("api", s.mailgun_api_key))


def _twilio_send(to: str, body: str) -> tuple[bool, str]:
    s = get_settings()
    if not (s.twilio_account_sid and s.twilio_auth_token and s.twilio_from_number):
        return False, "twilio credentials/from not set"
    url = f"https://api.twilio.com/2010-04-01/Accounts/{s.twilio_account_sid}/Messages.json"
    data = urllib.parse.urlencode({
        "From": s.twilio_from_number, "To": to, "Body": body,
    }).encode()
    return _http_post(url, data, basic_auth=(s.twilio_account_sid, s.twilio_auth_token))


def _http_post(url: str, data: bytes, basic_auth: tuple[str, str]) -> tuple[bool, str]:
    import base64

    req = urllib.request.Request(url, data=data, method="POST")
    token = base64.b64encode(f"{basic_auth[0]}:{basic_auth[1]}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            return 200 <= resp.status < 300, f"http {resp.status}"
    except Exception as e:  # noqa: BLE001
        return False, f"http error: {e}"
