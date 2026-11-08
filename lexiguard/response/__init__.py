"""LexiGuard Phase 5.2 – Automated Incident Response & Alert Operations.

Exports the primary orchestrator, webhook broadcaster, and supporting types
so callers can import directly from ``lexiguard.response``.
"""

from __future__ import annotations

from lexiguard.response.responder import (
    ResponseResult,
    build_security_alert,
    get_or_create_quarantine_label,
    orchestrate_response,
    quarantine_message,
)
from lexiguard.response.webhooks import (
    AlertSeverity,
    SecurityAlert,
    WebhookConfig,
    WebhookFormat,
    broadcast_alert,
    format_discord_payload,
    format_generic_payload,
    format_slack_payload,
    format_teams_payload,
    send_security_alert,
    send_webhook,
)

__all__ = [
    # responder
    "ResponseResult",
    "build_security_alert",
    "get_or_create_quarantine_label",
    "orchestrate_response",
    "quarantine_message",
    # webhooks
    "AlertSeverity",
    "SecurityAlert",
    "WebhookConfig",
    "WebhookFormat",
    "broadcast_alert",
    "format_discord_payload",
    "format_generic_payload",
    "format_slack_payload",
    "format_teams_payload",
    "send_security_alert",
    "send_webhook",
]
