"""LexiGuard Webhook & SIEM Alert Broadcaster (Phase 5.2).

Formats and dispatches structured JSON security alerts to external platforms
including generic SIEM endpoints, Slack, Discord, and Microsoft Teams.

Network calls are isolated inside ``send_webhook`` so the rest of the
codebase (and all unit tests) can operate entirely offline by injecting a
mock ``requests`` session.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enums & Configuration types
# ---------------------------------------------------------------------------


class WebhookFormat(str, Enum):
    """Payload format expected by the receiving webhook endpoint."""

    GENERIC = "GENERIC"
    SLACK = "SLACK"
    DISCORD = "DISCORD"
    TEAMS = "TEAMS"


class AlertSeverity(str, Enum):
    """Human-readable severity tier attached to every outbound alert."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Colour constants used by Slack/Discord embeds (decimal RGB).
_COLOUR_CRITICAL = 0xFF0000   # red
_COLOUR_HIGH = 0xFF6600       # orange
_COLOUR_MEDIUM = 0xFFCC00     # yellow
_COLOUR_LOW = 0x00AAFF        # blue

_SEVERITY_COLOUR: dict[AlertSeverity, int] = {
    AlertSeverity.CRITICAL: _COLOUR_CRITICAL,
    AlertSeverity.HIGH: _COLOUR_HIGH,
    AlertSeverity.MEDIUM: _COLOUR_MEDIUM,
    AlertSeverity.LOW: _COLOUR_LOW,
}

_SEVERITY_EMOJI: dict[AlertSeverity, str] = {
    AlertSeverity.CRITICAL: "🚨",
    AlertSeverity.HIGH: "⛔",
    AlertSeverity.MEDIUM: "⚠️",
    AlertSeverity.LOW: "ℹ️",
}


@dataclass
class WebhookConfig:
    """Configuration for a single outbound webhook destination.

    Attributes:
        url:     Full HTTPS endpoint URL.
        format:  Payload format the endpoint expects.
        name:    Human-readable label used in logs (e.g. "SOC Slack channel").
        headers: Additional HTTP headers (e.g. authentication tokens).
        enabled: Toggle without removing the config entry.
    """

    url: str
    format: WebhookFormat = WebhookFormat.GENERIC
    name: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    enabled: bool = True


# ---------------------------------------------------------------------------
# Alert data model
# ---------------------------------------------------------------------------


@dataclass
class SecurityAlert:
    """Structured security incident payload dispatched by the responder.

    All fields are safe to serialise to JSON (no custom objects).
    """

    incident_id: str
    timestamp: str                          # ISO 8601 UTC
    sender: str
    subject: str
    message_id: str
    verdict: str                            # "MALICIOUS" | "SUSPICIOUS" | "SAFE"
    risk_score: int
    severity: AlertSeverity
    violations: list[str]                   # policy violation codes
    cloud_intel_summary: dict[str, Any]
    attachment_summaries: list[dict[str, Any]]
    html_evasion_summary: dict[str, Any]
    quarantine_applied: bool = False
    remediation_notes: str = ""

    @classmethod
    def from_scan_report(cls, scan_report: dict[str, Any]) -> "SecurityAlert":
        """Convenience factory: build a SecurityAlert from a scan-report dict.

        Accepts the dictionary format produced by
        ``GmailClient.inspect_message_payload`` or any ``log_scan`` extra dict.
        Missing keys default to safe empty values so the factory never raises.
        """
        verdict = str(scan_report.get("verdict", "SAFE")).upper()
        risk_score = int(scan_report.get("risk_score", 0))
        severity = _derive_severity(verdict, risk_score)

        # Violations may be stored as a list of dicts (with "code" keys) or
        # plain strings – normalise to a flat list of code strings.
        raw_violations: list[Any] = scan_report.get("violations", []) or []
        violations: list[str] = []
        for v in raw_violations:
            if isinstance(v, dict):
                code = v.get("code") or v.get("name") or str(v)
                violations.append(str(code))
            elif isinstance(v, str):
                violations.append(v)

        return cls(
            incident_id=scan_report.get("incident_id") or str(uuid.uuid4()),
            timestamp=scan_report.get("timestamp") or _utc_now(),
            sender=scan_report.get("sender", "unknown"),
            subject=scan_report.get("subject", "(no subject)"),
            message_id=scan_report.get("message_id", ""),
            verdict=verdict,
            risk_score=risk_score,
            severity=severity,
            violations=violations,
            cloud_intel_summary=scan_report.get("cloud_intel", {}) or {},
            attachment_summaries=scan_report.get("attachments", []) or [],
            html_evasion_summary=scan_report.get("html_evasion", {}) or {},
            quarantine_applied=bool(scan_report.get("quarantine_applied", False)),
            remediation_notes=scan_report.get("remediation_notes", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a fully JSON-serialisable dictionary representation."""
        return {
            "incident_id": self.incident_id,
            "timestamp": self.timestamp,
            "sender": self.sender,
            "subject": self.subject,
            "message_id": self.message_id,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "severity": self.severity.value,
            "violations": self.violations,
            "triggered_policy_violations": self.violations,
            "cloud_intel_summary": self.cloud_intel_summary,
            "attachment_summaries": self.attachment_summaries,
            "html_evasion_summary": self.html_evasion_summary,
            "quarantine_applied": self.quarantine_applied,
            "remediation_notes": self.remediation_notes,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _derive_severity(verdict: str, risk_score: int) -> AlertSeverity:
    """Map verdict and risk score to an alert severity tier."""
    if verdict == "MALICIOUS" or risk_score >= 8:
        return AlertSeverity.CRITICAL
    if risk_score >= 5:
        return AlertSeverity.HIGH
    if verdict == "SUSPICIOUS" or risk_score >= 3:
        return AlertSeverity.MEDIUM
    return AlertSeverity.LOW


def _short_violations(violations: list[str], max_items: int = 5) -> str:
    """Return a human-readable bullet list of the top N violations."""
    shown = violations[:max_items]
    extra = len(violations) - len(shown)
    bullets = "\n".join(f"  • {v}" for v in shown)
    if extra > 0:
        bullets += f"\n  • …and {extra} more"
    return bullets or "  • (none)"


# ---------------------------------------------------------------------------
# Payload formatters
# ---------------------------------------------------------------------------


def format_generic_payload(alert: SecurityAlert) -> dict[str, Any]:
    """Build a flat JSON payload suitable for generic SIEM/SOAR endpoints.

    The schema mirrors the STIX-compatible incident format used by most
    enterprise SIEMs (Splunk HEC, Elastic SIEM, QRadar, etc.).
    """
    return {
        "schema_version": "lexiguard/1.0",
        "incident": alert.to_dict(),
    }


def format_slack_payload(alert: SecurityAlert) -> dict[str, Any]:
    """Build a Slack ``blocks`` payload for Slack incoming webhooks.

    Uses Block Kit for rich formatting with color-coded severity sidebars.
    """
    emoji = _SEVERITY_EMOJI[alert.severity]
    title = f"{emoji} LexiGuard Alert – {alert.severity.value} | {alert.verdict}"
    colour_hex = f"#{_SEVERITY_COLOUR[alert.severity]:06X}"

    fields = [
        {"type": "mrkdwn", "text": f"*Sender:*\n{alert.sender}"},
        {"type": "mrkdwn", "text": f"*Subject:*\n{alert.subject}"},
        {"type": "mrkdwn", "text": f"*Risk Score:*\n{alert.risk_score}/10"},
        {"type": "mrkdwn", "text": f"*Verdict:*\n{alert.verdict}"},
        {"type": "mrkdwn", "text": f"*Quarantined:*\n{'Yes ✅' if alert.quarantine_applied else 'No ❌'}"},
        {"type": "mrkdwn", "text": f"*Incident ID:*\n`{alert.incident_id}`"},
    ]

    violations_text = _short_violations(alert.violations)

    return {
        "text": title,
        "attachments": [
            {
                "color": colour_hex,
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": title, "emoji": True},
                    },
                    {
                        "type": "section",
                        "fields": fields,
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Policy Violations:*\n{violations_text}",
                        },
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"🕒 {alert.timestamp}  |  Msg ID: `{alert.message_id}`",
                            }
                        ],
                    },
                ],
            }
        ],
    }


def format_discord_payload(alert: SecurityAlert) -> dict[str, Any]:
    """Build a Discord webhook payload using embeds for rich formatting."""
    emoji = _SEVERITY_EMOJI[alert.severity]
    title = f"{emoji} {alert.severity.value} — {alert.verdict}"
    colour = _SEVERITY_COLOUR[alert.severity]
    violations_text = _short_violations(alert.violations)

    fields = [
        {"name": "Sender", "value": alert.sender or "unknown", "inline": True},
        {"name": "Risk Score", "value": f"{alert.risk_score}/10", "inline": True},
        {"name": "Quarantined", "value": "Yes ✅" if alert.quarantine_applied else "No ❌", "inline": True},
        {"name": "Subject", "value": alert.subject or "(none)", "inline": False},
        {"name": "Policy Violations", "value": violations_text or "(none)", "inline": False},
        {"name": "Incident ID", "value": f"`{alert.incident_id}`", "inline": False},
    ]

    return {
        "username": "LexiGuard Security",
        "avatar_url": "https://raw.githubusercontent.com/google/material-design-icons/master/png/action/security/materialicons/48dp/1x/baseline_security_black_48dp.png",
        "embeds": [
            {
                "title": title,
                "color": colour,
                "fields": fields,
                "footer": {"text": f"LexiGuard Gateway  •  {alert.timestamp}"},
                "timestamp": alert.timestamp,
            }
        ],
    }


def format_teams_payload(alert: SecurityAlert) -> dict[str, Any]:
    """Build a Microsoft Teams 'MessageCard' (Legacy Connector) payload.

    Compatible with both Incoming Webhook connectors and Power Automate flows.
    """
    emoji = _SEVERITY_EMOJI[alert.severity]
    colour_map = {
        AlertSeverity.CRITICAL: "FF0000",
        AlertSeverity.HIGH: "FF6600",
        AlertSeverity.MEDIUM: "FFCC00",
        AlertSeverity.LOW: "0055AA",
    }
    theme_colour = colour_map.get(alert.severity, "0055AA")
    violations_text = _short_violations(alert.violations)

    facts = [
        {"name": "Sender", "value": alert.sender},
        {"name": "Subject", "value": alert.subject},
        {"name": "Risk Score", "value": f"{alert.risk_score}/10"},
        {"name": "Verdict", "value": alert.verdict},
        {"name": "Quarantined", "value": "Yes" if alert.quarantine_applied else "No"},
        {"name": "Incident ID", "value": alert.incident_id},
        {"name": "Timestamp", "value": alert.timestamp},
    ]

    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_colour,
        "summary": f"LexiGuard {alert.severity.value} alert – {alert.verdict}",
        "sections": [
            {
                "activityTitle": f"{emoji} LexiGuard Security Alert",
                "activitySubtitle": f"**{alert.severity.value}** — {alert.verdict}",
                "activityImage": "https://www.gstatic.com/images/icons/material/system/2x/security_grey600_48dp.png",
                "facts": facts,
                "markdown": True,
            },
            {
                "title": "Policy Violations",
                "text": violations_text,
            },
        ],
    }


# ---------------------------------------------------------------------------
# Dispatch layer
# ---------------------------------------------------------------------------


def send_webhook(
    alert: SecurityAlert,
    config: WebhookConfig,
    timeout: int = 10,
    *,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """Dispatch a single alert to one webhook endpoint.

    Args:
        alert:    The security alert to send.
        config:   Destination webhook configuration.
        timeout:  HTTP request timeout in seconds.
        session:  Optional ``requests.Session`` for dependency injection
                  (used in unit tests to avoid real HTTP calls).

    Returns:
        Result dict with keys: ``success`` (bool), ``status_code`` (int | None),
        ``error`` (str | None), ``webhook_name`` (str).
    """
    result: dict[str, Any] = {
        "webhook_name": config.name or config.url,
        "success": False,
        "status_code": None,
        "error": None,
    }

    if not config.enabled:
        result["error"] = "Webhook disabled; skipped."
        logger.debug("Webhook '%s' is disabled – skipping.", config.name)
        return result

    if not config.url:
        result["error"] = "Webhook URL is empty."
        logger.warning("Empty webhook URL in config '%s' – skipping.", config.name)
        return result

    # Select formatter
    formatters = {
        WebhookFormat.SLACK: format_slack_payload,
        WebhookFormat.DISCORD: format_discord_payload,
        WebhookFormat.TEAMS: format_teams_payload,
        WebhookFormat.GENERIC: format_generic_payload,
    }
    payload = formatters.get(config.format, format_generic_payload)(alert)

    # Merge custom headers
    headers = {"Content-Type": "application/json", "User-Agent": "LexiGuard-Gateway/1.0"}
    headers.update(config.headers or {})

    http = session or requests.Session()
    try:
        resp = http.post(config.url, json=payload, headers=headers, timeout=timeout)
        result["status_code"] = resp.status_code
        if resp.ok:
            result["success"] = True
            logger.info(
                "Webhook '%s' delivered successfully (HTTP %s).",
                config.name,
                resp.status_code,
            )
        else:
            result["error"] = f"HTTP {resp.status_code}: {resp.text[:200]}"
            logger.warning(
                "Webhook '%s' returned non-OK status %s: %s",
                config.name,
                resp.status_code,
                resp.text[:200],
            )
    except requests.exceptions.Timeout:
        result["error"] = f"Request timed out after {timeout}s."
        logger.error("Webhook '%s' timed out.", config.name)
    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"Connection error: {exc}"
        logger.error("Webhook '%s' connection error: %s", config.name, exc)
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"Unexpected error: {type(exc).__name__}: {exc}"
        logger.exception("Unexpected error dispatching webhook '%s'.", config.name)

    return result


def broadcast_alert(
    alert: SecurityAlert,
    webhook_configs: list[WebhookConfig],
    timeout: int = 10,
    *,
    session: requests.Session | None = None,
) -> list[dict[str, Any]]:
    """Dispatch an alert to every configured webhook, collecting results.

    Failures on individual webhooks are logged but do NOT abort the broadcast
    loop – all configured endpoints are attempted regardless.

    Args:
        alert:           The security alert to broadcast.
        webhook_configs: List of ``WebhookConfig`` destinations.
        timeout:         Per-request HTTP timeout in seconds.
        session:         Optional shared ``requests.Session`` (useful for tests).

    Returns:
        List of per-webhook result dicts (same shape as ``send_webhook``).
    """
    results: list[dict[str, Any]] = []
    if not webhook_configs:
        logger.debug("broadcast_alert called with no webhook configs; nothing to send.")
        return results

    for config in webhook_configs:
        result = send_webhook(alert, config, timeout=timeout, session=session)
        results.append(result)

    successes = sum(1 for r in results if r["success"])
    logger.info(
        "Alert broadcast complete: %d/%d webhooks succeeded.",
        successes,
        len(results),
    )
    return results


def send_security_alert(
    alert_or_scan_report: SecurityAlert | dict[str, Any],
    webhook_url_or_config: str | WebhookConfig,
    format: WebhookFormat = WebhookFormat.GENERIC,
    timeout: int = 10,
    *,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """Format and send a standard JSON security alert payload to a webhook URL.

    Accepts either an existing SecurityAlert instance or a scan_report dictionary,
    and either a direct webhook endpoint URL string or a WebhookConfig object.

    Args:
        alert_or_scan_report:  SecurityAlert or scan report dictionary containing
                               incident_id, timestamp, sender, subject, message_id,
                               verdict, risk_score, triggered_policy_violations,
                               cloud_intel_summary, etc.
        webhook_url_or_config: Destination URL string or WebhookConfig object.
        format:                Payload format when a string URL is supplied.
        timeout:               HTTP request timeout in seconds.
        session:               Optional requests.Session for testing.

    Returns:
        Result dictionary with keys: success, status_code, error, webhook_name.
    """
    if isinstance(alert_or_scan_report, dict):
        alert = SecurityAlert.from_scan_report(alert_or_scan_report)
    else:
        alert = alert_or_scan_report

    if isinstance(webhook_url_or_config, str):
        config = WebhookConfig(url=webhook_url_or_config, format=format)
    else:
        config = webhook_url_or_config

    return send_webhook(alert, config, timeout=timeout, session=session)

