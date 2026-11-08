"""LexiGuard Phase 5.2 – Incident Response Orchestrator.

Provides the main action engine that evaluates scan reports, applies the
quarantine policy via the Gmail API, dispatches webhook alerts, and logs
remediation audit records back to SQLite.

Design principles
-----------------
* All Gmail API interactions accept an injectable ``service`` object so
  unit tests can run completely offline with mocks.
* Thresholds are driven by the same constants used in ``lexiguard.scorer``
  (``MALICIOUS_SCORE_THRESHOLD = 8``, ``SUSPICIOUS_SCORE_MIN = 3``).
* No function silently swallows exceptions that alter business logic;
  errors are captured in the returned result dict and logged.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lexiguard.db.database import log_scan
from lexiguard.response.webhooks import (
    AlertSeverity,
    SecurityAlert,
    WebhookConfig,
    broadcast_alert,
    send_security_alert,
)
from lexiguard.scorer import MALICIOUS_SCORE_THRESHOLD, SUSPICIOUS_SCORE_MIN, Verdict

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Gmail nested-label name created for quarantine isolation.
QUARANTINE_LABEL_NAME = "[LexiGuard]/Quarantine"

#: Gmail system labels removed when a message is quarantined.
_INBOX_LABELS_TO_REMOVE = ["INBOX", "UNREAD"]

# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass
class ResponseResult:
    """Structured outcome of a single ``orchestrate_response`` call.

    Attributes:
        incident_id:         UUID for the incident (links logs, webhooks, DB rows).
        verdict:             The evaluated verdict string from the scan report.
        risk_score:          Numeric risk score (0-10+).
        quarantine_attempted: True if a quarantine action was initiated.
        quarantine_success:  True if the Gmail API call succeeded.
        quarantine_error:    Error description if quarantine failed.
        webhook_results:     Per-webhook send result dicts.
        db_scan_id:          Rowid of the remediation record inserted into SQLite.
        actions_taken:       Human-readable list of completed actions.
        skipped:             True when the verdict is SAFE and no action is needed.
    """

    incident_id: str
    verdict: str
    risk_score: int
    quarantine_attempted: bool = False
    quarantine_success: bool = False
    quarantine_error: str | None = None
    webhook_results: list[dict[str, Any]] = field(default_factory=list)
    db_scan_id: int = 0
    actions_taken: list[str] = field(default_factory=list)
    skipped: bool = False


# ---------------------------------------------------------------------------
# Gmail quarantine helpers
# ---------------------------------------------------------------------------


def get_or_create_quarantine_label(service: Any) -> str:
    """Return the Gmail label ID for ``[LexiGuard]/Quarantine``, creating it if absent.

    Args:
        service: Authorized Google API Gmail resource object
                 (``googleapiclient.discovery.build('gmail', 'v1', ...)``).

    Returns:
        The Gmail label ID string (e.g. ``"Label_1234567890"``)

    Raises:
        googleapiclient.errors.HttpError: Propagated if the Gmail API returns
            an error other than a label already-exists conflict.
        Exception: Any other unexpected error from the API client.
    """
    labels_response: dict[str, Any] = (
        service.users().labels().list(userId="me").execute()
    )
    existing: list[dict[str, Any]] = labels_response.get("labels", [])

    for lbl in existing:
        if lbl.get("name") == QUARANTINE_LABEL_NAME:
            label_id: str = lbl["id"]
            logger.debug(
                "Quarantine label '%s' already exists (id=%s).",
                QUARANTINE_LABEL_NAME,
                label_id,
            )
            return label_id

    # Label does not exist – create it.
    logger.info(
        "Creating quarantine label '%s' in Gmail.", QUARANTINE_LABEL_NAME
    )
    new_label: dict[str, Any] = (
        service.users()
        .labels()
        .create(
            userId="me",
            body={
                "name": QUARANTINE_LABEL_NAME,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            },
        )
        .execute()
    )
    label_id = new_label["id"]
    logger.info(
        "Quarantine label created successfully (id=%s).", label_id
    )
    return label_id


def quarantine_message(
    message_id: str,
    service: Any,
) -> dict[str, Any]:
    """Move a Gmail message out of INBOX into the ``[LexiGuard]/Quarantine`` label.

    Steps:
    1. Retrieve or create the quarantine label ID.
    2. Call ``messages.modify`` to add the label and remove INBOX/UNREAD.

    Args:
        message_id: Gmail message resource ID (e.g. ``"18c4f3a1b2d9e0f1"``).
        service:    Authorized Gmail API service object.

    Returns:
        Result dict::

            {
                "success": bool,
                "message_id": str,
                "label_id": str | None,
                "label_name": str,
                "error": str | None,
            }

    Note:
        The Gmail OAuth scope **must** include
        ``https://www.googleapis.com/auth/gmail.modify``.  If only
        ``gmail.readonly`` is granted the API will return HTTP 403 and
        ``success`` will be ``False``.
    """
    result: dict[str, Any] = {
        "success": False,
        "message_id": message_id,
        "label_id": None,
        "label_name": QUARANTINE_LABEL_NAME,
        "error": None,
    }

    if not message_id:
        result["error"] = "message_id is empty; cannot quarantine."
        logger.warning("quarantine_message called with empty message_id.")
        return result

    try:
        label_id = get_or_create_quarantine_label(service)
        result["label_id"] = label_id

        service.users().messages().modify(
            userId="me",
            id=message_id,
            body={
                "addLabelIds": [label_id],
                "removeLabelIds": _INBOX_LABELS_TO_REMOVE,
            },
        ).execute()

        result["success"] = True
        logger.info(
            "Message '%s' quarantined successfully under label '%s' (%s).",
            message_id,
            QUARANTINE_LABEL_NAME,
            label_id,
        )
    except Exception as exc:  # noqa: BLE001
        error_msg = f"{type(exc).__name__}: {exc}"
        result["error"] = error_msg
        logger.error(
            "Failed to quarantine message '%s': %s", message_id, error_msg
        )

    return result


# ---------------------------------------------------------------------------
# Alert builder
# ---------------------------------------------------------------------------


def build_security_alert(
    scan_report: dict[str, Any],
    *,
    incident_id: str | None = None,
    quarantine_applied: bool = False,
    remediation_notes: str = "",
) -> SecurityAlert:
    """Construct a ``SecurityAlert`` from a LexiGuard scan-report dictionary.

    The scan report is the dict returned by
    ``GmailClient.inspect_message_payload()`` or assembled from ``log_scan``
    parameters.  Missing keys are tolerated gracefully.

    Args:
        scan_report:        Raw scan result dict.
        incident_id:        Optional UUID override; generated if omitted.
        quarantine_applied: Whether the quarantine action was successfully executed.
        remediation_notes:  Freeform notes appended to the alert.

    Returns:
        A fully populated :class:`SecurityAlert` instance.
    """
    if incident_id is None:
        # Attempt a deterministic ID from message_id so duplicate triggers
        # for the same email produce the same incident reference.
        msg_id = scan_report.get("message_id", "")
        incident_id = (
            str(uuid.uuid5(uuid.NAMESPACE_URL, msg_id)) if msg_id else str(uuid.uuid4())
        )

    enriched = dict(scan_report)
    enriched["incident_id"] = incident_id
    enriched["timestamp"] = scan_report.get("timestamp") or _utc_now()
    enriched["quarantine_applied"] = quarantine_applied
    enriched["remediation_notes"] = remediation_notes

    return SecurityAlert.from_scan_report(enriched)


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------


def orchestrate_response(
    scan_report: dict[str, Any],
    *,
    service: Any = None,
    webhook_configs: list[WebhookConfig] | None = None,
    db_path: Path | None = None,
) -> ResponseResult:
    """Evaluate a scan report and execute the appropriate incident-response actions.

    Policy thresholds
    -----------------
    * ``MALICIOUS`` OR ``risk_score >= 8`` → Quarantine + HIGH-severity webhook
    * ``SUSPICIOUS`` OR ``risk_score >= 3`` → Alert-only webhook (no quarantine)
    * ``SAFE`` / below thresholds → No action (``skipped=True``)

    Args:
        scan_report:     LexiGuard scan result dict (from ``inspect_message_payload``
                         or manual assembly).
        service:         Authorized Gmail API service object.  Required for quarantine;
                         if ``None`` quarantine is attempted but will fail gracefully.
        webhook_configs: List of webhook destinations.  Pass ``[]`` or ``None`` to
                         suppress outbound alerts (useful in offline/test scenarios).
        db_path:         Override SQLite DB path.  Uses ``DEFAULT_DB_PATH`` when omitted.

    Returns:
        :class:`ResponseResult` with a full record of every action taken or skipped.
    """
    verdict_str = str(scan_report.get("verdict", "SAFE")).upper()
    risk_score = int(scan_report.get("risk_score", 0))
    message_id = scan_report.get("message_id", "")

    # Generate a stable incident_id for the entire response lifecycle.
    incident_id = (
        str(uuid.uuid5(uuid.NAMESPACE_URL, message_id))
        if message_id
        else str(uuid.uuid4())
    )

    result = ResponseResult(
        incident_id=incident_id,
        verdict=verdict_str,
        risk_score=risk_score,
    )

    # ------------------------------------------------------------------
    # Threshold evaluation
    # ------------------------------------------------------------------
    is_malicious = verdict_str == Verdict.MALICIOUS.value or risk_score >= MALICIOUS_SCORE_THRESHOLD
    is_suspicious = verdict_str == Verdict.SUSPICIOUS.value or risk_score >= SUSPICIOUS_SCORE_MIN

    if not is_malicious and not is_suspicious:
        result.skipped = True
        logger.debug(
            "orchestrate_response: verdict=%s score=%d – no action required.",
            verdict_str,
            risk_score,
        )
        return result

    # ------------------------------------------------------------------
    # Step 1: Quarantine (MALICIOUS only)
    # ------------------------------------------------------------------
    quarantine_applied = False

    if is_malicious:
        if service is not None:
            logger.info(
                "Incident %s: verdict=%s – initiating quarantine for message '%s'.",
                incident_id,
                verdict_str,
                message_id,
            )
            q_result = quarantine_message(message_id, service)
            result.quarantine_attempted = True
            result.quarantine_success = q_result["success"]
            result.quarantine_error = q_result.get("error")
            quarantine_applied = q_result["success"]

            if quarantine_applied:
                result.actions_taken.append(
                    f"Quarantined to '{QUARANTINE_LABEL_NAME}' (label={q_result.get('label_id')})"
                )
            else:
                result.actions_taken.append(
                    f"Quarantine attempted but failed: {q_result.get('error')}"
                )
        else:
            logger.warning(
                "Incident %s: MALICIOUS verdict but no Gmail service provided – "
                "quarantine skipped.",
                incident_id,
            )
            result.quarantine_attempted = False
            result.actions_taken.append("Quarantine skipped (no Gmail service provided).")

    # ------------------------------------------------------------------
    # Step 2: Build alert & broadcast webhooks
    # ------------------------------------------------------------------
    remediation_notes = _build_remediation_notes(
        verdict_str, risk_score, quarantine_applied, result.quarantine_error
    )

    alert = build_security_alert(
        scan_report,
        incident_id=incident_id,
        quarantine_applied=quarantine_applied,
        remediation_notes=remediation_notes,
    )

    configs = webhook_configs or []
    if configs:
        logger.info(
            "Incident %s: broadcasting alert to %d webhook(s).",
            incident_id,
            len(configs),
        )
        result.webhook_results = broadcast_alert(alert, configs)
        successful_hooks = sum(1 for r in result.webhook_results if r["success"])
        result.actions_taken.append(
            f"Alert dispatched to {successful_hooks}/{len(configs)} webhook(s)."
        )
    else:
        logger.debug("Incident %s: no webhook configs supplied.", incident_id)

    # ------------------------------------------------------------------
    # Step 3: Persist remediation record to SQLite
    # ------------------------------------------------------------------
    extra_payload: dict[str, Any] = {
        "incident_id": incident_id,
        "phase": "5.2_response",
        "quarantine_attempted": result.quarantine_attempted,
        "quarantine_success": result.quarantine_success,
        "quarantine_error": result.quarantine_error,
        "webhook_results": result.webhook_results,
        "actions_taken": result.actions_taken,
        "remediation_notes": remediation_notes,
        "severity": alert.severity.value,
    }

    try:
        scan_id = log_scan(
            message_id=f"response_{incident_id}",
            sender=scan_report.get("sender", ""),
            subject=scan_report.get("subject", ""),
            verdict=verdict_str,
            risk_score=risk_score,
            urls=scan_report.get("urls") or [],
            excerpt=f"[Phase 5.2 Response] {remediation_notes}",
            extra=extra_payload,
            db_path=db_path,
        )
        result.db_scan_id = scan_id
        result.actions_taken.append(f"Remediation record logged to SQLite (scan id={scan_id}).")
        logger.info("Incident %s: remediation record saved (id=%d).", incident_id, scan_id)
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "Incident %s: failed to write remediation record to SQLite: %s",
            incident_id,
            exc,
        )

    return result


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_remediation_notes(
    verdict: str,
    risk_score: int,
    quarantine_applied: bool,
    quarantine_error: str | None,
) -> str:
    """Compose a human-readable remediation summary for audit logs."""
    lines = [
        f"Verdict: {verdict}",
        f"Risk Score: {risk_score}/10",
    ]
    if quarantine_applied:
        lines.append(f"Action: Message quarantined to '{QUARANTINE_LABEL_NAME}'.")
    elif quarantine_error:
        lines.append(f"Quarantine failed: {quarantine_error}")
    else:
        if verdict == "MALICIOUS" or risk_score >= MALICIOUS_SCORE_THRESHOLD:
            lines.append("Action: No quarantine (Gmail service not available).")
        else:
            lines.append("Action: Suspicious alert dispatched; no quarantine applied.")
    lines.append("Recommended: Review message and investigate sender domain.")
    return " | ".join(lines)
