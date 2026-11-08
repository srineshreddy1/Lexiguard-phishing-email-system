"""Unit tests for Phase 5.2: Incident Response Orchestrator & Webhook Broadcaster.

All tests are fully offline – every network call and Gmail API interaction
is replaced with ``unittest.mock`` objects so the suite passes without any
credentials, tokens, or running services.

Test coverage
-------------
* ``get_or_create_quarantine_label``: label exists vs must-create path.
* ``quarantine_message``: success, missing message_id, Gmail API failure.
* ``build_security_alert``: field mapping, deterministic incident_id, defaults.
* ``format_*_payload``: structural shape validation for all four formats.
* ``send_webhook``: success path, HTTP error, timeout, disabled config.
* ``broadcast_alert``: mixed success/failure across multiple configs.
* ``orchestrate_response``: SAFE (skip), SUSPICIOUS (alert only),
  MALICIOUS (quarantine + alert + DB write).
* ``SecurityAlert.to_dict``: round-trip serialisability.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from lexiguard.response.responder import (
    QUARANTINE_LABEL_NAME,
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


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------


def _make_gmail_service(
    existing_label_name: str | None = None,
    create_label_id: str = "Label_NEW",
) -> MagicMock:
    """Return a mock Gmail API service object.

    Args:
        existing_label_name: If set, that label name is returned in the labels
                             list so the 'already exists' code path is taken.
        create_label_id:     Label id returned by the create() mock.
    """
    service = MagicMock()

    # labels().list()
    labels_list = []
    if existing_label_name:
        labels_list.append({"id": "Label_EXIST", "name": existing_label_name})
    service.users.return_value.labels.return_value.list.return_value.execute.return_value = {
        "labels": labels_list
    }

    # labels().create()
    service.users.return_value.labels.return_value.create.return_value.execute.return_value = {
        "id": create_label_id,
        "name": QUARANTINE_LABEL_NAME,
    }

    # messages().modify()
    service.users.return_value.messages.return_value.modify.return_value.execute.return_value = {
        "id": "msg_001",
        "labelIds": [create_label_id],
    }

    return service


def _make_scan_report(
    verdict: str = "MALICIOUS",
    risk_score: int = 9,
    message_id: str = "test_msg_001",
) -> dict[str, Any]:
    """Return a minimal scan report dict exercising the main response paths."""
    return {
        "message_id": message_id,
        "sender": "attacker@evil.example",
        "subject": "Urgent: Account Suspended",
        "verdict": verdict,
        "risk_score": risk_score,
        "urls": ["https://evil.example/phish"],
        "violations": [
            {"code": "IP_LITERAL_HOST", "severity": "high"},
            {"code": "EXCESSIVE_SUBDOMAINS", "severity": "medium"},
        ],
        "cloud_intel": {
            "virustotal": {"verdict": "MALICIOUS", "positives": 12},
            "webrisk": {"verdict": "MALICIOUS"},
        },
        "attachments": [],
        "html_evasion": {"hidden_elements": 2, "microscopic_fonts": 1},
    }


def _make_webhook_config(
    fmt: WebhookFormat = WebhookFormat.GENERIC,
    enabled: bool = True,
    url: str = "https://siem.example.com/ingest",
) -> WebhookConfig:
    return WebhookConfig(url=url, format=fmt, name="test-hook", enabled=enabled)


def _mock_ok_response(status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.ok = True
    resp.status_code = status_code
    resp.text = "OK"
    return resp


def _mock_error_response(status_code: int = 500) -> MagicMock:
    resp = MagicMock()
    resp.ok = False
    resp.status_code = status_code
    resp.text = "Internal Server Error"
    return resp


# ===========================================================================
# get_or_create_quarantine_label
# ===========================================================================


class TestGetOrCreateQuarantineLabel:
    def test_returns_existing_label_id(self) -> None:
        """If the quarantine label already exists, return its id without calling create()."""
        service = _make_gmail_service(existing_label_name=QUARANTINE_LABEL_NAME)
        label_id = get_or_create_quarantine_label(service)
        assert label_id == "Label_EXIST"
        # create should NOT have been called
        service.users.return_value.labels.return_value.create.assert_not_called()

    def test_creates_label_when_absent(self) -> None:
        """If the label does not exist, create it and return the new label id."""
        service = _make_gmail_service(existing_label_name=None, create_label_id="Label_BRAND_NEW")
        label_id = get_or_create_quarantine_label(service)
        assert label_id == "Label_BRAND_NEW"
        service.users.return_value.labels.return_value.create.assert_called_once()

    def test_passes_correct_label_name_to_create(self) -> None:
        """Verify the exact label name is passed to the Gmail create API."""
        service = _make_gmail_service()
        get_or_create_quarantine_label(service)
        call_kwargs = service.users.return_value.labels.return_value.create.call_args
        body = call_kwargs.kwargs.get("body") or call_kwargs.args[0] if call_kwargs.args else {}
        # body may be a keyword arg
        if not body:
            body = call_kwargs[1].get("body", {})
        assert body.get("name") == QUARANTINE_LABEL_NAME


# ===========================================================================
# quarantine_message
# ===========================================================================


class TestQuarantineMessage:
    def test_success_path_existing_label(self) -> None:
        """Full success: label exists, modify succeeds."""
        service = _make_gmail_service(existing_label_name=QUARANTINE_LABEL_NAME)
        result = quarantine_message("msg_abc", service)
        assert result["success"] is True
        assert result["label_id"] == "Label_EXIST"
        assert result["error"] is None
        assert result["message_id"] == "msg_abc"

    def test_success_path_creates_new_label(self) -> None:
        """Full success: label does not exist, created on-the-fly."""
        service = _make_gmail_service(create_label_id="Label_NEW_123")
        result = quarantine_message("msg_xyz", service)
        assert result["success"] is True
        assert result["label_id"] == "Label_NEW_123"

    def test_empty_message_id_returns_failure(self) -> None:
        """An empty message_id must return success=False without calling the API."""
        service = _make_gmail_service()
        result = quarantine_message("", service)
        assert result["success"] is False
        assert "empty" in (result["error"] or "").lower()
        service.users.return_value.labels.return_value.list.assert_not_called()

    def test_api_exception_captured_gracefully(self) -> None:
        """Gmail API errors are caught and surfaced in the result dict."""
        service = MagicMock()
        service.users.return_value.labels.return_value.list.return_value.execute.side_effect = (
            Exception("API quota exceeded")
        )
        result = quarantine_message("msg_fail", service)
        assert result["success"] is False
        assert "quota exceeded" in (result["error"] or "").lower()

    def test_modify_failure_captured(self) -> None:
        """If messages.modify raises, quarantine returns success=False."""
        service = _make_gmail_service(existing_label_name=QUARANTINE_LABEL_NAME)
        service.users.return_value.messages.return_value.modify.return_value.execute.side_effect = (
            Exception("Forbidden: insufficient scope")
        )
        result = quarantine_message("msg_403", service)
        assert result["success"] is False
        assert result["error"] is not None


# ===========================================================================
# build_security_alert
# ===========================================================================


class TestBuildSecurityAlert:
    def test_fields_mapped_correctly(self) -> None:
        """All key fields from the scan report appear in the alert."""
        report = _make_scan_report()
        alert = build_security_alert(report)
        assert alert.sender == "attacker@evil.example"
        assert alert.subject == "Urgent: Account Suspended"
        assert alert.verdict == "MALICIOUS"
        assert alert.risk_score == 9
        assert alert.severity == AlertSeverity.CRITICAL

    def test_violation_codes_extracted(self) -> None:
        """Policy violation dicts are normalised to a list of code strings."""
        report = _make_scan_report()
        alert = build_security_alert(report)
        assert "IP_LITERAL_HOST" in alert.violations
        assert "EXCESSIVE_SUBDOMAINS" in alert.violations

    def test_deterministic_incident_id_for_same_message(self) -> None:
        """Same message_id always produces the same incident_id."""
        report = _make_scan_report(message_id="stable_msg")
        a1 = build_security_alert(report)
        a2 = build_security_alert(report)
        assert a1.incident_id == a2.incident_id

    def test_different_message_ids_produce_different_incident_ids(self) -> None:
        r1 = _make_scan_report(message_id="msg_A")
        r2 = _make_scan_report(message_id="msg_B")
        assert build_security_alert(r1).incident_id != build_security_alert(r2).incident_id

    def test_quarantine_applied_propagated(self) -> None:
        report = _make_scan_report()
        alert = build_security_alert(report, quarantine_applied=True)
        assert alert.quarantine_applied is True

    def test_custom_incident_id_respected(self) -> None:
        custom_id = "my-custom-uuid"
        report = _make_scan_report()
        alert = build_security_alert(report, incident_id=custom_id)
        assert alert.incident_id == custom_id

    def test_safe_verdict_severity_is_low(self) -> None:
        report = _make_scan_report(verdict="SAFE", risk_score=0)
        alert = build_security_alert(report)
        assert alert.severity == AlertSeverity.LOW

    def test_suspicious_verdict_severity_is_medium(self) -> None:
        report = _make_scan_report(verdict="SUSPICIOUS", risk_score=4)
        alert = build_security_alert(report)
        assert alert.severity == AlertSeverity.MEDIUM


# ===========================================================================
# SecurityAlert.to_dict
# ===========================================================================


class TestSecurityAlertToDict:
    def test_to_dict_is_json_serialisable(self) -> None:
        """to_dict() must produce a dict that json.dumps() accepts without error."""
        report = _make_scan_report()
        alert = build_security_alert(report)
        serialised = json.dumps(alert.to_dict())
        assert isinstance(serialised, str)

    def test_to_dict_contains_all_required_keys(self) -> None:
        required_keys = {
            "incident_id", "timestamp", "sender", "subject", "message_id",
            "verdict", "risk_score", "severity", "violations",
            "cloud_intel_summary", "attachment_summaries", "html_evasion_summary",
            "quarantine_applied", "remediation_notes",
        }
        report = _make_scan_report()
        d = build_security_alert(report).to_dict()
        assert required_keys.issubset(d.keys())


# ===========================================================================
# Payload formatters
# ===========================================================================


def _make_test_alert(verdict: str = "MALICIOUS", score: int = 9) -> SecurityAlert:
    return build_security_alert(_make_scan_report(verdict=verdict, risk_score=score))


class TestFormatGenericPayload:
    def test_has_schema_version(self) -> None:
        payload = format_generic_payload(_make_test_alert())
        assert "schema_version" in payload

    def test_incident_block_present(self) -> None:
        payload = format_generic_payload(_make_test_alert())
        assert "incident" in payload
        assert payload["incident"]["verdict"] == "MALICIOUS"


class TestFormatSlackPayload:
    def test_has_text_key(self) -> None:
        payload = format_slack_payload(_make_test_alert())
        assert "text" in payload

    def test_has_attachments_with_blocks(self) -> None:
        payload = format_slack_payload(_make_test_alert())
        assert "attachments" in payload
        assert len(payload["attachments"]) > 0
        assert "blocks" in payload["attachments"][0]

    def test_colour_present(self) -> None:
        payload = format_slack_payload(_make_test_alert())
        assert "color" in payload["attachments"][0]

    def test_suspicious_payload_shape(self) -> None:
        payload = format_slack_payload(_make_test_alert(verdict="SUSPICIOUS", score=4))
        assert "attachments" in payload

    def test_safe_payload_shape(self) -> None:
        payload = format_slack_payload(_make_test_alert(verdict="SAFE", score=0))
        assert "attachments" in payload


class TestFormatDiscordPayload:
    def test_has_embeds(self) -> None:
        payload = format_discord_payload(_make_test_alert())
        assert "embeds" in payload
        assert len(payload["embeds"]) > 0

    def test_embed_has_colour(self) -> None:
        payload = format_discord_payload(_make_test_alert())
        assert "color" in payload["embeds"][0]

    def test_embed_has_fields(self) -> None:
        payload = format_discord_payload(_make_test_alert())
        assert "fields" in payload["embeds"][0]
        assert len(payload["embeds"][0]["fields"]) > 0


class TestFormatTeamsPayload:
    def test_has_type_message_card(self) -> None:
        payload = format_teams_payload(_make_test_alert())
        assert payload["@type"] == "MessageCard"

    def test_has_sections(self) -> None:
        payload = format_teams_payload(_make_test_alert())
        assert "sections" in payload
        assert len(payload["sections"]) > 0

    def test_has_theme_colour(self) -> None:
        payload = format_teams_payload(_make_test_alert())
        assert "themeColor" in payload


# ===========================================================================
# send_webhook
# ===========================================================================


class TestSendWebhook:
    def _make_session(self, ok: bool = True, status: int = 200) -> MagicMock:
        session = MagicMock(spec=requests.Session)
        resp = _mock_ok_response(status) if ok else _mock_error_response(status)
        session.post.return_value = resp
        return session

    def test_success_generic(self) -> None:
        session = self._make_session()
        config = _make_webhook_config(WebhookFormat.GENERIC)
        result = send_webhook(_make_test_alert(), config, session=session)
        assert result["success"] is True
        assert result["status_code"] == 200
        assert result["error"] is None

    def test_success_slack(self) -> None:
        session = self._make_session()
        config = _make_webhook_config(WebhookFormat.SLACK)
        result = send_webhook(_make_test_alert(), config, session=session)
        assert result["success"] is True

    def test_success_discord(self) -> None:
        session = self._make_session()
        config = _make_webhook_config(WebhookFormat.DISCORD)
        result = send_webhook(_make_test_alert(), config, session=session)
        assert result["success"] is True

    def test_success_teams(self) -> None:
        session = self._make_session()
        config = _make_webhook_config(WebhookFormat.TEAMS)
        result = send_webhook(_make_test_alert(), config, session=session)
        assert result["success"] is True

    def test_http_error_response(self) -> None:
        session = self._make_session(ok=False, status=500)
        config = _make_webhook_config()
        result = send_webhook(_make_test_alert(), config, session=session)
        assert result["success"] is False
        assert result["status_code"] == 500
        assert "500" in (result["error"] or "")

    def test_disabled_config_skipped(self) -> None:
        session = self._make_session()
        config = _make_webhook_config(enabled=False)
        result = send_webhook(_make_test_alert(), config, session=session)
        assert result["success"] is False
        session.post.assert_not_called()

    def test_empty_url_fails_gracefully(self) -> None:
        session = self._make_session()
        config = WebhookConfig(url="", format=WebhookFormat.GENERIC, name="empty")
        result = send_webhook(_make_test_alert(), config, session=session)
        assert result["success"] is False
        session.post.assert_not_called()

    def test_timeout_exception(self) -> None:
        session = MagicMock(spec=requests.Session)
        session.post.side_effect = requests.exceptions.Timeout("connection timed out")
        config = _make_webhook_config()
        result = send_webhook(_make_test_alert(), config, session=session)
        assert result["success"] is False
        assert "timed out" in (result["error"] or "").lower()

    def test_connection_error(self) -> None:
        session = MagicMock(spec=requests.Session)
        session.post.side_effect = requests.exceptions.ConnectionError("refused")
        config = _make_webhook_config()
        result = send_webhook(_make_test_alert(), config, session=session)
        assert result["success"] is False
        assert result["error"] is not None

    def test_webhook_name_in_result(self) -> None:
        session = self._make_session()
        config = WebhookConfig(url="https://x.com/hook", name="MySIEM", format=WebhookFormat.GENERIC)
        result = send_webhook(_make_test_alert(), config, session=session)
        assert result["webhook_name"] == "MySIEM"

    def test_json_body_posted(self) -> None:
        """The payload sent to the session must be a dict (json= kwarg)."""
        session = self._make_session()
        config = _make_webhook_config(WebhookFormat.GENERIC)
        send_webhook(_make_test_alert(), config, session=session)
        _, kwargs = session.post.call_args
        assert "json" in kwargs
        assert isinstance(kwargs["json"], dict)


class TestSendSecurityAlert:
    def test_send_security_alert_with_dict_and_string_url(self) -> None:
        session = MagicMock(spec=requests.Session)
        session.post.return_value = _mock_ok_response()
        report = _make_scan_report(verdict="MALICIOUS", risk_score=9)
        result = send_security_alert(
            report,
            "https://siem.enterprise.local/api/v1/alerts",
            format=WebhookFormat.GENERIC,
            session=session,
        )
        assert result["success"] is True
        session.post.assert_called_once()
        _, kwargs = session.post.call_args
        assert kwargs["json"]["incident"]["verdict"] == "MALICIOUS"
        assert "triggered_policy_violations" in kwargs["json"]["incident"]

    def test_send_security_alert_with_alert_instance_and_config(self) -> None:
        session = MagicMock(spec=requests.Session)
        session.post.return_value = _mock_ok_response()
        alert = _make_test_alert(verdict="SUSPICIOUS", score=5)
        config = WebhookConfig(url="https://hooks.slack.com/services/XYZ", format=WebhookFormat.SLACK)
        result = send_security_alert(alert, config, session=session)
        assert result["success"] is True
        session.post.assert_called_once()
        _, kwargs = session.post.call_args
        assert "attachments" in kwargs["json"]



# ===========================================================================
# broadcast_alert
# ===========================================================================


class TestBroadcastAlert:
    def _session_for_urls(self, url_results: dict[str, bool]) -> MagicMock:
        """Return a session mock where each URL maps to ok=True/False."""
        session = MagicMock(spec=requests.Session)

        def _side_effect(url: str, **kwargs: Any) -> MagicMock:
            ok = url_results.get(url, True)
            return _mock_ok_response() if ok else _mock_error_response()

        session.post.side_effect = _side_effect
        return session

    def test_empty_configs_returns_empty_list(self) -> None:
        results = broadcast_alert(_make_test_alert(), [])
        assert results == []

    def test_single_success(self) -> None:
        session = MagicMock(spec=requests.Session)
        session.post.return_value = _mock_ok_response()
        results = broadcast_alert(_make_test_alert(), [_make_webhook_config()], session=session)
        assert len(results) == 1
        assert results[0]["success"] is True

    def test_mixed_success_failure(self) -> None:
        url_a = "https://a.example.com/hook"
        url_b = "https://b.example.com/hook"
        configs = [
            WebhookConfig(url=url_a, format=WebhookFormat.GENERIC, name="A"),
            WebhookConfig(url=url_b, format=WebhookFormat.SLACK, name="B"),
        ]
        session = self._session_for_urls({url_a: True, url_b: False})
        results = broadcast_alert(_make_test_alert(), configs, session=session)
        assert len(results) == 2
        successes = [r["success"] for r in results]
        assert True in successes
        assert False in successes

    def test_all_configs_attempted_even_if_one_fails(self) -> None:
        """A failure on the first config must not abort the remaining configs."""
        session = MagicMock(spec=requests.Session)
        session.post.side_effect = [
            requests.exceptions.ConnectionError("refused"),
            _mock_ok_response(),
        ]
        configs = [
            WebhookConfig(url="https://x.com/1", name="X1", format=WebhookFormat.GENERIC),
            WebhookConfig(url="https://x.com/2", name="X2", format=WebhookFormat.GENERIC),
        ]
        results = broadcast_alert(_make_test_alert(), configs, session=session)
        assert len(results) == 2
        assert results[1]["success"] is True

    def test_all_disabled_configs_skipped(self) -> None:
        session = MagicMock(spec=requests.Session)
        configs = [
            WebhookConfig(url="https://x.com/hook", name="Disabled", format=WebhookFormat.GENERIC, enabled=False),
        ]
        results = broadcast_alert(_make_test_alert(), configs, session=session)
        assert results[0]["success"] is False
        session.post.assert_not_called()


# ===========================================================================
# orchestrate_response – threshold logic
# ===========================================================================


class TestOrchestrateResponse:
    """Integration-level tests for the main orchestrator."""

    # ------------------------------------------------------------------
    # SAFE → no action
    # ------------------------------------------------------------------

    def test_safe_verdict_skips_all_actions(self, tmp_path: Path) -> None:
        report = _make_scan_report(verdict="SAFE", risk_score=0)
        result = orchestrate_response(report, db_path=tmp_path / "test.db")
        assert result.skipped is True
        assert result.quarantine_attempted is False
        assert result.webhook_results == []

    def test_low_score_below_threshold_skips(self, tmp_path: Path) -> None:
        report = _make_scan_report(verdict="SAFE", risk_score=2)
        result = orchestrate_response(report, db_path=tmp_path / "test.db")
        assert result.skipped is True

    # ------------------------------------------------------------------
    # SUSPICIOUS → alert only
    # ------------------------------------------------------------------

    def test_suspicious_verdict_triggers_alert_not_quarantine(self, tmp_path: Path) -> None:
        report = _make_scan_report(verdict="SUSPICIOUS", risk_score=4)
        session = MagicMock(spec=requests.Session)
        session.post.return_value = _mock_ok_response()
        configs = [_make_webhook_config()]
        service = _make_gmail_service()

        result = orchestrate_response(
            report,
            service=service,
            webhook_configs=configs,
            db_path=tmp_path / "test.db",
        )

        assert result.skipped is False
        assert result.quarantine_attempted is False
        assert result.verdict == "SUSPICIOUS"

    def test_score_3_triggers_alert(self, tmp_path: Path) -> None:
        """risk_score=3 crosses SUSPICIOUS threshold even with SAFE verdict label."""
        report = _make_scan_report(verdict="SAFE", risk_score=3)
        result = orchestrate_response(report, db_path=tmp_path / "test.db")
        assert result.skipped is False

    # ------------------------------------------------------------------
    # MALICIOUS → quarantine + alert + DB
    # ------------------------------------------------------------------

    def test_malicious_triggers_quarantine(self, tmp_path: Path) -> None:
        report = _make_scan_report(verdict="MALICIOUS", risk_score=9)
        service = _make_gmail_service(existing_label_name=QUARANTINE_LABEL_NAME)

        result = orchestrate_response(
            report,
            service=service,
            webhook_configs=[],
            db_path=tmp_path / "test.db",
        )

        assert result.quarantine_attempted is True
        assert result.quarantine_success is True
        assert result.quarantine_error is None

    def test_score_8_triggers_quarantine(self, tmp_path: Path) -> None:
        """risk_score >= 8 treated as MALICIOUS regardless of verdict label."""
        report = _make_scan_report(verdict="SUSPICIOUS", risk_score=8)
        service = _make_gmail_service()

        result = orchestrate_response(
            report,
            service=service,
            webhook_configs=[],
            db_path=tmp_path / "test.db",
        )

        assert result.quarantine_attempted is True

    def test_malicious_without_service_skips_quarantine_gracefully(self, tmp_path: Path) -> None:
        """MALICIOUS but no Gmail service → quarantine_attempted=False, no crash."""
        report = _make_scan_report(verdict="MALICIOUS", risk_score=9)
        result = orchestrate_response(
            report,
            service=None,
            webhook_configs=[],
            db_path=tmp_path / "test.db",
        )
        assert result.quarantine_attempted is False
        assert result.skipped is False

    def test_malicious_quarantine_api_failure_captured(self, tmp_path: Path) -> None:
        """Gmail API failure is captured in quarantine_error; no exception propagates."""
        service = MagicMock()
        service.users.return_value.labels.return_value.list.return_value.execute.side_effect = (
            Exception("API down")
        )
        report = _make_scan_report(verdict="MALICIOUS", risk_score=9)
        result = orchestrate_response(
            report,
            service=service,
            webhook_configs=[],
            db_path=tmp_path / "test.db",
        )
        assert result.quarantine_success is False
        assert result.quarantine_error is not None

    def test_malicious_dispatches_webhooks(self, tmp_path: Path) -> None:
        report = _make_scan_report(verdict="MALICIOUS", risk_score=9)
        service = _make_gmail_service(existing_label_name=QUARANTINE_LABEL_NAME)
        session = MagicMock(spec=requests.Session)
        session.post.return_value = _mock_ok_response()

        # We patch broadcast_alert to avoid real HTTP while still checking it's called.
        with patch(
            "lexiguard.response.responder.broadcast_alert",
            return_value=[{"success": True, "webhook_name": "test", "status_code": 200, "error": None}],
        ) as mock_broadcast:
            result = orchestrate_response(
                report,
                service=service,
                webhook_configs=[_make_webhook_config()],
                db_path=tmp_path / "test.db",
            )
            mock_broadcast.assert_called_once()

        assert len(result.webhook_results) == 1

    def test_db_scan_id_populated(self, tmp_path: Path) -> None:
        """A successful orchestration writes a remediation record and returns its id."""
        report = _make_scan_report(verdict="SUSPICIOUS", risk_score=5)
        result = orchestrate_response(
            report,
            webhook_configs=[],
            db_path=tmp_path / "lexiguard.db",
        )
        assert result.db_scan_id > 0

    def test_incident_id_is_stable_uuid(self, tmp_path: Path) -> None:
        """Same message_id → same incident_id across calls."""
        report = _make_scan_report(message_id="stable_for_id_test")
        r1 = orchestrate_response(report, webhook_configs=[], db_path=tmp_path / "t1.db")
        r2 = orchestrate_response(report, webhook_configs=[], db_path=tmp_path / "t2.db")
        assert r1.incident_id == r2.incident_id

    def test_actions_taken_populated_for_malicious(self, tmp_path: Path) -> None:
        report = _make_scan_report(verdict="MALICIOUS", risk_score=9)
        service = _make_gmail_service(existing_label_name=QUARANTINE_LABEL_NAME)
        result = orchestrate_response(
            report,
            service=service,
            webhook_configs=[],
            db_path=tmp_path / "test.db",
        )
        assert len(result.actions_taken) > 0


# ===========================================================================
# ResponseResult data model
# ===========================================================================


class TestResponseResult:
    def test_default_values(self) -> None:
        r = ResponseResult(incident_id="abc", verdict="SAFE", risk_score=0)
        assert r.quarantine_attempted is False
        assert r.quarantine_success is False
        assert r.webhook_results == []
        assert r.actions_taken == []
        assert r.skipped is False
        assert r.db_scan_id == 0


# ===========================================================================
# WebhookConfig & AlertSeverity enums
# ===========================================================================


class TestWebhookConfigDefaults:
    def test_default_format_is_generic(self) -> None:
        c = WebhookConfig(url="https://x.com/hook")
        assert c.format == WebhookFormat.GENERIC

    def test_enabled_by_default(self) -> None:
        c = WebhookConfig(url="https://x.com/hook")
        assert c.enabled is True

    def test_empty_headers_by_default(self) -> None:
        c = WebhookConfig(url="https://x.com/hook")
        assert c.headers == {}


class TestAlertSeverityDerived:
    def _severity(self, verdict: str, score: int) -> AlertSeverity:
        return build_security_alert(_make_scan_report(verdict=verdict, risk_score=score)).severity

    def test_critical_on_malicious(self) -> None:
        assert self._severity("MALICIOUS", 9) == AlertSeverity.CRITICAL

    def test_critical_on_score_8(self) -> None:
        assert self._severity("SAFE", 8) == AlertSeverity.CRITICAL

    def test_high_on_score_5(self) -> None:
        assert self._severity("SUSPICIOUS", 5) == AlertSeverity.HIGH

    def test_medium_on_score_3(self) -> None:
        assert self._severity("SAFE", 3) == AlertSeverity.MEDIUM

    def test_low_on_score_0(self) -> None:
        assert self._severity("SAFE", 0) == AlertSeverity.LOW
