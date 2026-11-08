"""Secure Gmail API ingestion gateway for LexiGuard.

Provides OAuth 2.0 polling, MIME message decoding, Unicode sanitization,
HTML evasion inspection, attachment threat scanning, URL static scoring,
Universal Cryptographic Authentication verification, and automated SQLite audit persistence.
"""

from __future__ import annotations

import base64
import email.utils
import json
import logging
import os
from pathlib import Path
import re
import stat
from typing import Any, Optional, TypedDict

logger = logging.getLogger("LexiGuard.GmailGateway")

# Cross-platform resolution of credentials and token files
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def get_credentials_path() -> Path:
    """Resolve credentials.json across project roots and known environments."""
    env_p = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
    candidates = [
        Path.cwd() / "credentials.json",
        _PROJECT_ROOT / "credentials.json",
        Path.home() / ".lexiguard" / "credentials.json",
    ]
    if env_p:
        candidates.insert(0, Path(env_p))
    for c in candidates:
        if c.exists():
            return c
    return _PROJECT_ROOT / "credentials.json"


def get_token_path() -> Path:
    """Resolve token.json across project roots and known environments."""
    candidates = [
        Path.cwd() / "token.json",
        _PROJECT_ROOT / "token.json",
        Path.home() / ".lexiguard" / "token.json",
    ]
    for c in candidates:
        if c.exists():
            return c
    return _PROJECT_ROOT / "token.json"


CREDENTIALS_PATH = get_credentials_path()
TOKEN_PATH = get_token_path()
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]


class EmailScanReport(TypedDict, total=False):
    message_id: str
    sender: str
    subject: str
    verdict: str
    risk_score: int
    extracted_urls: list[str]
    analysis_results: list[dict[str, Any]]
    db_scan_ids: list[int]
    html_report: dict[str, Any]
    attachment_reports: list[dict[str, Any]]


def _secure_file_permissions(file_path: Path) -> None:
    """Restrict file permissions to owner read/write only."""
    try:
        if file_path.exists():
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass


def get_gmail_service() -> Any:
    """Authenticate securely via OAuth 2.0 and return the authorized Gmail API service."""
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build

    creds: Optional[Credentials] = None
    if TOKEN_PATH.exists():
        try:
            creds = Credentials.from_authorized_user_file(str(TOKEN_PATH), SCOPES)
        except Exception:
            creds = None

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as refresh_err:
                logger.warning("Token refresh failed (%s). Triggering fresh login flow...", refresh_err)
                creds = None
                if TOKEN_PATH.exists():
                    try:
                        TOKEN_PATH.unlink()
                    except Exception:
                        pass

        if not creds or not creds.valid:
            target_creds = get_credentials_path()
            if not target_creds.exists():
                raise FileNotFoundError(
                    f"Google OAuth credentials file missing at {target_creds}."
                )
            
            # Check client type: InstalledAppFlow requires 'installed' (Desktop app)
            try:
                with open(target_creds, "r", encoding="utf-8") as f:
                    c_json = json.load(f)
                if "web" in c_json and "installed" not in c_json:
                    raise ValueError(
                        "Google OAuth client type mismatch: credentials.json is configured as a 'Web application'. "
                        "Google blocks local desktop authentication on Web client IDs (Error 400). "
                        "Please create an OAuth Client ID with Application type: 'Desktop app' in Google Cloud Console."
                    )
            except ValueError:
                raise
            except Exception:
                pass

            flow = InstalledAppFlow.from_client_secrets_file(str(target_creds), SCOPES)
            creds = flow.run_local_server(port=0)

        with open(TOKEN_PATH, "w", encoding="utf-8") as token_file:
            token_file.write(creds.to_json())
        _secure_file_permissions(TOKEN_PATH)

    return build("gmail", "v1", credentials=creds)


def process_unread_inbox(max_results: int = 5) -> list[dict[str, Any]]:
    """Fetch unread emails, sanitize payloads, evaluate risks, and log to SQLite.

    Pipeline Flow:
    1. Authenticates via Google OAuth 2.0.
    2. Polls Gmail API for unread messages (q="is:unread").
    3. Runs complete inspection via GmailClient (HTML stego, magic-byte attachments, URL scoring).
    4. Automatically persists audit trail to SQLite scans ledger.
    """
    try:
        service = get_gmail_service()
        client = GmailClient(service=service)
        response = service.users().messages().list(
            userId="me", q="is:unread", maxResults=max(1, int(max_results))
        ).execute()
    except Exception as exc:
        logger.warning("Could not poll unread Gmail messages: %s", exc)
        raise exc

    messages = response.get("messages", [])
    scan_reports: list[dict[str, Any]] = []

    for msg_stub in messages:
        msg_id = msg_stub.get("id")
        if not msg_id:
            continue
        try:
            msg = service.users().messages().get(
                userId="me", id=msg_id, format="full"
            ).execute()
            report = client.inspect_message_payload(msg)
            report["extracted_urls"] = report.get("urls", [])
            report["analysis_results"] = report.get("url_scores", [])
            scan_reports.append(report)
        except Exception as err:
            logger.warning("Skipping message %s due to retrieval error: %s", msg_id, err)

    return scan_reports


from lexiguard.core.parser import parse_url
from lexiguard.db.database import log_scan, lookup_threat
from lexiguard.evasion.html_guard import extract_hrefs, inspect_html, strip_html
from lexiguard.evasion.unicode_guard import sanitize_text, sanitize_url
from lexiguard.features import extract_features
from lexiguard.gateway.attachments import (
    AttachmentReport,
    AttachmentVerdict,
    inspect_all_attachments,
)
from lexiguard.scorer import Verdict, score_risk


# Industry standard verified Email Service Providers (ESPs) and transactional gateways
VERIFIED_MAILING_PROVIDERS: tuple[str, ...] = (
    "sendgrid.net", "sendgrid.com", "sendgrid.info",
    "mailgun.org", "mailgun.net", "mailgun.com",
    "amazonses.com", "awstrack.me",
    "postmarkapp.com", "pstmrk.it",
    "mailchimp.com", "mcsv.net", "mcdlv.net", "list-manage.com",
    "google.com", "googlemail.com", "gmail.com",
    "protection.outlook.com", "microsoft.com", "office365.com", "outlook.com",
    "hubspot.com", "hubspotemail.net",
    "salesforce.com", "exacttarget.com",
    "klaviyo.com", "constantcontact.com",
    "sparkpostmail.com", "sparkpost.com",
    "sendinblue.com", "brevo.com",
    "createsend.com", "cmail19.com", "cmail20.com",
    "linkedin.com", "licdn.com",
    "github.com", "stripe.com",
)

# Major enterprise brands for display-name spoofing detection
WELL_KNOWN_BRANDS: dict[str, tuple[str, ...]] = {
    "google": ("google.com", "googlemail.com", "gmail.com", "youtube.com"),
    "microsoft": ("microsoft.com", "office.com", "office365.com", "outlook.com", "live.com", "msn.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazonses.com", "aws.amazon.com"),
    "paypal": ("paypal.com", "paypal.co.uk"),
    "linkedin": ("linkedin.com", "licdn.com"),
    "netflix": ("netflix.com",),
    "facebook": ("facebook.com", "meta.com", "fb.com"),
    "meta": ("meta.com", "facebook.com", "instagram.com"),
    "instagram": ("instagram.com",),
    "twitter": ("twitter.com", "x.com"),
    "github": ("github.com",),
    "dropbox": ("dropbox.com",),
    "chase": ("chase.com",),
    "wells fargo": ("wellsfargo.com",),
    "bank of america": ("bankofamerica.com",),
    "citibank": ("citi.com", "citigroup.com"),
}


def detect_display_name_spoofing(sender_header: str) -> bool:
    """Detect display name impersonation attacks.

    Flags cases where the display name explicitly references a major brand
    (e.g. 'PayPal Security') while the actual sender email domain is unrelated.
    """
    if not sender_header:
        return False
    name, email_addr = email.utils.parseaddr(sender_header)
    if not name or not email_addr or "@" not in email_addr:
        return False

    sender_domain = email_addr.split("@")[-1].strip().lower()
    name_lower = name.lower()

    for brand, authorized_domains in WELL_KNOWN_BRANDS.items():
        if re.search(rf"\b{re.escape(brand)}\b", name_lower):
            is_authorized = any(
                sender_domain == dom or sender_domain.endswith("." + dom)
                for dom in authorized_domains
            )
            if not is_authorized:
                return True
    return False


def evaluate_cryptographic_authentication(
    headers_dict: dict[str, str],
    sender_header: str,
) -> dict[str, bool]:
    """Evaluate SPF, DKIM, and DMARC cryptographic posture and domain alignment.

    Universal trust rule (RFC 7489 / DMARC alignment):
    Works for any legitimate company (large enterprise, tech publisher, startup, SaaS)
    that possesses valid cryptographic signatures (SPF or DKIM) aligned with the sender domain
    or an industry-verified mailing gateway (SendGrid, Mailgun, Amazon SES, Google, etc.).
    """
    auth_header = headers_dict.get("authentication-results", "").lower()
    received_spf = headers_dict.get("received-spf", "").lower()

    has_explicit_fail = bool(
        re.search(r"\b(spf|dkim|dmarc)=fail\b", auth_header)
        or received_spf.startswith("fail")
    )

    spf_pass = ("spf=pass" in auth_header) or received_spf.startswith("pass")
    dkim_pass = "dkim=pass" in auth_header
    dmarc_pass = "dmarc=pass" in auth_header

    _, email_addr = email.utils.parseaddr(sender_header)
    sender_domain = email_addr.split("@")[-1].strip().lower() if "@" in email_addr else ""

    # Check verified ESPs
    is_verified_esp = False
    if sender_domain:
        is_verified_esp = any(
            sender_domain == esp or sender_domain.endswith("." + esp)
            for esp in VERIFIED_MAILING_PROVIDERS
        )

    # Check SPF Alignment (RFC 7489 / DMARC):
    # SPF passes and the envelope/authenticated domain matches the From: domain or verified ESP
    spf_aligned = False
    if spf_pass and sender_domain:
        if sender_domain in received_spf or sender_domain in auth_header or is_verified_esp:
            spf_aligned = True

    # Check DKIM Alignment:
    signing_domains = re.findall(r"(?:header\.i=@?|header\.d=)([a-z0-9.\-_]+)", auth_header)
    dkim_aligned = False
    if dkim_pass and sender_domain:
        for s_dom in signing_domains:
            s_dom = s_dom.strip().lower()
            if s_dom == sender_domain or s_dom.endswith("." + sender_domain) or any(s_dom == esp or s_dom.endswith("." + esp) for esp in VERIFIED_MAILING_PROVIDERS):
                dkim_aligned = True
                break
        if not signing_domains and is_verified_esp:
            dkim_aligned = True

    auth_verified = False
    if not has_explicit_fail:
        # Standard DMARC alignment: either aligned SPF pass or aligned DKIM pass satisfies authenticity
        if (spf_pass and dkim_pass) or dmarc_pass or spf_aligned or dkim_aligned:
            auth_verified = True

    return {
        "auth_verified": auth_verified,
        "has_auth_failure": has_explicit_fail,
        "spf_pass": spf_pass,
        "dkim_pass": dkim_pass,
        "dmarc_pass": dmarc_pass,
        "spf_aligned": spf_aligned,
        "dkim_aligned": dkim_aligned,
    }


class GmailClient:
    """Gateway client for polling and processing Gmail messages with LexiGuard."""

    def __init__(
        self,
        service: Any = None,
        db_path: Path | None = None,
    ) -> None:
        """Initialize GmailClient with optional Google API resource and DB path.

        Args:
            service: Authorized Google API client (googleapiclient.discovery.build('gmail', 'v1')).
            db_path: Optional custom Path for SQLite scan persistence.
        """
        self.service = service
        self.db_path = db_path

    def inspect_message_payload(
        self,
        message_dict: dict[str, Any],
    ) -> dict[str, Any]:
        """Process a single Gmail API message resource dictionary.

        Deconstructs headers, decodes text/html bodies, extracts and sanitizes URLs,
        analyzes HTML steganography, scans attachments, executes risk scoring,
        and logs the scan audit record to SQLite.

        Args:
            message_dict: Gmail API message resource dict containing id and payload.

        Returns:
            Dictionary containing processed security scan results.
        """
        message_id = message_dict.get("id", "unknown_id")
        payload = message_dict.get("payload", {})
        headers_list = payload.get("headers", [])
        headers = {h.get("name", "").lower(): h.get("value", "") for h in headers_list}

        sender = sanitize_text(headers.get("from", ""))
        subject = sanitize_text(headers.get("subject", ""))

        # Extract message bodies (plain text and html)
        html_bodies: list[str] = []
        text_bodies: list[str] = []

        def _extract_body(part: dict[str, Any]) -> None:
            mime_type = part.get("mimeType", "")
            body = part.get("body", {})
            data_str = body.get("data")
            if data_str:
                try:
                    padding = (4 - (len(data_str) % 4)) % 4
                    raw_bytes = base64.urlsafe_b64decode(data_str + ("=" * padding))
                    decoded = raw_bytes.decode("utf-8", errors="replace")
                    if mime_type == "text/html":
                        html_bodies.append(decoded)
                    elif mime_type == "text/plain":
                        text_bodies.append(decoded)
                except Exception:
                    pass
            for sub in part.get("parts", []):
                _extract_body(sub)

        _extract_body(payload)

        combined_html = "\n".join(html_bodies)
        combined_text = "\n".join(text_bodies)
        if combined_html:
            visible_text = strip_html(combined_html)
        else:
            visible_text = sanitize_text(combined_text)

        # 1. HTML Anti-evasion analysis
        html_report = inspect_html(combined_html) if combined_html else None

        # 2. Attachment threat analysis
        attachment_reports: list[AttachmentReport] = inspect_all_attachments(
            message_dict, db_path=self.db_path
        )

        # 3. URL extraction & Risk scoring
        discovered_urls: list[str] = []
        if combined_html:
            discovered_urls.extend(extract_hrefs(combined_html))
        if html_report:
            for item in html_report.get("deceptive_links", []):
                discovered_urls.append(item["destination_url"])

        # Extract message headers for authentication and sender domain verification
        headers_dict = {
            (h.get("name") or "").lower(): (h.get("value") or "")
            for h in payload.get("headers", [])
        }

        # Cryptographic Authentication & Domain Spoofing Analysis
        auth_eval = evaluate_cryptographic_authentication(headers_dict, sender)
        auth_verified = auth_eval["auth_verified"]
        has_auth_failure = auth_eval["has_auth_failure"]
        has_display_name_spoofing = detect_display_name_spoofing(sender)

        url_scores: list[dict[str, Any]] = []
        highest_url_score = 0
        overall_url_verdict = Verdict.SAFE
        all_urls_clean_intel = True

        for u in set(discovered_urls):
            sanitized_u = sanitize_url(u)
            if not sanitized_u:
                continue
            parsed = parse_url(sanitized_u)
            feat = extract_features(parsed)
            host = (parsed.get("host") or "").lower()

            # Check local threat intelligence cache (or external feeds)
            intel_entry = lookup_threat(sanitized_u, db_path=self.db_path) or lookup_threat(host, db_path=self.db_path)
            intel_verdict = intel_entry.get("verdict") if intel_entry else None
            intel_clean = (intel_entry is None or intel_verdict == "SAFE")
            intel_is_malicious = (intel_entry is not None and intel_verdict in ("MALICIOUS", "SUSPICIOUS"))

            scored = score_risk(
                feat,
                intel_verdict=intel_verdict,
                threat_intel_clean=intel_clean,
                auth_verified=auth_verified,
                is_trusted_domain=auth_verified,
                has_auth_failure=(has_auth_failure or has_display_name_spoofing),
                has_spoofing_indicators=(has_display_name_spoofing or has_auth_failure),
            )

            if intel_is_malicious:
                scored["verdict"] = Verdict.MALICIOUS if intel_verdict == "MALICIOUS" else Verdict.SUSPICIOUS
                scored["risk_score"] = max(scored["risk_score"], 8 if scored["verdict"] == Verdict.MALICIOUS else 5)
                all_urls_clean_intel = False

            if scored["verdict"] != Verdict.SAFE:
                all_urls_clean_intel = False

            url_scores.append({"url": sanitized_u, "score": scored["risk_score"], "verdict": scored["verdict"].value})
            if scored["risk_score"] > highest_url_score:
                highest_url_score = scored["risk_score"]
            if scored["verdict"] == Verdict.MALICIOUS:
                overall_url_verdict = Verdict.MALICIOUS
            elif scored["verdict"] == Verdict.SUSPICIOUS and overall_url_verdict != Verdict.MALICIOUS:
                overall_url_verdict = Verdict.SUSPICIOUS

        # 4. Gateway Compounding Verdict Calculation
        has_malicious_attachment = any(a["verdict"] == AttachmentVerdict.MALICIOUS for a in attachment_reports)
        has_suspicious_attachment = any(a["verdict"] == AttachmentVerdict.SUSPICIOUS for a in attachment_reports)

        # Active HTML threat detection
        has_active_html_threat = False
        suspicious_code = False
        if html_report and html_report.get("has_evasion"):
            flags = set(html_report.get("evasion_flags", []))
            suspicious_code = bool(flags.intersection({
                "suspicious_script_tag",
                "suspicious_event_handler",
                "suspicious_iframe_tag",
                "base_tag_hijack",
                "dangerous_scheme_url",
            }))
            deceptive_links = False
            for dlink in html_report.get("deceptive_links", []):
                disp = (dlink.get("displayed_text") or "").strip().lower()
                dest = (dlink.get("destination_url") or "").strip().lower()
                if (disp.startswith("http://") or disp.startswith("https://") or disp.startswith("www.")) and not (dest.startswith(disp) or disp in dest):
                    deceptive_links = True
                    break

            # In authentic emails, microscopic font and hidden text are standard preheaders, not attacks
            has_hidden_attack = False
            if not auth_verified or has_auth_failure or has_display_name_spoofing:
                has_hidden_attack = bool(
                    html_report.get("hidden_text_snippets") and
                    (html_report.get("microscopic_font_count", 0) > 0 or html_report.get("color_matching_count", 0) > 0)
                )
            has_active_html_threat = suspicious_code or deceptive_links or has_hidden_attack

        # 5. Universal Authentication & Clean Threat Intel Trust Override
        is_universally_trusted = (
            auth_verified
            and all_urls_clean_intel
            and not has_auth_failure
            and not has_display_name_spoofing
            and not has_malicious_attachment
            and not has_suspicious_attachment
            and not suspicious_code
        )

        if is_universally_trusted:
            final_verdict = "SAFE"
            composite_score = 0
            for u_item in url_scores:
                u_item["score"] = 0
                u_item["verdict"] = "SAFE"
        elif has_malicious_attachment or overall_url_verdict == Verdict.MALICIOUS or (has_display_name_spoofing and has_auth_failure):
            final_verdict = "MALICIOUS"
        elif has_suspicious_attachment or overall_url_verdict == Verdict.SUSPICIOUS or has_active_html_threat or has_display_name_spoofing or has_auth_failure:
            final_verdict = "SUSPICIOUS"
        else:
            final_verdict = "SAFE"

        # Calculate composite score from verified threats if not universally trusted
        if not is_universally_trusted:
            raw_composite = highest_url_score
            if html_report and has_active_html_threat:
                raw_composite += html_report.get("risk_score", 0)
            for a in attachment_reports:
                raw_composite += a["risk_score"]
            if has_display_name_spoofing:
                raw_composite += 5
            if has_auth_failure:
                raw_composite += 4

            if final_verdict == "MALICIOUS":
                composite_score = max(8, min(raw_composite if raw_composite >= 8 else 8, 10))
            elif final_verdict == "SUSPICIOUS":
                composite_score = max(3, min(raw_composite if raw_composite >= 3 else 4, 7))
            else:
                composite_score = min(raw_composite, 2)
        else:
            composite_score = 0

        # 6. SQLite Audit Logging
        extra_meta = {
            "html_evasion": html_report,
            "attachments": [
                {
                    "filename": a["filename"],
                    "verdict": a["verdict"].value,
                    "sha256": a["metadata"]["sha256"],
                    "detected_format": a["metadata"]["detected_format"],
                }
                for a in attachment_reports
            ],
            "url_scores": url_scores,
            "auth_verified": auth_verified,
            "has_auth_failure": has_auth_failure,
            "has_display_name_spoofing": has_display_name_spoofing,
            "is_universally_trusted": is_universally_trusted,
        }

        log_scan(
            message_id=message_id,
            sender=sender,
            subject=subject,
            verdict=final_verdict,
            risk_score=composite_score,
            urls=discovered_urls,
            excerpt=visible_text[:2000],
            extra=extra_meta,
            db_path=self.db_path,
        )

        return {
            "message_id": message_id,
            "sender": sender,
            "subject": subject,
            "verdict": final_verdict,
            "risk_score": composite_score,
            "urls": discovered_urls,
            "html_report": html_report,
            "attachment_reports": attachment_reports,
            "url_scores": url_scores,
            "excerpt": visible_text[:500],
            "auth_verified": auth_verified,
            "is_universally_trusted": is_universally_trusted,
        }
