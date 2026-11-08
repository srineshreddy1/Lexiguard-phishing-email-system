"""Unit tests for LexiGuard HTML anti-evasion and steganography detection."""

from __future__ import annotations

from lexiguard.evasion.html_guard import (
    EvasionFlag,
    extract_hrefs,
    inspect_html,
    parse_css_color,
    parse_font_size_px,
    strip_html,
)


def test_microscopic_fonts_px() -> None:
    for style in ('style="font-size: 1px"', 'style="font-size: 2px"', 'style="font-size: 0.5px"', 'style="font-size: 0px"'):
        markup = f"<p>Visible <span {style}>HiddenSpam</span> text</p>"
        report = inspect_html(markup)
        assert report["has_evasion"] is True
        assert EvasionFlag.MICROSCOPIC_FONT.value in report["evasion_flags"]
        assert report["microscopic_font_count"] >= 1
        assert "HiddenSpam" in report["hidden_text_snippets"]
        assert "Visible" in report["visible_text"]


def test_microscopic_fonts_pt() -> None:
    # 1pt = 1.33px (< 3px), 2pt = 2.67px (< 3px)
    markup = '<span style="font-size: 1pt">PtOne</span><span style="font-size: 2pt">PtTwo</span>'
    report = inspect_html(markup)
    assert report["has_evasion"] is True
    assert report["microscopic_font_count"] == 2
    assert "PtOne" in report["hidden_text_snippets"]
    assert "PtTwo" in report["hidden_text_snippets"]


def test_microscopic_fonts_em_rem_percent() -> None:
    # 0.1em = 1.6px (< 3px), 10% = 1.6px (< 3px)
    markup = '<span style="font-size: 0.1em">TinyEm</span><span style="font-size: 10%">TinyPercent</span>'
    report = inspect_html(markup)
    assert report["has_evasion"] is True
    assert report["microscopic_font_count"] == 2
    assert "TinyEm" in report["hidden_text_snippets"]


def test_normal_font_size_not_flagged() -> None:
    markup = '<p style="font-size: 14px">Normal body</p><span style="font-size: 1em">Normal em</span>'
    report = inspect_html(markup)
    assert report["has_evasion"] is False
    assert report["microscopic_font_count"] == 0
    assert EvasionFlag.MICROSCOPIC_FONT.value not in report["evasion_flags"]


def test_hidden_css_display_none() -> None:
    markup = '<div style="display: none">Secret payload keywords</div>'
    report = inspect_html(markup)
    assert report["has_evasion"] is True
    assert EvasionFlag.HIDDEN_CSS_DISPLAY_NONE.value in report["evasion_flags"]
    assert "Secret payload keywords" in report["hidden_text_snippets"]


def test_hidden_css_visibility_hidden() -> None:
    markup = '<div style="visibility: hidden">Ghost keywords</div>'
    report = inspect_html(markup)
    assert report["has_evasion"] is True
    assert EvasionFlag.HIDDEN_CSS_VISIBILITY_HIDDEN.value in report["evasion_flags"]
    assert "Ghost keywords" in report["hidden_text_snippets"]


def test_hidden_css_zero_opacity() -> None:
    markup = '<div style="opacity: 0">Faded out</div>'
    report = inspect_html(markup)
    assert report["has_evasion"] is True
    assert EvasionFlag.HIDDEN_CSS_ZERO_OPACITY.value in report["evasion_flags"]
    assert "Faded out" in report["hidden_text_snippets"]


def test_hidden_css_offscreen_positioning() -> None:
    markup = '<div style="position: absolute; left: -9999px">Off-screen lure</div>'
    report = inspect_html(markup)
    assert report["has_evasion"] is True
    assert EvasionFlag.HIDDEN_CSS_OFFSCREEN.value in report["evasion_flags"]
    assert "Off-screen lure" in report["hidden_text_snippets"]


def test_hidden_css_text_indent() -> None:
    markup = '<p style="text-indent: -9999px">Negative indent text</p>'
    report = inspect_html(markup)
    assert report["has_evasion"] is True
    assert EvasionFlag.HIDDEN_CSS_TEXT_INDENT.value in report["evasion_flags"]
    assert "Negative indent text" in report["hidden_text_snippets"]


def test_hidden_css_zero_dimensions_with_hidden_overflow() -> None:
    markup = '<div style="height: 0px; overflow: hidden">Collapsed container</div>'
    report = inspect_html(markup)
    assert report["has_evasion"] is True
    assert EvasionFlag.HIDDEN_CSS_ZERO_SIZE.value in report["evasion_flags"]


def test_hidden_css_clipping() -> None:
    markup = '<div style="clip: rect(0, 0, 0, 0); position: absolute">Clipped out</div>'
    report = inspect_html(markup)
    assert report["has_evasion"] is True
    assert EvasionFlag.HIDDEN_CSS_CLIPPED.value in report["evasion_flags"]


def test_hidden_html_attributes() -> None:
    markup = '<div hidden>Hidden attr</div><span aria-hidden="true">Aria hidden</span>'
    report = inspect_html(markup)
    assert report["has_evasion"] is True
    assert EvasionFlag.HIDDEN_HTML_ATTRIBUTE.value in report["evasion_flags"]
    assert report["hidden_elements_count"] >= 2


def test_color_matching_white_on_white() -> None:
    markup = '<span style="color: #ffffff; background-color: #ffffff">Steganography</span>'
    report = inspect_html(markup)
    assert report["has_evasion"] is True
    assert EvasionFlag.COLOR_MATCHING_EVASION.value in report["evasion_flags"]
    assert report["color_matching_count"] >= 1
    assert "Steganography" in report["hidden_text_snippets"]


def test_color_matching_black_on_black() -> None:
    markup = '<span style="color: #000000; background-color: #000000">Dark lure</span>'
    report = inspect_html(markup)
    assert report["has_evasion"] is True
    assert EvasionFlag.COLOR_MATCHING_EVASION.value in report["evasion_flags"]


def test_color_matching_transparent_text() -> None:
    markup = '<span style="color: transparent">See through</span><span style="color: rgba(255,255,255,0)">Zero Alpha</span>'
    report = inspect_html(markup)
    assert report["has_evasion"] is True
    assert EvasionFlag.TRANSPARENT_TEXT.value in report["evasion_flags"]
    assert report["color_matching_count"] == 2


def test_color_matching_default_email_canvas() -> None:
    # Default email canvas is white; white text on it is color-matching evasion
    markup = '<p style="color: #ffffff">White text on canvas</p>'
    report = inspect_html(markup)
    assert report["has_evasion"] is True
    assert EvasionFlag.COLOR_MATCHING_EVASION.value in report["evasion_flags"]


def test_deceptive_anchor_text_phishing() -> None:
    markup = '<a href="https://evil-phish.cc/login">https://www.paypal.com/signin</a>'
    report = inspect_html(markup)
    assert report["has_evasion"] is True
    assert EvasionFlag.DECEPTIVE_ANCHOR_TEXT.value in report["evasion_flags"]
    assert report["deceptive_link_count"] == 1
    match = report["deceptive_links"][0]
    assert match["displayed_domain"] == "paypal.com"
    assert match["destination_domain"] == "evil-phish.cc"


def test_safe_anchor_text_aligned() -> None:
    markup = '<a href="https://login.paypal.com/signin">paypal.com</a>'
    report = inspect_html(markup)
    assert report["deceptive_link_count"] == 0
    assert EvasionFlag.DECEPTIVE_ANCHOR_TEXT.value not in report["evasion_flags"]


def test_tracking_pixel_detection() -> None:
    markup = '<img src="https://telemetry.beacon/pixel.gif" width="1" height="1" />'
    report = inspect_html(markup)
    assert report["has_evasion"] is True
    assert EvasionFlag.TRACKING_PIXEL.value in report["evasion_flags"]


def test_script_and_event_handler_detection() -> None:
    markup = '<script>evilPayload()</script><img src="x" onerror="alert(1)" />'
    report = inspect_html(markup)
    assert report["has_evasion"] is True
    assert EvasionFlag.SUSPICIOUS_SCRIPT_TAG.value in report["evasion_flags"]
    assert EvasionFlag.SUSPICIOUS_EVENT_HANDLER.value in report["evasion_flags"]


def test_strip_html_and_extract_hrefs_compatibility() -> None:
    html = '<p>Hello <a href="https://example.com/test">Click</a><span style="display:none">Hidden</span></p>'
    text = strip_html(html)
    assert "Hello" in text
    assert "Hidden" not in text

    hrefs = extract_hrefs(html)
    assert "https://example.com/test" in hrefs
