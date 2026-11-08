"""Local HTML deconstruction and anti-evasion inspection for email bodies.

This module inspects HTML payloads for sophisticated visual and steganographic
evasion techniques used by modern phishing and malware campaigns:
- Hidden CSS styles (display: none, visibility: hidden, opacity: 0, offscreen coordinates,
  negative text indents, clipped elements, zero-dimension containers with hidden overflow).
- Microscopic fonts (< 3px / < 2.25pt / < 0.2em / < 20%) used for Bayesian filter poisoning
  and hiding malicious keywords or seed phrases.
- Text-to-background color-matching evasion (white-on-white, black-on-black, low contrast,
  and transparent text) evaluated against element styles and container/canvas backgrounds.
- Deceptive anchor text (where displayed link text depicts a legitimate domain while
  the actual destination href resolves to a phishing origin).
- Zero-dimension tracking beacons / tracking pixels.
- Suspicious inline scripts, event handlers, and dangerous URL schemes.

All analysis is performed entirely in-memory using deterministic parsing.
This module never renders HTML, executes scripts, or initiates network I/O.
"""

from __future__ import annotations

from enum import Enum
from html.parser import HTMLParser
import math
import re
from typing import Any, NamedTuple, TypedDict
from urllib.parse import unquote, urlparse


class EvasionFlag(str, Enum):
    """Specific evasion techniques detected in HTML / CSS markup."""

    HIDDEN_CSS_DISPLAY_NONE = "HIDDEN_CSS_DISPLAY_NONE"
    HIDDEN_CSS_VISIBILITY_HIDDEN = "HIDDEN_CSS_VISIBILITY_HIDDEN"
    HIDDEN_CSS_ZERO_OPACITY = "HIDDEN_CSS_ZERO_OPACITY"
    HIDDEN_CSS_OFFSCREEN = "HIDDEN_CSS_OFFSCREEN"
    HIDDEN_CSS_TEXT_INDENT = "HIDDEN_CSS_TEXT_INDENT"
    HIDDEN_CSS_ZERO_SIZE = "HIDDEN_CSS_ZERO_SIZE"
    HIDDEN_CSS_CLIPPED = "HIDDEN_CSS_CLIPPED"
    HIDDEN_HTML_ATTRIBUTE = "HIDDEN_HTML_ATTRIBUTE"
    MICROSCOPIC_FONT = "MICROSCOPIC_FONT"
    COLOR_MATCHING_EVASION = "COLOR_MATCHING_EVASION"
    TRANSPARENT_TEXT = "TRANSPARENT_TEXT"
    DECEPTIVE_ANCHOR_TEXT = "DECEPTIVE_ANCHOR_TEXT"
    TRACKING_PIXEL = "TRACKING_PIXEL"
    SUSPICIOUS_SCRIPT_TAG = "SUSPICIOUS_SCRIPT_TAG"
    SUSPICIOUS_EVENT_HANDLER = "SUSPICIOUS_EVENT_HANDLER"
    SUSPICIOUS_IFRAME_TAG = "SUSPICIOUS_IFRAME_TAG"
    BASE_TAG_HIJACK = "BASE_TAG_HIJACK"
    DANGEROUS_SCHEME_URL = "DANGEROUS_SCHEME_URL"


class HtmlViolation(TypedDict):
    """Structured violation record for an identified evasion technique."""

    flag: str
    severity: str  # "low", "medium", "high"
    tag: str
    snippet: str
    evidence: dict[str, Any]


class HtmlEvasionReport(TypedDict):
    """Structured report of all HTML/CSS anti-evasion findings."""

    has_evasion: bool
    evasion_flags: list[str]
    hidden_elements_count: int
    microscopic_font_count: int
    color_matching_count: int
    deceptive_link_count: int
    hidden_text_snippets: list[str]
    deceptive_links: list[dict[str, str]]
    violations: list[HtmlViolation]
    visible_text: str
    hrefs: list[str]
    risk_score: int


# Standard CSS named colors mapped to (R, G, B, Alpha)
_NAMED_COLORS: dict[str, tuple[int, int, int, float]] = {
    "white": (255, 255, 255, 1.0),
    "black": (0, 0, 0, 1.0),
    "red": (255, 0, 0, 1.0),
    "green": (0, 128, 0, 1.0),
    "blue": (0, 0, 255, 1.0),
    "yellow": (255, 255, 0, 1.0),
    "cyan": (0, 255, 255, 1.0),
    "magenta": (255, 0, 255, 1.0),
    "gray": (128, 128, 128, 1.0),
    "grey": (128, 128, 128, 1.0),
    "silver": (192, 192, 192, 1.0),
    "maroon": (128, 0, 0, 1.0),
    "navy": (0, 0, 128, 1.0),
    "olive": (128, 128, 0, 1.0),
    "purple": (128, 0, 128, 1.0),
    "teal": (0, 128, 128, 1.0),
    "orange": (255, 165, 0, 1.0),
    "snow": (255, 250, 250, 1.0),
    "ivory": (255, 255, 240, 1.0),
    "whitesmoke": (245, 245, 245, 1.0),
    "ghostwhite": (248, 248, 255, 1.0),
    "aliceblue": (240, 248, 255, 1.0),
    "linen": (250, 240, 230, 1.0),
    "antiquewhite": (250, 235, 215, 1.0),
    "azure": (240, 255, 255, 1.0),
    "mintcream": (245, 255, 250, 1.0),
    "honeydew": (240, 255, 240, 1.0),
    "floralwhite": (255, 250, 240, 1.0),
    "transparent": (0, 0, 0, 0.0),
    "none": (0, 0, 0, 0.0),
}

_RGBA_RE = re.compile(
    r"^rgba?\s*\(\s*([0-9]*\.?[0-9]+%?)\s*,\s*([0-9]*\.?[0-9]+%?)\s*,\s*([0-9]*\.?[0-9]+%?)(?:\s*,\s*([0-9]*\.?[0-9]+%?))?\s*\)$",
    re.IGNORECASE,
)
_FONT_SIZE_RE = re.compile(
    r"^([0-9]*\.?[0-9]+)\s*(px|pt|em|rem|%|in|cm|mm|pc)?$",
    re.IGNORECASE,
)
_LENGTH_VAL_RE = re.compile(
    r"^(-?[0-9]*\.?[0-9]+)\s*(px|pt|em|rem|%|in|cm|mm|pc)?$",
    re.IGNORECASE,
)
_HREF_RE = re.compile(r"""href\s*=\s*(?P<q>['"])(?P<url>.*?)(?P=q)""", re.IGNORECASE | re.DOTALL)
_STYLE_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_EVENT_HANDLER_RE = re.compile(r"^on[a-z]+$", re.IGNORECASE)
_DOMAIN_LIKE_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)(?::\d+)?(?:/[^\s]*)?$",
    re.IGNORECASE,
)

# Standard default background color of an email canvas
DEFAULT_CANVAS_BG: tuple[int, int, int, float] = (255, 255, 255, 1.0)


def parse_css_color(raw: str | None) -> tuple[int, int, int, float] | None:
    """Parse CSS color declarations (hex, named, rgb, rgba) into (r, g, b, alpha)."""
    if not raw:
        return None
    val = raw.strip().lower().split("!")[0].strip()

    if val in _NAMED_COLORS:
        return _NAMED_COLORS[val]

    if val.startswith("#"):
        hex_str = val[1:]
        try:
            if len(hex_str) == 3:
                r = int(hex_str[0] * 2, 16)
                g = int(hex_str[1] * 2, 16)
                b = int(hex_str[2] * 2, 16)
                return (r, g, b, 1.0)
            elif len(hex_str) == 4:
                r = int(hex_str[0] * 2, 16)
                g = int(hex_str[1] * 2, 16)
                b = int(hex_str[2] * 2, 16)
                a = int(hex_str[3] * 2, 16) / 255.0
                return (r, g, b, round(a, 3))
            elif len(hex_str) == 6:
                r = int(hex_str[0:2], 16)
                g = int(hex_str[2:4], 16)
                b = int(hex_str[4:6], 16)
                return (r, g, b, 1.0)
            elif len(hex_str) == 8:
                r = int(hex_str[0:2], 16)
                g = int(hex_str[2:4], 16)
                b = int(hex_str[4:6], 16)
                a = int(hex_str[6:8], 16) / 255.0
                return (r, g, b, round(a, 3))
        except ValueError:
            return None

    m = _RGBA_RE.match(val)
    if m:
        try:
            parts = []
            for i in range(1, 4):
                p = m.group(i)
                if p.endswith("%"):
                    parts.append(int(round(float(p[:-1]) * 2.55)))
                else:
                    parts.append(int(round(float(p))))
            alpha = 1.0
            if m.group(4) is not None:
                a_str = m.group(4)
                if a_str.endswith("%"):
                    alpha = float(a_str[:-1]) / 100.0
                else:
                    alpha = float(a_str)
            r = max(0, min(255, parts[0]))
            g = max(0, min(255, parts[1]))
            b = max(0, min(255, parts[2]))
            alpha = max(0.0, min(1.0, alpha))
            return (r, g, b, round(alpha, 3))
        except (ValueError, IndexError):
            return None

    return None


def extract_color_from_shorthand(background_val: str) -> tuple[int, int, int, float] | None:
    """Extract a color value from CSS background shorthand (e.g. background: #ffffff url(...))."""
    if not background_val:
        return None
    val = background_val.strip().lower().split("!")[0].strip()
    direct = parse_css_color(val)
    if direct:
        return direct
    hex_m = re.search(r"#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{3,4})", val)
    if hex_m:
        parsed = parse_css_color(hex_m.group(0))
        if parsed:
            return parsed
    rgb_m = re.search(r"rgba?\s*\([^)]+\)", val)
    if rgb_m:
        parsed = parse_css_color(rgb_m.group(0))
        if parsed:
            return parsed
    for name in _NAMED_COLORS:
        if re.search(r"\b" + re.escape(name) + r"\b", val):
            return _NAMED_COLORS[name]
    return None


def parse_font_size_px(raw: str | None) -> float | None:
    """Normalize font-size expressions across units (px, pt, em, rem, %) to pixels."""
    if not raw:
        return None
    val = raw.strip().lower().split("!")[0].strip()
    m = _FONT_SIZE_RE.match(val)
    if not m:
        return None
    try:
        num = float(m.group(1))
        unit = (m.group(2) or "px").lower()
        if unit == "px":
            return num
        elif unit == "pt":
            # 1pt = 1.333333px at 96 DPI
            return num * (96.0 / 72.0)
        elif unit in ("em", "rem"):
            # Base font-size assumed 16px standard
            return num * 16.0
        elif unit == "%":
            return (num / 100.0) * 16.0
        elif unit == "in":
            return num * 96.0
        elif unit == "cm":
            return num * (96.0 / 2.54)
        elif unit == "mm":
            return num * (96.0 / 25.4)
        elif unit == "pc":
            return num * 16.0
        return num
    except ValueError:
        return None


def parse_length_px(raw: str | None) -> float | None:
    """Convert CSS dimension or coordinate strings to pixel float values."""
    if not raw:
        return None
    val = raw.strip().lower().split("!")[0].strip()
    m = _LENGTH_VAL_RE.match(val)
    if not m:
        return None
    try:
        num = float(m.group(1))
        unit = (m.group(2) or "px").lower()
        if unit == "px":
            return num
        elif unit == "pt":
            return num * (96.0 / 72.0)
        elif unit in ("em", "rem"):
            return num * 16.0
        elif unit == "%":
            return num
        return num
    except ValueError:
        return None


def parse_style_string(style_str: str | None) -> dict[str, str]:
    """Parse an inline CSS style attribute into a dictionary of property-value pairs."""
    if not style_str:
        return {}
    cleaned = _STYLE_COMMENT_RE.sub(" ", style_str)
    props: dict[str, str] = {}
    for item in cleaned.split(";"):
        item = item.strip()
        if not item or ":" not in item:
            continue
        key, _, val = item.partition(":")
        k = key.strip().lower()
        v = val.strip()
        if k:
            props[k] = v
    return props


def _luminance(r: int, g: int, b: int) -> float:
    """Calculate WCAG relative luminance for an RGB tuple."""
    def _channel(c: float) -> float:
        c = c / 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def are_colors_matching(
    fg: tuple[int, int, int, float],
    bg: tuple[int, int, int, float],
) -> tuple[bool, str]:
    """Determine whether foreground text is visually indistinguishable from background."""
    if fg[3] <= 0.05:
        return (True, "transparent_text")
    actual_bg = bg if (len(bg) > 3 and bg[3] > 0.05) else DEFAULT_CANVAS_BG
    dist = math.sqrt((fg[0] - actual_bg[0]) ** 2 + (fg[1] - actual_bg[1]) ** 2 + (fg[2] - actual_bg[2]) ** 2)
    if dist < 18.0:
        return (True, f"euclidean_distance_{dist:.1f}")
    l1 = _luminance(fg[0], fg[1], fg[2])
    l2 = _luminance(actual_bg[0], actual_bg[1], actual_bg[2])
    lighter = max(l1, l2)
    darker = min(l1, l2)
    contrast = (lighter + 0.05) / (darker + 0.05)
    if contrast < 1.15:
        return (True, f"low_contrast_ratio_{contrast:.2f}")
    return (False, "")


class _ElementFrame:
    """Tracking frame for nested HTML elements and inherited styling states."""

    def __init__(
        self,
        tag: str,
        attrs: dict[str, str | None],
        effective_bg: tuple[int, int, int, float],
        is_hidden: bool = False,
        is_microscopic: bool = False,
        is_color_matched: bool = False,
        is_transparent: bool = False,
        active_flags: list[EvasionFlag] | None = None,
    ) -> None:
        self.tag = tag
        self.attrs = attrs
        self.effective_bg = effective_bg
        self.is_hidden = is_hidden
        self.is_microscopic = is_microscopic
        self.is_color_matched = is_color_matched
        self.is_transparent = is_transparent
        self.active_flags: list[EvasionFlag] = active_flags or []
        self.text_chunks: list[str] = []

    @property
    def has_any_evasion(self) -> bool:
        return (
            self.is_hidden
            or self.is_microscopic
            or self.is_color_matched
            or self.is_transparent
        )


class HtmlInspector(HTMLParser):
    """HTML Parser that detects CSS evasion, microscopic fonts, and deceptive elements."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.violations: list[HtmlViolation] = []
        self.evasion_flags: set[str] = set()
        self.hidden_snippets: list[str] = []
        self.deceptive_links: list[dict[str, str]] = []
        self.visible_chunks: list[str] = []
        self.hrefs: list[str] = []
        self.seen_hrefs: set[str] = set()

        self._stack: list[_ElementFrame] = []
        self._in_script_or_style = False
        self._class_styles: dict[str, dict[str, str]] = {}
        self._pending_anchor: dict[str, Any] | None = None

        self.hidden_elements_count = 0
        self.microscopic_font_count = 0
        self.color_matching_count = 0
        self.tracking_pixel_count = 0

    def _record_violation(
        self,
        flag: EvasionFlag,
        severity: str,
        tag: str,
        evidence: dict[str, Any],
        snippet: str = "",
    ) -> None:
        self.evasion_flags.add(flag.value)
        self.violations.append(
            {
                "flag": flag.value,
                "severity": severity,
                "tag": tag,
                "snippet": snippet[:200],
                "evidence": evidence,
            }
        )

    def handle_starttag(self, tag: str, attrs_list: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        attrs = {k.lower(): v for k, v in attrs_list}

        if tag_lower in ("script", "style"):
            self._in_script_or_style = True
            if tag_lower == "script":
                script_type = (attrs.get("type") or "").strip().lower()
                # Exclude benign non-executable schema metadata (e.g. schema.org application/ld+json)
                if script_type not in ("application/ld+json", "application/json"):
                    self._record_violation(
                        EvasionFlag.SUSPICIOUS_SCRIPT_TAG,
                        "high",
                        tag_lower,
                        {"src": attrs.get("src"), "type": script_type},
                    )

        if tag_lower in ("iframe", "embed", "object"):
            self._record_violation(
                EvasionFlag.SUSPICIOUS_IFRAME_TAG,
                "high",
                tag_lower,
                {"src": attrs.get("src", "")},
            )

        if tag_lower == "base":
            href = attrs.get("href")
            if href:
                self._record_violation(
                    EvasionFlag.BASE_TAG_HIJACK,
                    "high",
                    tag_lower,
                    {"base_href": href},
                )

        # Check inline event handlers
        for k, v in attrs.items():
            if _EVENT_HANDLER_RE.match(k):
                self._record_violation(
                    EvasionFlag.SUSPICIOUS_EVENT_HANDLER,
                    "high",
                    tag_lower,
                    {"handler": k, "value": v or ""},
                )

        # Href extraction and scheme inspection
        href = attrs.get("href")
        if href:
            raw_href = unquote(href).strip()
            if raw_href:
                lower_href = raw_href.lower()
                if lower_href.startswith(("javascript:", "vbscript:", "data:text/html")):
                    self._record_violation(
                        EvasionFlag.DANGEROUS_SCHEME_URL,
                        "high",
                        tag_lower,
                        {"scheme_url": raw_href[:100]},
                    )
                elif not lower_href.startswith("data:") and raw_href not in self.seen_hrefs:
                    self.seen_hrefs.add(raw_href)
                    self.hrefs.append(raw_href)

        # Tracking pixel detection (zero or 1px dimensions)
        if tag_lower == "img":
            width_attr = attrs.get("width")
            height_attr = attrs.get("height")
            style_attr = attrs.get("style", "")
            styles = parse_style_string(style_attr)
            w = parse_length_px(width_attr) or parse_length_px(styles.get("width"))
            h = parse_length_px(height_attr) or parse_length_px(styles.get("height"))
            if (
                (w is not None and w <= 1.0)
                or (h is not None and h <= 1.0)
                or styles.get("display") == "none"
            ):
                self.tracking_pixel_count += 1
                self._record_violation(
                    EvasionFlag.TRACKING_PIXEL,
                    "medium",
                    tag_lower,
                    {"src": attrs.get("src", ""), "width": w, "height": h},
                )

        # Resolve parent inheritance
        parent_frame = self._stack[-1] if self._stack else None
        inherited_bg = parent_frame.effective_bg if parent_frame else DEFAULT_CANVAS_BG
        parent_is_hidden = parent_frame.is_hidden if parent_frame else False
        parent_is_microscopic = parent_frame.is_microscopic if parent_frame else False
        parent_is_color_matched = parent_frame.is_color_matched if parent_frame else False
        parent_is_transparent = parent_frame.is_transparent if parent_frame else False

        # Parse element styles
        inline_style_str = attrs.get("style", "")
        style_props = parse_style_string(inline_style_str)

        # Merge class styles if defined in earlier <style> blocks
        class_val = attrs.get("class")
        if class_val:
            for cls in class_val.split():
                if cls in self._class_styles:
                    merged = dict(self._class_styles[cls])
                    merged.update(style_props)
                    style_props = merged

        # Check background color updates
        elem_bg_color = None
        if "background-color" in style_props:
            elem_bg_color = parse_css_color(style_props["background-color"])
        elif "background" in style_props:
            elem_bg_color = extract_color_from_shorthand(style_props["background"])
        elif "bgcolor" in attrs:
            elem_bg_color = parse_css_color(attrs["bgcolor"])

        effective_bg = elem_bg_color if (elem_bg_color and elem_bg_color[3] > 0.05) else inherited_bg

        # Check text color
        elem_color = None
        if "color" in style_props:
            elem_color = parse_css_color(style_props["color"])

        # Detect evasion indicators on this element
        elem_hidden = parent_is_hidden
        elem_micro = parent_is_microscopic
        elem_color_matched = parent_is_color_matched
        elem_trans = parent_is_transparent
        elem_flags: list[EvasionFlag] = []

        # 1. Hidden attributes
        if "hidden" in attrs or attrs.get("aria-hidden") == "true" or attrs.get("type") == "hidden":
            elem_hidden = True
            elem_flags.append(EvasionFlag.HIDDEN_HTML_ATTRIBUTE)
            self._record_violation(
                EvasionFlag.HIDDEN_HTML_ATTRIBUTE,
                "high",
                tag_lower,
                {"attrs": {k: attrs[k] for k in ("hidden", "aria-hidden", "type") if k in attrs}},
            )

        # 2. Hidden CSS styles
        disp = style_props.get("display", "").lower()
        if disp == "none":
            elem_hidden = True
            elem_flags.append(EvasionFlag.HIDDEN_CSS_DISPLAY_NONE)
            self._record_violation(
                EvasionFlag.HIDDEN_CSS_DISPLAY_NONE, "high", tag_lower, {"display": disp}
            )

        vis = style_props.get("visibility", "").lower()
        if vis in ("hidden", "collapse"):
            elem_hidden = True
            elem_flags.append(EvasionFlag.HIDDEN_CSS_VISIBILITY_HIDDEN)
            self._record_violation(
                EvasionFlag.HIDDEN_CSS_VISIBILITY_HIDDEN, "high", tag_lower, {"visibility": vis}
            )

        opacity_val = style_props.get("opacity")
        if opacity_val:
            try:
                op = float(opacity_val.split("!")[0].strip())
                if op <= 0.05:
                    elem_hidden = True
                    elem_flags.append(EvasionFlag.HIDDEN_CSS_ZERO_OPACITY)
                    self._record_violation(
                        EvasionFlag.HIDDEN_CSS_ZERO_OPACITY, "high", tag_lower, {"opacity": op}
                    )
            except ValueError:
                pass

        # Off-screen positioning
        pos = style_props.get("position", "").lower()
        for coord_key in ("left", "top", "margin-left", "margin-top"):
            coord_val = style_props.get(coord_key)
            if coord_val:
                px = parse_length_px(coord_val)
                if px is not None and px <= -500.0:
                    elem_hidden = True
                    elem_flags.append(EvasionFlag.HIDDEN_CSS_OFFSCREEN)
                    self._record_violation(
                        EvasionFlag.HIDDEN_CSS_OFFSCREEN,
                        "high",
                        tag_lower,
                        {"position": pos, coord_key: coord_val},
                    )
                    break

        # Negative text indentation
        text_indent = style_props.get("text-indent")
        if text_indent:
            px = parse_length_px(text_indent)
            if px is not None and px <= -500.0:
                elem_hidden = True
                elem_flags.append(EvasionFlag.HIDDEN_CSS_TEXT_INDENT)
                self._record_violation(
                    EvasionFlag.HIDDEN_CSS_TEXT_INDENT,
                    "high",
                    tag_lower,
                    {"text-indent": text_indent},
                )

        # Zero dimensions with overflow:hidden
        overflow = style_props.get("overflow", "").lower()
        if "hidden" in overflow:
            h = parse_length_px(style_props.get("height"))
            w = parse_length_px(style_props.get("width"))
            max_h = parse_length_px(style_props.get("max-height"))
            max_w = parse_length_px(style_props.get("max-width"))
            lh = parse_length_px(style_props.get("line-height"))
            if (
                (h is not None and h <= 0.5)
                or (w is not None and w <= 0.5)
                or (max_h is not None and max_h <= 0.5)
                or (max_w is not None and max_w <= 0.5)
                or (lh is not None and lh <= 0.5)
            ):
                elem_hidden = True
                elem_flags.append(EvasionFlag.HIDDEN_CSS_ZERO_SIZE)
                self._record_violation(
                    EvasionFlag.HIDDEN_CSS_ZERO_SIZE,
                    "high",
                    tag_lower,
                    {
                        "overflow": overflow,
                        "height": style_props.get("height"),
                        "width": style_props.get("width"),
                    },
                )

        # CSS clipping
        clip_val = style_props.get("clip", "").lower()
        clip_path = style_props.get("clip-path", "").lower()
        if (
            "rect(0" in clip_val.replace(" ", "")
            or "inset(50%)" in clip_path
            or "inset(100%)" in clip_path
        ):
            elem_hidden = True
            elem_flags.append(EvasionFlag.HIDDEN_CSS_CLIPPED)
            self._record_violation(
                EvasionFlag.HIDDEN_CSS_CLIPPED,
                "high",
                tag_lower,
                {"clip": clip_val, "clip-path": clip_path},
            )

        # 3. Microscopic font (< 3px)
        font_size_val = style_props.get("font-size")
        if font_size_val:
            fs_px = parse_font_size_px(font_size_val)
            if fs_px is not None and fs_px < 3.0:
                elem_micro = True
                elem_flags.append(EvasionFlag.MICROSCOPIC_FONT)
                self.microscopic_font_count += 1
                self._record_violation(
                    EvasionFlag.MICROSCOPIC_FONT,
                    "high",
                    tag_lower,
                    {"font-size-raw": font_size_val, "font-size-px": round(fs_px, 2)},
                )

        # 4. Color matching / transparent text evasion
        if elem_color:
            if elem_color[3] <= 0.05:
                elem_trans = True
                elem_flags.append(EvasionFlag.TRANSPARENT_TEXT)
                self.color_matching_count += 1
                self._record_violation(
                    EvasionFlag.TRANSPARENT_TEXT,
                    "high",
                    tag_lower,
                    {"color": style_props.get("color")},
                )
            else:
                matched, reason = are_colors_matching(elem_color, effective_bg)
                if matched:
                    elem_color_matched = True
                    elem_flags.append(EvasionFlag.COLOR_MATCHING_EVASION)
                    self.color_matching_count += 1
                    self._record_violation(
                        EvasionFlag.COLOR_MATCHING_EVASION,
                        "high",
                        tag_lower,
                        {
                            "text_color": style_props.get("color"),
                            "background_color": effective_bg,
                            "reason": reason,
                        },
                    )
                else:
                    elem_color_matched = False

        if elem_hidden:
            self.hidden_elements_count += 1

        frame = _ElementFrame(
            tag=tag_lower,
            attrs=attrs,
            effective_bg=effective_bg,
            is_hidden=elem_hidden,
            is_microscopic=elem_micro,
            is_color_matched=elem_color_matched,
            is_transparent=elem_trans,
            active_flags=elem_flags,
        )
        self._stack.append(frame)

        # If <a> tag, prepare deceptive link tracking
        if tag_lower == "a" and href:
            self._pending_anchor = {
                "href": href,
                "text_parts": [],
            }

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()

        if tag_lower in ("script", "style"):
            self._in_script_or_style = False

        if tag_lower == "a" and self._pending_anchor is not None:
            anchor_href = self._pending_anchor["href"]
            anchor_text = "".join(self._pending_anchor["text_parts"]).strip()
            self._pending_anchor = None
            self._inspect_anchor_text(anchor_text, anchor_href)

        if self._stack and self._stack[-1].tag == tag_lower:
            frame = self._stack.pop()
            joined_snippet = "".join(frame.text_chunks).strip()
            if joined_snippet and frame.has_any_evasion:
                self.hidden_snippets.append(joined_snippet)

    def handle_data(self, data: str) -> None:
        if not data:
            return

        if self._in_script_or_style:
            if self._stack and self._stack[-1].tag == "style":
                self._parse_style_sheet(data)
            return

        current_frame = self._stack[-1] if self._stack else None
        is_evasion_text = current_frame.has_any_evasion if current_frame else False

        if is_evasion_text:
            if current_frame:
                current_frame.text_chunks.append(data)
        else:
            cleaned = data.strip()
            if cleaned:
                self.visible_chunks.append(cleaned)

        if self._pending_anchor is not None:
            self._pending_anchor["text_parts"].append(data)

    def _parse_style_sheet(self, css_text: str) -> None:
        """Extract CSS class rules from <style> blocks."""
        cleaned = _STYLE_COMMENT_RE.sub(" ", css_text)
        rules = re.findall(r"\.([a-zA-Z0-9_-]+)\s*\{([^}]+)\}", cleaned)
        for class_name, block in rules:
            self._class_styles[class_name] = parse_style_string(block)

    def _inspect_anchor_text(self, anchor_text: str, href: str) -> None:
        """Detect deceptive anchor texts where visible domain mismatches target href."""
        if not anchor_text or not href:
            return

        raw_text = anchor_text.strip()
        m = _DOMAIN_LIKE_RE.match(raw_text)
        if not m:
            return

        displayed_domain = m.group(1).lower().rstrip(".")
        if displayed_domain.startswith("www."):
            displayed_domain = displayed_domain[4:]

        try:
            parsed_href = urlparse(href.strip())
            dest_host = (parsed_href.hostname or "").lower().rstrip(".")
            if dest_host.startswith("www."):
                dest_host = dest_host[4:]
        except Exception:
            dest_host = ""

        if not dest_host:
            return

        # Check if destination host matches or is a subdomain of displayed domain
        is_aligned = (
            dest_host == displayed_domain
            or dest_host.endswith("." + displayed_domain)
            or displayed_domain.endswith("." + dest_host)
        )
        if not is_aligned:
            # Check official first-party shorteners and corporate domain aliases
            alias_groups = [
                {"google.com", "c.gle", "goo.gl", "g.co"},
                {"linkedin.com", "lnkd.in"},
                {"microsoft.com", "msft.it", "aka.ms", "office.com"},
            ]
            for group in alias_groups:
                in_dest = any(dest_host == d or dest_host.endswith("." + d) for d in group)
                in_disp = any(displayed_domain == d or displayed_domain.endswith("." + d) for d in group)
                if in_dest and in_disp:
                    is_aligned = True
                    break

        if not is_aligned:
            self._record_violation(
                EvasionFlag.DECEPTIVE_ANCHOR_TEXT,
                "high",
                "a",
                {
                    "displayed_text": raw_text,
                    "displayed_domain": displayed_domain,
                    "destination_url": href,
                    "destination_domain": dest_host,
                },
                snippet=raw_text,
            )
            self.deceptive_links.append(
                {
                    "displayed_text": raw_text,
                    "displayed_domain": displayed_domain,
                    "destination_url": href,
                    "destination_domain": dest_host,
                }
            )


def inspect_html(markup: str | None) -> HtmlEvasionReport:
    """Inspect an HTML email body for advanced evasion and steganography techniques.

    Args:
        markup: Raw HTML string from email MIME body.

    Returns:
        Structured HtmlEvasionReport with evasion flags, counts, violations,
        extracted hidden text snippets, deceptive links, and risk score.
    """
    if not markup:
        return {
            "has_evasion": False,
            "evasion_flags": [],
            "hidden_elements_count": 0,
            "microscopic_font_count": 0,
            "color_matching_count": 0,
            "deceptive_link_count": 0,
            "hidden_text_snippets": [],
            "deceptive_links": [],
            "violations": [],
            "visible_text": "",
            "hrefs": [],
            "risk_score": 0,
        }

    parser = HtmlInspector()
    try:
        parser.feed(str(markup))
        parser.close()
    except Exception:
        pass

    evasion_flags = sorted(parser.evasion_flags)
    has_evasion = len(evasion_flags) > 0

    # Compounding risk score for HTML evasion (capped at 10)
    score = 0
    for v in parser.violations:
        sev = v.get("severity", "medium")
        if sev == "high":
            score += 4
        elif sev == "medium":
            score += 2
        else:
            score += 1
    score = min(score, 10)

    return {
        "has_evasion": has_evasion,
        "evasion_flags": evasion_flags,
        "hidden_elements_count": parser.hidden_elements_count,
        "microscopic_font_count": parser.microscopic_font_count,
        "color_matching_count": parser.color_matching_count,
        "deceptive_link_count": len(parser.deceptive_links),
        "hidden_text_snippets": parser.hidden_snippets,
        "deceptive_links": parser.deceptive_links,
        "violations": parser.violations,
        "visible_text": " ".join(parser.visible_chunks),
        "hrefs": parser.hrefs,
        "risk_score": score,
    }


class _VisibleTextExtractor(HTMLParser):
    """Fallback plain-text extractor dropping scripts and stylesheets."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript"}:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0 and data:
            self._chunks.append(data)

    def text(self) -> str:
        return " ".join(part.strip() for part in self._chunks if part.strip())


def strip_html(markup: str | None) -> str:
    """Return visible text from HTML, stripping script/style and hidden evasion content."""
    if not markup:
        return ""
    try:
        report = inspect_html(markup)
        if report["visible_text"]:
            return report["visible_text"]
        parser = _VisibleTextExtractor()
        parser.feed(str(markup))
        parser.close()
        return parser.text()
    except Exception:
        return re.sub(r"<[^>]+>", " ", str(markup)).strip()


def extract_hrefs(markup: str | None) -> list[str]:
    """Collect href values without fetching them."""
    if not markup:
        return []
    found: list[str] = []
    seen: set[str] = set()
    try:
        for match in _HREF_RE.finditer(str(markup)):
            raw = unquote(match.group("url")).strip()
            if raw and raw not in seen and not raw.lower().startswith(("javascript:", "data:", "vbscript:")):
                seen.add(raw)
                found.append(raw)
    except Exception:
        return found
    return found
