"""Cyber Scout — Streamlit B2B email security posture assessment.

Run locally:
    streamlit run app.py

This application performs external DNS posture checks only. It does not send email,
attempt authentication, modify DNS, or conduct penetration testing.
"""

from __future__ import annotations

import html
import io
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from email import policy
from email.parser import Parser
from typing import Any
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import streamlit as st
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


APP_NAME = "Cyber Scout"
BRAND_NAME = "Nexanar"
BRAND_TAGLINE = "External Email Security Assessment"
CONTACT_EMAIL = "security@nexanar.example"
WEBSITE = "nexanar.example"

PRIMARY = "#35E3B2"
NAVY = "#071522"
NAVY_2 = "#0B2031"
PANEL = "#10283A"
TEXT = "#EAF5F4"
MUTED = "#98ADBA"
GREEN = "#36D399"
AMBER = "#F4B740"
RED = "#FF5D73"
BLUE = "#58A6FF"

DNS_TIMEOUT_SECONDS = 4.0
MAX_HEADER_CHARS = 50_000


# -----------------------------------------------------------------------------
# Generic helpers
# -----------------------------------------------------------------------------

def to_plain(value: Any) -> Any:
    """Convert library-returned objects into JSON/session-state-safe values."""
    if isinstance(value, Mapping):
        return {str(key): to_plain(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [to_plain(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def safe_text(value: Any, fallback: str = "—") -> str:
    if value is None:
        return fallback
    text = str(value).strip()
    return text if text else fallback


def flatten_messages(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [json.dumps(to_plain(value), ensure_ascii=False)]
    if isinstance(value, Sequence):
        return [safe_text(item) for item in value if safe_text(item, "")]
    return [str(value)]


def normalize_domain(raw_value: str) -> str:
    """Normalize a URL, email address, hostname, or bare domain to an IDNA domain."""
    value = (raw_value or "").strip().lower()
    if not value:
        raise ValueError("Enter a corporate domain, for example company.com.")

    if len(value) > 253 + 20:
        raise ValueError("The supplied value is too long to be a valid domain.")

    if "@" in value and "://" not in value:
        value = value.rsplit("@", 1)[-1]

    if "://" not in value:
        value = f"//{value}"

    parsed = urlparse(value)
    host = parsed.hostname or ""
    host = host.strip(".")
    if host.startswith("www."):
        host = host[4:]

    if not host:
        raise ValueError("The domain format is invalid.")

    try:
        ascii_domain = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("The domain contains unsupported characters.") from exc

    if len(ascii_domain) > 253:
        raise ValueError("The domain is longer than the DNS limit.")

    labels = ascii_domain.split(".")
    if len(labels) < 2:
        raise ValueError("Enter a complete public domain such as company.com.")

    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
    if any(not label_pattern.fullmatch(label) for label in labels):
        raise ValueError("The domain contains an invalid DNS label.")

    return ascii_domain


def get_nested(data: Mapping[str, Any], *paths: tuple[str, ...] | str) -> Any:
    """Return the first value found among alternative key paths."""
    for path in paths:
        parts = (path,) if isinstance(path, str) else path
        current: Any = data
        found = True
        for part in parts:
            if not isinstance(current, Mapping) or part not in current:
                found = False
                break
            current = current[part]
        if found:
            return current
    return None


def extract_tag(tags: Any, name: str) -> str | None:
    if not isinstance(tags, Mapping):
        return None
    value = tags.get(name)
    if isinstance(value, Mapping):
        value = value.get("value")
    return str(value).lower().strip() if value is not None else None


def label_from_score(score: int) -> tuple[str, str, str]:
    if score >= 85:
        return "Strong", "Low", GREEN
    if score >= 65:
        return "Moderate", "Medium", AMBER
    if score >= 40:
        return "Elevated", "High", RED
    return "Critical", "High", RED


# -----------------------------------------------------------------------------
# DNS and checkdmarc assessment
# -----------------------------------------------------------------------------

def query_txt_records(name: str) -> list[str]:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = DNS_TIMEOUT_SECONDS
    resolver.timeout = DNS_TIMEOUT_SECONDS
    answers = resolver.resolve(name, "TXT", lifetime=DNS_TIMEOUT_SECONDS)
    records: list[str] = []
    for answer in answers:
        if hasattr(answer, "strings"):
            records.append(b"".join(answer.strings).decode("utf-8", errors="replace"))
        else:
            records.append(str(answer).strip('"').replace('" "', ""))
    return records


def query_mx_records(domain: str) -> list[dict[str, Any]]:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = DNS_TIMEOUT_SECONDS
    resolver.timeout = DNS_TIMEOUT_SECONDS
    answers = resolver.resolve(domain, "MX", lifetime=DNS_TIMEOUT_SECONDS)
    records = [
        {"preference": int(answer.preference), "hostname": str(answer.exchange).rstrip(".")}
        for answer in answers
    ]
    return sorted(records, key=lambda item: item["preference"])


def fallback_dns_snapshot(domain: str) -> dict[str, Any]:
    """Independent dnspython snapshot used for transparency and graceful fallback."""
    snapshot: dict[str, Any] = {
        "spf_records": [],
        "dmarc_records": [],
        "mx_records": [],
        "errors": [],
    }

    try:
        root_txt = query_txt_records(domain)
        snapshot["spf_records"] = [record for record in root_txt if record.lower().startswith("v=spf1")]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as exc:
        snapshot["errors"].append(f"SPF lookup: {type(exc).__name__}")
    except (dns.exception.Timeout, dns.resolver.NoNameservers, OSError) as exc:
        snapshot["errors"].append(f"SPF lookup: {exc}")

    try:
        dmarc_txt = query_txt_records(f"_dmarc.{domain}")
        snapshot["dmarc_records"] = [
            record for record in dmarc_txt if record.lower().startswith("v=dmarc1")
        ]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as exc:
        snapshot["errors"].append(f"DMARC lookup: {type(exc).__name__}")
    except (dns.exception.Timeout, dns.resolver.NoNameservers, OSError) as exc:
        snapshot["errors"].append(f"DMARC lookup: {exc}")

    try:
        snapshot["mx_records"] = query_mx_records(domain)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as exc:
        snapshot["errors"].append(f"MX lookup: {type(exc).__name__}")
    except (dns.exception.Timeout, dns.resolver.NoNameservers, OSError) as exc:
        snapshot["errors"].append(f"MX lookup: {exc}")

    return snapshot


def run_checkdmarc(domain: str) -> tuple[dict[str, Any], str | None]:
    """Run checkdmarc with compatibility handling across supported 5.x releases."""
    try:
        import checkdmarc  # Imported here so helper functions remain independently testable.
    except ImportError:
        return {}, "checkdmarc is not installed. Install dependencies from requirements.txt."

    try:
        try:
            raw = checkdmarc.check_domains(
                [domain],
                skip_tls=True,
                include_dmarc_tag_descriptions=False,
                timeout=DNS_TIMEOUT_SECONDS,
            )
        except TypeError:
            raw = checkdmarc.check_domains(
                [domain],
                skip_tls=True,
                timeout=DNS_TIMEOUT_SECONDS,
            )

        if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes, bytearray)):
            raw = raw[0] if raw else {}
        if not isinstance(raw, Mapping):
            return {}, "checkdmarc returned an unexpected response format."
        return to_plain(raw), None
    except Exception as exc:  # Library exposes many record-specific exception classes.
        return {}, f"checkdmarc scan failed: {exc}"


def normalize_checkdmarc_results(
    domain: str,
    raw: Mapping[str, Any],
    fallback: Mapping[str, Any],
    library_error: str | None,
) -> dict[str, Any]:
    spf_section = raw.get("spf") if isinstance(raw.get("spf"), Mapping) else {}
    dmarc_section = raw.get("dmarc") if isinstance(raw.get("dmarc"), Mapping) else {}
    mx_section = raw.get("mx") if isinstance(raw.get("mx"), Mapping) else {}

    spf_record = get_nested(spf_section, "record", ("parsed", "record"))
    if not spf_record and fallback.get("spf_records"):
        spf_record = fallback["spf_records"][0]

    dmarc_record = get_nested(dmarc_section, "record", ("parsed", "record"))
    if not dmarc_record and fallback.get("dmarc_records"):
        dmarc_record = fallback["dmarc_records"][0]

    dmarc_tags = get_nested(dmarc_section, "tags", ("parsed", "tags")) or {}
    dmarc_policy = extract_tag(dmarc_tags, "p")
    subdomain_policy = extract_tag(dmarc_tags, "sp")
    pct = extract_tag(dmarc_tags, "pct") or "100"

    if not dmarc_policy and dmarc_record:
        policy_match = re.search(r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\b", dmarc_record, re.I)
        dmarc_policy = policy_match.group(1).lower() if policy_match else None
    if not subdomain_policy and dmarc_record:
        sp_match = re.search(r"(?:^|;)\s*sp\s*=\s*(none|quarantine|reject)\b", dmarc_record, re.I)
        subdomain_policy = sp_match.group(1).lower() if sp_match else None
    if dmarc_record:
        pct_match = re.search(r"(?:^|;)\s*pct\s*=\s*(\d{1,3})\b", dmarc_record, re.I)
        if pct_match:
            pct = pct_match.group(1)

    spf_valid = spf_section.get("valid")
    dmarc_valid = dmarc_section.get("valid")
    if spf_valid is None:
        spf_valid = bool(spf_record and spf_record.lower().startswith("v=spf1"))
    if dmarc_valid is None:
        dmarc_valid = bool(dmarc_record and dmarc_record.lower().startswith("v=dmarc1"))

    mx_hosts = get_nested(mx_section, "hosts") or fallback.get("mx_records") or []
    if isinstance(mx_hosts, Mapping):
        mx_hosts = [mx_hosts]
    mx_hosts = to_plain(mx_hosts) if isinstance(mx_hosts, Sequence) else []

    spf_warnings = flatten_messages(spf_section.get("warnings"))
    dmarc_warnings = flatten_messages(
        dmarc_section.get("warnings") or get_nested(dmarc_section, ("parsed", "warnings"))
    )
    mx_warnings = flatten_messages(mx_section.get("warnings"))

    spf_error = safe_text(spf_section.get("error"), "") or None
    dmarc_error = safe_text(dmarc_section.get("error"), "") or None
    mx_error = safe_text(mx_section.get("error"), "") or None

    if not spf_record and not spf_error:
        spf_error = "No SPF record was found."
    if not dmarc_record and not dmarc_error:
        dmarc_error = "No DMARC record was found."
    if not mx_hosts and not mx_error:
        mx_error = "No MX records were found."

    return {
        "domain": domain,
        "base_domain": raw.get("base_domain") or domain,
        "spf": {
            "valid": bool(spf_valid),
            "record": spf_record,
            "dns_lookups": get_nested(spf_section, "dns_lookups", ("parsed", "dns_lookups")),
            "warnings": spf_warnings,
            "error": spf_error,
        },
        "dmarc": {
            "valid": bool(dmarc_valid),
            "record": dmarc_record,
            "policy": dmarc_policy,
            "subdomain_policy": subdomain_policy,
            "pct": pct,
            "location": dmarc_section.get("location"),
            "warnings": dmarc_warnings,
            "error": dmarc_error,
        },
        "mx": {
            "hosts": mx_hosts,
            "warnings": mx_warnings,
            "error": mx_error,
        },
        "engine": {
            "checkdmarc_error": library_error,
            "dns_errors": flatten_messages(fallback.get("errors")),
        },
    }


# -----------------------------------------------------------------------------
# Optional email-header evidence
# -----------------------------------------------------------------------------

def parse_authentication_results(values: list[str]) -> dict[str, str]:
    statuses = {"spf": "not-found", "dkim": "not-found", "dmarc": "not-found"}
    for value in values:
        for mechanism in statuses:
            matches = re.findall(
                rf"\b{mechanism}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|bestguesspass)\b",
                value,
                flags=re.IGNORECASE,
            )
            if not matches:
                continue
            normalized = [match.lower() for match in matches]
            if "fail" in normalized or "permerror" in normalized:
                statuses[mechanism] = "fail"
            elif "pass" in normalized:
                statuses[mechanism] = "pass"
            elif statuses[mechanism] == "not-found":
                statuses[mechanism] = normalized[-1]
    return statuses


def extract_address_domain(header_value: str | None) -> str | None:
    if not header_value:
        return None
    match = re.search(r"@([a-z0-9.-]+)", header_value, re.IGNORECASE)
    return match.group(1).rstrip(".").lower() if match else None


def analyze_headers(raw_headers: str) -> dict[str, Any]:
    text = (raw_headers or "").strip()
    if not text:
        return {
            "provided": False,
            "statuses": {"spf": "not-provided", "dkim": "not-provided", "dmarc": "not-provided"},
            "from_domain": None,
            "return_path_domain": None,
            "message_id": None,
            "authentication_results": [],
            "note": "No raw headers were supplied.",
        }

    if len(text) > MAX_HEADER_CHARS:
        raise ValueError(f"Email headers must be under {MAX_HEADER_CHARS:,} characters.")

    message = Parser(policy=policy.default).parsestr(text, headersonly=True)
    authentication_results = message.get_all("Authentication-Results", [])
    received_spf = message.get_all("Received-SPF", [])
    combined_results = [str(value) for value in authentication_results + received_spf]

    return {
        "provided": True,
        "statuses": parse_authentication_results(combined_results),
        "from_domain": extract_address_domain(str(message.get("From", ""))),
        "return_path_domain": extract_address_domain(str(message.get("Return-Path", ""))),
        "message_id": safe_text(message.get("Message-ID"), "") or None,
        "authentication_results": combined_results[:8],
        "note": (
            "Header results are reported by the receiving mail system. This tool does not "
            "cryptographically re-verify the DKIM signature."
        ),
    }


# -----------------------------------------------------------------------------
# Risk model and recommendations
# -----------------------------------------------------------------------------

def evaluate_spf(spf: Mapping[str, Any]) -> dict[str, str]:
    record = safe_text(spf.get("record"), "")
    if not record or not spf.get("valid"):
        return {
            "state": "critical",
            "label": "Missing or invalid",
            "detail": safe_text(spf.get("error"), "No valid SPF policy was found."),
        }

    normalized = record.lower()
    if re.search(r"(?:^|\s)\+all(?:\s|$)", normalized):
        return {"state": "critical", "label": "Unsafe +all", "detail": "SPF explicitly authorizes every sender."}
    if re.search(r"(?:^|\s)\?all(?:\s|$)", normalized):
        return {"state": "critical", "label": "Neutral policy", "detail": "SPF does not provide meaningful enforcement."}
    if re.search(r"(?:^|\s)~all(?:\s|$)", normalized):
        return {"state": "warning", "label": "Soft fail", "detail": "Unauthorized senders are marked, but not decisively rejected."}
    if re.search(r"(?:^|\s)-all(?:\s|$)", normalized):
        return {"state": "secure", "label": "Hard fail", "detail": "SPF ends with a restrictive -all mechanism."}
    return {"state": "warning", "label": "Review required", "detail": "A valid SPF record exists but no clear terminal all policy was detected."}


def evaluate_dmarc(dmarc: Mapping[str, Any]) -> dict[str, str]:
    record = safe_text(dmarc.get("record"), "")
    policy_value = safe_text(dmarc.get("policy"), "").lower()
    pct_value = safe_text(dmarc.get("pct"), "100")

    if not record or not dmarc.get("valid"):
        return {
            "state": "critical",
            "label": "Not enforced",
            "detail": safe_text(dmarc.get("error"), "No valid DMARC record was found."),
        }
    if policy_value == "none":
        return {"state": "critical", "label": "Monitoring only", "detail": "DMARC uses p=none and does not request enforcement."}
    if policy_value == "quarantine":
        if pct_value.isdigit() and int(pct_value) < 100:
            return {"state": "warning", "label": "Partial quarantine", "detail": f"Quarantine applies to only {pct_value}% of failing messages."}
        return {"state": "warning", "label": "Quarantine", "detail": "Failing messages are requested to be treated as suspicious."}
    if policy_value == "reject":
        if pct_value.isdigit() and int(pct_value) < 100:
            return {"state": "warning", "label": "Partial reject", "detail": f"Reject applies to only {pct_value}% of failing messages."}
        return {"state": "secure", "label": "Reject enforced", "detail": "DMARC requests rejection of messages that fail alignment."}
    return {"state": "warning", "label": "Unknown policy", "detail": "A DMARC record exists, but its enforcement policy could not be classified."}


def evaluate_mx(mx: Mapping[str, Any]) -> dict[str, str]:
    hosts = mx.get("hosts") or []
    if hosts:
        return {"state": "secure", "label": f"{len(hosts)} host(s)", "detail": "Mail exchanger records were resolved."}
    return {"state": "critical", "label": "Not found", "detail": safe_text(mx.get("error"), "No MX records were resolved.")}


def build_recommendations(
    normalized: Mapping[str, Any],
    spf_eval: Mapping[str, str],
    dmarc_eval: Mapping[str, str],
    header_analysis: Mapping[str, Any],
) -> list[dict[str, str]]:
    recommendations: list[dict[str, str]] = []

    if dmarc_eval["state"] == "critical":
        recommendations.append({
            "priority": "P1",
            "title": "Enforce DMARC",
            "action": "Publish or update DMARC to p=quarantine, then progress to p=reject after validating legitimate senders and alignment.",
        })
    elif dmarc_eval["state"] == "warning":
        recommendations.append({
            "priority": "P2",
            "title": "Strengthen DMARC coverage",
            "action": "Move toward p=reject with pct=100 and review the subdomain policy so enforcement is consistent.",
        })

    if spf_eval["state"] == "critical":
        recommendations.append({
            "priority": "P1",
            "title": "Correct SPF authorization",
            "action": "Publish one valid SPF record containing only approved sending services and finish with an appropriate restrictive all mechanism.",
        })
    elif spf_eval["state"] == "warning":
        recommendations.append({
            "priority": "P2",
            "title": "Harden SPF",
            "action": "Review all includes, remove obsolete senders, keep DNS lookups within limits, and consider progressing from ~all to -all.",
        })

    dmarc = normalized["dmarc"]
    if dmarc.get("policy") in {"quarantine", "reject"} and dmarc.get("subdomain_policy") in {None, "none"}:
        recommendations.append({
            "priority": "P2",
            "title": "Protect subdomains",
            "action": "Set an explicit sp policy where appropriate and inventory subdomains that legitimately send email.",
        })

    header_statuses = header_analysis.get("statuses", {})
    if header_analysis.get("provided") and any(header_statuses.get(item) == "fail" for item in ("spf", "dkim", "dmarc")):
        recommendations.append({
            "priority": "P1",
            "title": "Investigate header authentication failures",
            "action": "Trace the sending platform, envelope-from domain, DKIM selector, and visible From alignment for the supplied message.",
        })

    if not recommendations:
        recommendations.append({
            "priority": "P3",
            "title": "Maintain enforcement",
            "action": "Continue monitoring aggregate DMARC reports, review authorized senders quarterly, and test changes before updating DNS.",
        })

    return recommendations[:5]


def calculate_score(
    normalized: Mapping[str, Any],
    spf_eval: Mapping[str, str],
    dmarc_eval: Mapping[str, str],
    mx_eval: Mapping[str, str],
    headers: Mapping[str, Any],
) -> int:
    score = 100

    score -= {"secure": 0, "warning": 12, "critical": 25}[spf_eval["state"]]
    score -= {"secure": 0, "warning": 18, "critical": 50}[dmarc_eval["state"]]
    score -= {"secure": 0, "warning": 7, "critical": 15}[mx_eval["state"]]

    dns_lookups = normalized["spf"].get("dns_lookups")
    try:
        if dns_lookups is not None and int(dns_lookups) > 10:
            score -= 10
    except (TypeError, ValueError):
        pass

    if headers.get("provided"):
        statuses = headers.get("statuses", {})
        score -= 8 if statuses.get("dmarc") == "fail" else 0
        score -= 4 if statuses.get("spf") == "fail" else 0
        score -= 4 if statuses.get("dkim") == "fail" else 0

    return max(0, min(100, score))


def assess_domain(domain: str, raw_headers: str) -> dict[str, Any]:
    fallback = fallback_dns_snapshot(domain)
    raw, library_error = run_checkdmarc(domain)
    normalized = normalize_checkdmarc_results(domain, raw, fallback, library_error)
    headers = analyze_headers(raw_headers)

    spf_eval = evaluate_spf(normalized["spf"])
    dmarc_eval = evaluate_dmarc(normalized["dmarc"])
    mx_eval = evaluate_mx(normalized["mx"])
    score = calculate_score(normalized, spf_eval, dmarc_eval, mx_eval, headers)
    posture, exposure, posture_color = label_from_score(score)

    # The headline exposure remains high whenever DMARC is absent or p=none,
    # regardless of secondary signals, because DMARC controls From-domain enforcement.
    if dmarc_eval["state"] == "critical":
        exposure = "High"
    elif normalized["dmarc"].get("policy") == "quarantine":
        exposure = "Medium"
    elif normalized["dmarc"].get("policy") == "reject":
        exposure = "Low"

    recommendations = build_recommendations(normalized, spf_eval, dmarc_eval, headers)

    return {
        "scan_id": datetime.now(timezone.utc).strftime("CSC-%Y%m%d-%H%M%S"),
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "domain": domain,
        "score": score,
        "posture": posture,
        "exposure": exposure,
        "posture_color": posture_color,
        "summary": (
            f"{domain} has a {posture.lower()} external email-security posture. "
            f"The current spoofing exposure is assessed as {exposure.lower()} based primarily on DMARC enforcement."
        ),
        "spf": normalized["spf"],
        "dmarc": normalized["dmarc"],
        "mx": normalized["mx"],
        "engine": normalized["engine"],
        "header_analysis": headers,
        "evaluations": {"spf": spf_eval, "dmarc": dmarc_eval, "mx": mx_eval},
        "recommendations": recommendations,
        "raw_checkdmarc": raw,
    }


# -----------------------------------------------------------------------------
# PDF generation
# -----------------------------------------------------------------------------

def pdf_color(hex_value: str) -> colors.Color:
    return colors.HexColor(hex_value)


def draw_brand_mark(canvas: Any, x: float, y: float, size: float = 13 * mm) -> None:
    canvas.saveState()
    canvas.setFillColor(pdf_color(PRIMARY))
    path = canvas.beginPath()
    path.moveTo(x + size * 0.5, y + size)
    path.lineTo(x + size, y + size * 0.78)
    path.lineTo(x + size * 0.88, y + size * 0.25)
    path.lineTo(x + size * 0.5, y)
    path.lineTo(x + size * 0.12, y + size * 0.25)
    path.lineTo(x, y + size * 0.78)
    path.close()
    canvas.drawPath(path, fill=1, stroke=0)

    canvas.setFillColor(pdf_color(NAVY))
    canvas.setLineWidth(1.8)
    canvas.setStrokeColor(pdf_color(NAVY))
    canvas.line(x + size * 0.33, y + size * 0.52, x + size * 0.47, y + size * 0.37)
    canvas.line(x + size * 0.47, y + size * 0.37, x + size * 0.72, y + size * 0.67)
    canvas.restoreState()


def draw_pdf_header_footer(canvas: Any, doc: SimpleDocTemplate, report: Mapping[str, Any]) -> None:
    width, height = A4
    canvas.saveState()

    canvas.setFillColor(pdf_color(NAVY))
    canvas.rect(0, height - 29 * mm, width, 29 * mm, fill=1, stroke=0)
    draw_brand_mark(canvas, 17 * mm, height - 22 * mm, 11 * mm)

    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 15)
    canvas.drawString(31 * mm, height - 14 * mm, BRAND_NAME.upper())
    canvas.setFillColor(pdf_color(PRIMARY))
    canvas.setFont("Helvetica", 8.5)
    canvas.drawString(31 * mm, height - 19 * mm, BRAND_TAGLINE.upper())

    domain = safe_text(report.get("domain"))
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 9)
    right_x = width - 17 * mm
    canvas.drawRightString(right_x, height - 13.5 * mm, domain)
    canvas.setFillColor(pdf_color(MUTED))
    canvas.setFont("Helvetica", 7.5)
    canvas.drawRightString(right_x, height - 18.5 * mm, safe_text(report.get("scan_id")))

    canvas.setStrokeColor(pdf_color("#D8E3E8"))
    canvas.setLineWidth(0.5)
    canvas.line(17 * mm, 14 * mm, width - 17 * mm, 14 * mm)
    canvas.setFillColor(pdf_color("#607787"))
    canvas.setFont("Helvetica", 7)
    canvas.drawString(17 * mm, 9 * mm, "External DNS posture assessment — not a penetration test")
    canvas.drawRightString(width - 17 * mm, 9 * mm, f"Page {doc.page}")

    canvas.restoreState()


def paragraph_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=28,
            textColor=pdf_color(NAVY),
            alignment=TA_LEFT,
            spaceAfter=5 * mm,
        ),
        "h1": ParagraphStyle(
            "H1",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=18,
            textColor=pdf_color(NAVY),
            spaceBefore=4 * mm,
            spaceAfter=3 * mm,
        ),
        "h2": ParagraphStyle(
            "H2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=13,
            textColor=pdf_color(NAVY_2),
            spaceAfter=2 * mm,
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=pdf_color("#243B4A"),
            spaceAfter=2.5 * mm,
        ),
        "small": ParagraphStyle(
            "Small",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=pdf_color("#607787"),
        ),
        "white_small": ParagraphStyle(
            "WhiteSmall",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=colors.white,
        ),
        "center": ParagraphStyle(
            "Center",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=11,
            alignment=TA_CENTER,
            textColor=pdf_color(NAVY),
        ),
    }


def status_pdf_color(state: str) -> colors.Color:
    return pdf_color({"secure": GREEN, "warning": AMBER, "critical": RED}.get(state, BLUE))


def create_pdf(report: Mapping[str, Any]) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=17 * mm,
        leftMargin=17 * mm,
        topMargin=36 * mm,
        bottomMargin=20 * mm,
        title=f"Cyber Scout Report — {report['domain']}",
        author=BRAND_NAME,
        subject="External email security posture assessment",
    )
    styles = paragraph_styles()
    story: list[Any] = []

    story.append(Paragraph("Executive Email Security Brief", styles["title"]))
    story.append(Paragraph(
        f"Assessment target: <b>{html.escape(report['domain'])}</b><br/>"
        f"Generated: {html.escape(report['scanned_at'])}",
        styles["body"],
    ))

    posture_color = pdf_color(report["posture_color"])
    score_card = Table(
        [
            [
                Paragraph("SECURITY SCORE", styles["white_small"]),
                Paragraph("POSTURE", styles["white_small"]),
                Paragraph("SPOOFING EXPOSURE", styles["white_small"]),
            ],
            [
                Paragraph(f"<font size='21'><b>{report['score']}/100</b></font>", styles["white_small"]),
                Paragraph(f"<font size='15'><b>{html.escape(report['posture'])}</b></font>", styles["white_small"]),
                Paragraph(f"<font size='15'><b>{html.escape(report['exposure'])}</b></font>", styles["white_small"]),
            ],
        ],
        colWidths=[55 * mm, 55 * mm, 55 * mm],
        rowHeights=[8 * mm, 16 * mm],
    )
    score_card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), pdf_color(NAVY_2)),
        ("BACKGROUND", (0, 1), (0, 1), posture_color),
        ("BACKGROUND", (1, 1), (1, 1), posture_color),
        ("BACKGROUND", (2, 1), (2, 1), status_pdf_color("critical" if report["exposure"] == "High" else "warning" if report["exposure"] == "Medium" else "secure")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BOX", (0, 0), (-1, -1), 0.5, pdf_color("#DCE7EB")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, pdf_color("#294558")),
    ]))
    story.append(score_card)
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph(html.escape(report["summary"]), styles["body"]))

    story.append(Paragraph("Control Findings", styles["h1"]))
    findings_data: list[list[Any]] = [[
        Paragraph("CONTROL", styles["center"]),
        Paragraph("STATUS", styles["center"]),
        Paragraph("EVIDENCE", styles["center"]),
    ]]
    for key, title in (("dmarc", "DMARC"), ("spf", "SPF"), ("mx", "MX")):
        evaluation = report["evaluations"][key]
        if key == "dmarc":
            evidence = report["dmarc"].get("record") or report["dmarc"].get("error")
        elif key == "spf":
            evidence = report["spf"].get("record") or report["spf"].get("error")
        else:
            hosts = report["mx"].get("hosts") or []
            evidence = ", ".join(
                safe_text(host.get("hostname") if isinstance(host, Mapping) else host)
                for host in hosts[:4]
            ) or report["mx"].get("error")

        findings_data.append([
            Paragraph(f"<b>{title}</b>", styles["body"]),
            Paragraph(f"<b>{html.escape(evaluation['label'])}</b><br/>{html.escape(evaluation['detail'])}", styles["body"]),
            Paragraph(html.escape(safe_text(evidence)), styles["small"]),
        ])

    findings = Table(findings_data, colWidths=[24 * mm, 62 * mm, 79 * mm], repeatRows=1)
    findings_style = [
        ("BACKGROUND", (0, 0), (-1, 0), pdf_color("#E7F0F3")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.45, pdf_color("#CDDCE2")),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]
    for row_idx, key in enumerate(("dmarc", "spf", "mx"), start=1):
        findings_style.append(("BACKGROUND", (0, row_idx), (0, row_idx), status_pdf_color(report["evaluations"][key]["state"])))
        findings_style.append(("TEXTCOLOR", (0, row_idx), (0, row_idx), colors.white))
    findings.setStyle(TableStyle(findings_style))
    story.append(findings)

    story.append(Paragraph("Prioritized Actions", styles["h1"]))
    action_rows: list[list[Any]] = []
    for item in report["recommendations"]:
        priority_color = RED if item["priority"] == "P1" else AMBER if item["priority"] == "P2" else BLUE
        action_rows.append([
            Paragraph(f"<b>{html.escape(item['priority'])}</b>", styles["center"]),
            Paragraph(f"<b>{html.escape(item['title'])}</b><br/>{html.escape(item['action'])}", styles["body"]),
        ])
    actions = Table(action_rows, colWidths=[18 * mm, 147 * mm])
    action_style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.45, pdf_color("#D6E2E7")),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]
    for row_idx, item in enumerate(report["recommendations"]):
        priority_color = RED if item["priority"] == "P1" else AMBER if item["priority"] == "P2" else BLUE
        action_style.extend([
            ("BACKGROUND", (0, row_idx), (0, row_idx), pdf_color(priority_color)),
            ("TEXTCOLOR", (0, row_idx), (0, row_idx), colors.white),
        ])
    actions.setStyle(TableStyle(action_style))
    story.append(actions)

    header = report["header_analysis"]
    story.append(Paragraph("Email Header Evidence", styles["h1"]))
    if header.get("provided"):
        statuses = header.get("statuses", {})
        header_rows = [
            [Paragraph("SPF", styles["center"]), Paragraph(html.escape(safe_text(statuses.get("spf"))), styles["center"])],
            [Paragraph("DKIM", styles["center"]), Paragraph(html.escape(safe_text(statuses.get("dkim"))), styles["center"])],
            [Paragraph("DMARC", styles["center"]), Paragraph(html.escape(safe_text(statuses.get("dmarc"))), styles["center"])],
            [Paragraph("From domain", styles["center"]), Paragraph(html.escape(safe_text(header.get("from_domain"))), styles["body"])],
            [Paragraph("Return-Path domain", styles["center"]), Paragraph(html.escape(safe_text(header.get("return_path_domain"))), styles["body"])],
        ]
        header_table = Table(header_rows, colWidths=[44 * mm, 121 * mm])
        header_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.45, pdf_color("#D6E2E7")),
            ("BACKGROUND", (0, 0), (0, -1), pdf_color("#EDF4F6")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(header_table)
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph(html.escape(header.get("note", "")), styles["small"]))
    else:
        story.append(Paragraph("No raw email headers were supplied, so message-level authentication evidence was not assessed.", styles["body"]))

    story.append(PageBreak())
    story.append(Paragraph("Technical Detail", styles["title"]))

    detail_sections = [
        ("DMARC", report["dmarc"]),
        ("SPF", report["spf"]),
        ("MX", report["mx"]),
    ]
    for title, detail in detail_sections:
        rows: list[list[Any]] = []
        for key, value in detail.items():
            if value in (None, "", [], {}):
                continue
            rendered = json.dumps(value, indent=2, ensure_ascii=False) if isinstance(value, (list, dict)) else str(value)
            rows.append([
                Paragraph(f"<b>{html.escape(str(key).replace('_', ' ').title())}</b>", styles["small"]),
                Paragraph(html.escape(rendered).replace("\n", "<br/>"), styles["small"]),
            ])
        if rows:
            story.append(KeepTogether([
                Paragraph(title, styles["h1"]),
                Table(rows, colWidths=[38 * mm, 127 * mm], style=TableStyle([
                    ("GRID", (0, 0), (-1, -1), 0.4, pdf_color("#D7E3E8")),
                    ("BACKGROUND", (0, 0), (0, -1), pdf_color("#EEF4F6")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ])),
            ]))

    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("Assessment Scope and Limitations", styles["h1"]))
    limitations = (
        "This report is based on public DNS responses and any raw headers voluntarily supplied at the time of the scan. "
        "DNS can change after generation. The score is an indicative prioritization aid, not a certification, warranty, "
        "or guarantee of deliverability or resistance to all forms of impersonation. DKIM configuration cannot be fully "
        "enumerated without known selectors, and supplied DKIM results are not cryptographically re-verified."
    )
    story.append(Paragraph(limitations, styles["body"]))
    story.append(Paragraph(
        f"Prepared by {BRAND_NAME} · {CONTACT_EMAIL} · {WEBSITE}",
        styles["small"],
    ))

    doc.build(
        story,
        onFirstPage=lambda canvas, document: draw_pdf_header_footer(canvas, document, report),
        onLaterPages=lambda canvas, document: draw_pdf_header_footer(canvas, document, report),
    )
    return buffer.getvalue()


# -----------------------------------------------------------------------------
# Streamlit presentation
# -----------------------------------------------------------------------------

def inject_css() -> None:
    st.markdown(
        f"""
        <style>
        :root {{
            --primary: {PRIMARY};
            --navy: {NAVY};
            --navy2: {NAVY_2};
            --panel: {PANEL};
            --text: {TEXT};
            --muted: {MUTED};
            --green: {GREEN};
            --amber: {AMBER};
            --red: {RED};
        }}
        .stApp {{
            background:
                radial-gradient(circle at 84% 5%, rgba(53,227,178,.12), transparent 27rem),
                linear-gradient(180deg, #06131e 0%, #081927 50%, #06131e 100%);
            color: var(--text);
        }}
        .block-container {{ max-width: 1120px; padding-top: 1.8rem; padding-bottom: 3rem; }}
        header[data-testid="stHeader"] {{ background: transparent; }}
        #MainMenu, footer {{ visibility: hidden; }}
        .brand-row {{ display:flex; align-items:center; gap:14px; margin-bottom:1.25rem; }}
        .brand-mark {{ width:46px; height:52px; flex:0 0 auto; }}
        .brand-name {{ color:#fff; font-weight:800; letter-spacing:.11em; font-size:1.1rem; }}
        .brand-sub {{ color:var(--primary); font-size:.72rem; letter-spacing:.12em; text-transform:uppercase; }}
        .hero {{
            border:1px solid rgba(152,173,186,.2); border-radius:22px; padding:30px 34px;
            background:linear-gradient(135deg, rgba(16,40,58,.96), rgba(7,21,34,.95));
            box-shadow:0 18px 55px rgba(0,0,0,.25); margin-bottom:1.1rem;
        }}
        .eyebrow {{ color:var(--primary); text-transform:uppercase; letter-spacing:.16em; font-size:.72rem; font-weight:700; }}
        .hero h1 {{ color:#fff; margin:.45rem 0 .65rem; font-size:clamp(2rem,5vw,3.5rem); line-height:1.02; letter-spacing:-.035em; }}
        .hero p {{ color:#b9c9d1; max-width:780px; font-size:1.02rem; line-height:1.65; margin:0; }}
        .trust-row {{ display:flex; gap:9px; flex-wrap:wrap; margin-top:1.2rem; }}
        .trust-pill {{ border:1px solid rgba(53,227,178,.28); color:#cceee5; border-radius:999px; padding:7px 11px; font-size:.76rem; background:rgba(53,227,178,.06); }}
        div[data-testid="stForm"] {{
            background:rgba(11,32,49,.85); border:1px solid rgba(152,173,186,.2); border-radius:18px; padding:1.2rem 1.25rem .7rem;
        }}
        label, .stMarkdown p, .stCaption {{ color:#dce9ec !important; }}
        input, textarea {{ background:#071522 !important; color:#effafa !important; border:1px solid #2a485b !important; border-radius:10px !important; }}
        input:focus, textarea:focus {{ border-color:var(--primary) !important; box-shadow:0 0 0 1px var(--primary) !important; }}
        div.stButton > button, div.stFormSubmitButton > button, div.stDownloadButton > button {{
            border-radius:10px; min-height:44px; font-weight:750; border:1px solid var(--primary);
            background:var(--primary); color:#041118; transition:all .16s ease;
        }}
        div.stButton > button:hover, div.stFormSubmitButton > button:hover, div.stDownloadButton > button:hover {{
            border-color:#7df0cf; background:#7df0cf; color:#041118; transform:translateY(-1px);
        }}
        .section-title {{ color:#fff; font-size:1.3rem; font-weight:800; margin:1.7rem 0 .8rem; }}
        .metric-card {{
            background:rgba(16,40,58,.86); border:1px solid rgba(152,173,186,.19); border-radius:16px;
            padding:17px 18px; min-height:142px; box-shadow:0 10px 28px rgba(0,0,0,.15);
        }}
        .metric-top {{ display:flex; justify-content:space-between; align-items:center; gap:10px; }}
        .metric-title {{ color:#a8bbc5; text-transform:uppercase; letter-spacing:.11em; font-size:.69rem; font-weight:700; }}
        .status-dot {{ width:10px; height:10px; border-radius:50%; box-shadow:0 0 13px currentColor; }}
        .metric-value {{ color:#fff; font-size:1.43rem; font-weight:800; margin:.68rem 0 .35rem; }}
        .metric-detail {{ color:#9fb3bd; font-size:.79rem; line-height:1.45; }}
        .score-wrap {{
            padding:22px; border-radius:18px; border:1px solid rgba(152,173,186,.2);
            background:linear-gradient(145deg, rgba(16,40,58,.95), rgba(8,25,39,.95));
        }}
        .score-number {{ color:#fff; font-size:3.5rem; font-weight:850; letter-spacing:-.06em; line-height:1; }}
        .score-number span {{ color:#78909d; font-size:1.05rem; letter-spacing:0; }}
        .score-label {{ font-size:1.05rem; font-weight:750; margin-top:.5rem; }}
        .score-summary {{ color:#a9bdc7; font-size:.84rem; line-height:1.5; margin-top:.5rem; }}
        .record-box {{ background:#06131e; border:1px solid #223f52; border-radius:12px; padding:13px; color:#bcd0d8; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.75rem; overflow-wrap:anywhere; }}
        .recommendation {{ border-left:4px solid var(--primary); background:rgba(16,40,58,.75); padding:13px 15px; border-radius:0 12px 12px 0; margin-bottom:10px; }}
        .recommendation b {{ color:#fff; }}
        .recommendation span {{ display:inline-block; font-size:.67rem; font-weight:800; padding:3px 7px; border-radius:999px; margin-right:7px; color:#06131e; }}
        .recommendation p {{ color:#aabdc6 !important; margin:.35rem 0 0; font-size:.82rem; }}
        .disclaimer {{ color:#78909d; font-size:.72rem; line-height:1.5; margin-top:1.5rem; padding:12px 14px; border-top:1px solid rgba(152,173,186,.15); }}
        div[data-testid="stAlert"] {{ border-radius:12px; }}
        @media (max-width: 640px) {{ .hero {{ padding:23px 20px; }} .block-container {{ padding-left:1rem; padding-right:1rem; }} }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def brand_header() -> None:
    st.markdown(
        """
        <div class="brand-row">
          <svg class="brand-mark" viewBox="0 0 60 68" aria-hidden="true">
            <path d="M30 2 L57 14 L51 49 L30 66 L9 49 L3 14 Z" fill="#35E3B2"/>
            <path d="M19 35 L27 43 L43 25" fill="none" stroke="#071522" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
          <div><div class="brand-name">NEXANAR</div><div class="brand-sub">Cyber Scout</div></div>
        </div>
        <div class="hero">
          <div class="eyebrow">External attack-surface signal</div>
          <h1>Can attackers spoof your company email?</h1>
          <p>Run a rapid, non-invasive DNS assessment of SPF and DMARC enforcement, review optional message-header evidence, and export an executive PDF brief.</p>
          <div class="trust-row">
            <span class="trust-pill">No login required</span>
            <span class="trust-pill">No data stored</span>
            <span class="trust-pill">Read-only DNS checks</span>
            <span class="trust-pill">PDF generated in memory</span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def state_color(state: str) -> str:
    return {"secure": GREEN, "warning": AMBER, "critical": RED}.get(state, BLUE)


def metric_card(title: str, value: str, detail: str, state: str) -> None:
    color = state_color(state)
    st.markdown(
        f"""
        <div class="metric-card">
          <div class="metric-top"><div class="metric-title">{html.escape(title)}</div><div class="status-dot" style="background:{color};color:{color}"></div></div>
          <div class="metric-value">{html.escape(value)}</div>
          <div class="metric-detail">{html.escape(detail)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def recommendation_card(item: Mapping[str, str]) -> None:
    priority = item["priority"]
    badge = RED if priority == "P1" else AMBER if priority == "P2" else BLUE
    st.markdown(
        f"""
        <div class="recommendation">
          <b><span style="background:{badge}">{html.escape(priority)}</span>{html.escape(item['title'])}</b>
          <p>{html.escape(item['action'])}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def display_results(report: Mapping[str, Any]) -> None:
    st.markdown('<div class="section-title">Assessment overview</div>', unsafe_allow_html=True)
    left, right = st.columns([0.34, 0.66], gap="large")
    with left:
        st.markdown(
            f"""
            <div class="score-wrap">
              <div class="metric-title">Composite posture score</div>
              <div class="score-number">{report['score']}<span>/100</span></div>
              <div class="score-label" style="color:{report['posture_color']}">{html.escape(report['posture'])} posture</div>
              <div class="score-summary">{html.escape(report['summary'])}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with right:
        col1, col2, col3 = st.columns(3)
        with col1:
            ev = report["evaluations"]["dmarc"]
            metric_card("DMARC", ev["label"], ev["detail"], ev["state"])
        with col2:
            ev = report["evaluations"]["spf"]
            metric_card("SPF", ev["label"], ev["detail"], ev["state"])
        with col3:
            ev = report["evaluations"]["mx"]
            metric_card("Mail routing", ev["label"], ev["detail"], ev["state"])

    st.markdown('<div class="section-title">DNS evidence</div>', unsafe_allow_html=True)
    dmarc_col, spf_col = st.columns(2, gap="large")
    with dmarc_col:
        st.markdown("**DMARC record**")
        st.markdown(
            f'<div class="record-box">{html.escape(safe_text(report["dmarc"].get("record"), safe_text(report["dmarc"].get("error"))))}</div>',
            unsafe_allow_html=True,
        )
        st.caption(
            f"Policy: {safe_text(report['dmarc'].get('policy'))} · Subdomain: {safe_text(report['dmarc'].get('subdomain_policy'))} · Coverage: {safe_text(report['dmarc'].get('pct'), '100')}%"
        )
    with spf_col:
        st.markdown("**SPF record**")
        st.markdown(
            f'<div class="record-box">{html.escape(safe_text(report["spf"].get("record"), safe_text(report["spf"].get("error"))))}</div>',
            unsafe_allow_html=True,
        )
        st.caption(f"DNS lookups reported: {safe_text(report['spf'].get('dns_lookups'), 'Not available')}")

    header = report["header_analysis"]
    if header.get("provided"):
        st.markdown('<div class="section-title">Supplied header evidence</div>', unsafe_allow_html=True)
        cols = st.columns(3)
        for idx, mechanism in enumerate(("spf", "dkim", "dmarc")):
            status = header["statuses"].get(mechanism, "not-found")
            state = "secure" if status == "pass" else "critical" if status in {"fail", "permerror"} else "warning"
            with cols[idx]:
                metric_card(mechanism.upper(), status.upper(), "Reported in Authentication-Results / Received-SPF.", state)
        st.caption(header["note"])

    st.markdown('<div class="section-title">Recommended next actions</div>', unsafe_allow_html=True)
    for recommendation in report["recommendations"]:
        recommendation_card(recommendation)

    engine_messages = flatten_messages(report["engine"].get("checkdmarc_error")) + flatten_messages(report["engine"].get("dns_errors"))
    if engine_messages:
        with st.expander("Scan diagnostics"):
            for message in engine_messages:
                st.write(f"• {message}")

    st.markdown('<div class="section-title">Export executive brief</div>', unsafe_allow_html=True)
    st.download_button(
        "Download branded PDF report",
        data=st.session_state.pdf_bytes,
        file_name=f"cyber-scout-{report['domain'].replace('.', '-')}.pdf",
        mime="application/pdf",
        use_container_width=True,
        key="download_report",
    )


def initialize_state() -> None:
    defaults = {
        "report": None,
        "pdf_bytes": None,
        "last_domain": "",
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def main() -> None:
    st.set_page_config(
        page_title=f"{APP_NAME} | Email Spoofing Assessment",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    inject_css()
    initialize_state()
    brand_header()

    with st.form("assessment_form", clear_on_submit=False):
        domain_input = st.text_input(
            "Corporate domain",
            value=st.session_state.last_domain,
            placeholder="company.com",
            help="Enter a public domain only. URLs and email addresses are normalized automatically.",
        )
        raw_headers = st.text_area(
            "Raw email headers (optional)",
            height=150,
            placeholder="Paste full raw headers to display SPF, DKIM, and DMARC outcomes reported by the receiving mail server...",
            help=f"Maximum {MAX_HEADER_CHARS:,} characters. Header content remains in the current session only.",
        )
        submitted = st.form_submit_button("Run security assessment", use_container_width=True)

    if submitted:
        try:
            domain = normalize_domain(domain_input)
            with st.spinner("Resolving DNS records and evaluating policy enforcement..."):
                report = assess_domain(domain, raw_headers)
                pdf_bytes = create_pdf(report)
            st.session_state.report = report
            st.session_state.pdf_bytes = pdf_bytes
            st.session_state.last_domain = domain
        except ValueError as exc:
            st.error(str(exc))
        except Exception as exc:
            st.error(f"The assessment could not be completed: {exc}")

    if st.session_state.report and st.session_state.pdf_bytes:
        display_results(st.session_state.report)

    st.markdown(
        """
        <div class="disclaimer">
          Cyber Scout performs read-only checks against publicly available DNS data. Results may be affected by DNS caching, resolver availability, delegated records, and configuration changes after the scan. This output is an indicative lead-generation assessment, not a formal audit or certification.
        </div>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
