"""Nexanar Scout — passive B2B email-security and external exposure dashboard.

Run locally:
    python -m streamlit run app.py

The application performs read-only checks against public DNS, HTTPS endpoints,
certificate-transparency data, and optional email headers. It does not attempt
authentication, exploit systems, send messages, or modify any target.
"""

from __future__ import annotations

import csv
import html
import io
import json
import re
import socket
import ssl
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

import dns.exception
import dns.resolver
import streamlit as st
from streamlit_option_menu import option_menu
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

import core

# Re-export core helpers so the original tests and integrations remain compatible.
normalize_domain = core.normalize_domain
analyze_headers = core.analyze_headers
evaluate_dmarc = core.evaluate_dmarc
evaluate_spf = core.evaluate_spf

APP_NAME = "Nexanar Scout"
APP_VERSION = "2.0"
BRAND_NAME = "Nexanar"
COPYRIGHT = "© 2026 Nexanar Deutschland. All rights reserved."
CONTACT_EMAIL = "security@nexanar.example"
WEBSITE = "nexanar.example"

BG = "#07111D"
SIDEBAR = "#081725"
PANEL = "#0E2133"
PANEL_2 = "#102A3E"
BORDER = "#1E3A4F"
TEXT = "#EEF7FA"
MUTED = "#90A8B7"
CYAN = "#20C6D7"
BLUE = "#4A8CFF"
GREEN = "#2ED39A"
AMBER = "#F6B94A"
RED = "#FF5B6E"
PURPLE = "#9B7BFF"

HTTP_TIMEOUT = 6
MAX_CT_SUBDOMAINS = 150
MAX_WEB_BYTES = 750_000

NAV_ITEMS = [
    "Overview",
    "New Assessment",
    "Email Security",
    "Exposure Discovery",
    "Findings",
    "Executive Report",
    "Methodology",
]

NAV_ICONS = {
    "Overview": "house",
    "New Assessment": "search",
    "Email Security": "shield-lock",
    "Exposure Discovery": "eye",
    "Findings": "exclamation-triangle",
    "Executive Report": "file-earmark-pdf",
    "Methodology": "book",
}

NAV_ACCENT = "#00FF66"

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4, "Passed": 5}
SEVERITY_COLOR = {
    "Critical": RED,
    "High": "#FF866F",
    "Medium": AMBER,
    "Low": BLUE,
    "Informational": PURPLE,
    "Passed": GREEN,
}


def safe(value: Any, fallback: str = "—") -> str:
    if value is None:
        return fallback
    text = str(value).strip()
    return text or fallback


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def dns_values(name: str, record_type: str, timeout: float = 4.5) -> tuple[list[str], str | None]:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(name, record_type, lifetime=timeout)
        values: list[str] = []
        for answer in answers:
            if record_type == "TXT" and hasattr(answer, "strings"):
                values.append(b"".join(answer.strings).decode("utf-8", errors="replace"))
            else:
                values.append(str(answer).strip('"').rstrip("."))
        return values, None
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return [], "Not published"
    except (dns.exception.Timeout, dns.resolver.NoNameservers, OSError) as exc:
        return [], str(exc)


def find_txt(prefix: str, domain: str, marker: str | None = None) -> dict[str, Any]:
    name = f"{prefix}.{domain}" if prefix else domain
    records, error = dns_values(name, "TXT")
    if marker:
        records = [record for record in records if record.lower().startswith(marker.lower())]
    return {"name": name, "present": bool(records), "records": records, "error": error if not records else None}


def scan_dns_surface(domain: str) -> dict[str, Any]:
    a_records, a_error = dns_values(domain, "A")
    aaaa_records, aaaa_error = dns_values(domain, "AAAA")
    ns_records, ns_error = dns_values(domain, "NS")
    caa_records, caa_error = dns_values(domain, "CAA")
    dnskey_records, dnskey_error = dns_values(domain, "DNSKEY")

    return {
        "addresses": {"ipv4": a_records, "ipv6": aaaa_records, "errors": [item for item in (a_error, aaaa_error) if item and item != "Not published"]},
        "nameservers": {"records": ns_records, "error": ns_error if not ns_records else None},
        "caa": {"present": bool(caa_records), "records": caa_records, "error": caa_error if not caa_records else None},
        "dnssec": {"published": bool(dnskey_records), "records": dnskey_records[:8], "error": dnskey_error if not dnskey_records else None},
        "mta_sts": find_txt("_mta-sts", domain, "v=STSv1"),
        "tls_rpt": find_txt("_smtp._tls", domain, "v=TLSRPTv1"),
        "bimi": find_txt("default._bimi", domain, "v=BIMI1"),
    }


def fetch_url(url: str, *, max_bytes: int = MAX_WEB_BYTES) -> dict[str, Any]:
    request = Request(
        url,
        headers={
            "User-Agent": "NexanarScout/2.0 (+passive-security-assessment)",
            "Accept": "text/html,application/json;q=0.9,*/*;q=0.7",
        },
    )
    context = ssl.create_default_context()
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT, context=context) as response:
            body = response.read(max_bytes)
            headers = {key.lower(): value for key, value in response.headers.items()}
            return {
                "ok": True,
                "url": response.geturl(),
                "status": getattr(response, "status", 200),
                "headers": headers,
                "body": body.decode("utf-8", errors="replace"),
                "error": None,
            }
    except HTTPError as exc:
        return {"ok": False, "url": url, "status": exc.code, "headers": {}, "body": "", "error": f"HTTP {exc.code}"}
    except (URLError, TimeoutError, ssl.SSLError, socket.timeout, OSError) as exc:
        return {"ok": False, "url": url, "status": None, "headers": {}, "body": "", "error": str(exc)}


def scan_web_surface(domain: str) -> dict[str, Any]:
    primary = fetch_url(f"https://{domain}/")
    if not primary["ok"]:
        alternate = fetch_url(f"https://www.{domain}/")
        if alternate["ok"]:
            primary = alternate

    headers = primary.get("headers", {})
    body = primary.get("body", "")
    domain_pattern = re.escape(domain)
    email_pattern = re.compile(rf"[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)*{domain_pattern}\b", re.IGNORECASE)
    emails = sorted({match.lower() for match in email_pattern.findall(body)})[:50]
    pgp_links = sorted(set(re.findall(r"(?:openpgp4fpr:[A-F0-9]+|https?://[^\"'<>\s]+\.(?:asc|pgp))", body, flags=re.IGNORECASE)))[:20]

    security_headers = {
        "strict-transport-security": headers.get("strict-transport-security"),
        "content-security-policy": headers.get("content-security-policy"),
        "x-content-type-options": headers.get("x-content-type-options"),
        "referrer-policy": headers.get("referrer-policy"),
        "permissions-policy": headers.get("permissions-policy"),
    }

    wkd_policy = fetch_url(f"https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/policy", max_bytes=2048)
    if not wkd_policy["ok"]:
        wkd_policy = fetch_url(f"https://{domain}/.well-known/openpgpkey/policy", max_bytes=2048)

    return {
        "reachable": bool(primary["ok"]),
        "final_url": primary.get("url"),
        "status": primary.get("status"),
        "error": primary.get("error"),
        "headers": security_headers,
        "public_emails": emails,
        "pgp_links": pgp_links,
        "wkd_detected": bool(wkd_policy["ok"]),
        "wkd_url": wkd_policy.get("url") if wkd_policy["ok"] else None,
    }


def enumerate_subdomains(domain: str) -> dict[str, Any]:
    url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
    response = fetch_url(url, max_bytes=2_500_000)
    if not response["ok"]:
        return {"source": "crt.sh certificate transparency", "subdomains": [], "truncated": False, "error": response["error"]}
    try:
        payload = json.loads(response["body"])
    except json.JSONDecodeError as exc:
        return {"source": "crt.sh certificate transparency", "subdomains": [], "truncated": False, "error": f"Invalid CT response: {exc}"}

    discovered: set[str] = set()
    for item in payload if isinstance(payload, list) else []:
        for name in str(item.get("name_value", "")).splitlines():
            candidate = name.strip().lower().lstrip("*.").rstrip(".")
            if candidate == domain or candidate.endswith(f".{domain}"):
                discovered.add(candidate)
    ordered = sorted(discovered, key=lambda value: (value.count("."), value))
    return {
        "source": "crt.sh certificate transparency",
        "subdomains": ordered[:MAX_CT_SUBDOMAINS],
        "truncated": len(ordered) > MAX_CT_SUBDOMAINS,
        "error": None,
    }


def control_state(label: str, present: bool, detail: str, *, missing_severity: str = "Medium") -> dict[str, str]:
    return {
        "label": label,
        "status": "Configured" if present else "Missing / not detected",
        "severity": "Passed" if present else missing_severity,
        "detail": detail,
    }


def build_findings(email_report: Mapping[str, Any], dns_surface: Mapping[str, Any], web_surface: Mapping[str, Any], osint: Mapping[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    dmarc_eval = email_report["evaluations"]["dmarc"]
    spf_eval = email_report["evaluations"]["spf"]
    mx_eval = email_report["evaluations"]["mx"]

    dmarc_severity = "Critical" if dmarc_eval["state"] == "critical" else "Medium" if dmarc_eval["state"] == "warning" else "Passed"
    findings.append({
        "id": "MAIL-001", "category": "Email Security", "title": "DMARC enforcement", "severity": dmarc_severity,
        "status": dmarc_eval["label"], "evidence": safe(email_report["dmarc"].get("record"), safe(email_report["dmarc"].get("error"))),
        "impact": "Weak or absent DMARC enforcement permits visible From-domain impersonation and increases business-email-compromise exposure.",
        "remediation": "Validate legitimate senders, move from monitoring to quarantine, then enforce p=reject with full coverage.",
    })

    spf_severity = "High" if spf_eval["state"] == "critical" else "Medium" if spf_eval["state"] == "warning" else "Passed"
    findings.append({
        "id": "MAIL-002", "category": "Email Security", "title": "SPF sender authorization", "severity": spf_severity,
        "status": spf_eval["label"], "evidence": safe(email_report["spf"].get("record"), safe(email_report["spf"].get("error"))),
        "impact": "Incorrect sender authorization can allow unauthorized infrastructure to send mail using the assessed domain.",
        "remediation": "Maintain one valid SPF record, remove obsolete services, remain within DNS lookup limits, and use a restrictive terminal mechanism.",
    })

    mx_severity = "High" if mx_eval["state"] == "critical" else "Passed"
    mx_hosts = email_report["mx"].get("hosts") or []
    findings.append({
        "id": "MAIL-003", "category": "Email Security", "title": "Mail exchanger visibility", "severity": mx_severity,
        "status": mx_eval["label"], "evidence": ", ".join(safe(item.get("hostname") if isinstance(item, Mapping) else item) for item in mx_hosts[:8]) or safe(email_report["mx"].get("error")),
        "impact": "Missing or unexpected MX records can indicate routing errors or an incomplete mail-domain configuration.",
        "remediation": "Confirm all mail exchangers are expected, current, and managed by approved providers.",
    })

    for finding_id, key, title, missing_severity, remediation in (
        ("MAIL-004", "mta_sts", "MTA-STS transport policy", "Medium", "Publish a valid _mta-sts TXT record and host the corresponding HTTPS policy file."),
        ("MAIL-005", "tls_rpt", "SMTP TLS reporting", "Low", "Publish a TLS-RPT record with an actively monitored reporting destination."),
        ("BRAND-001", "bimi", "BIMI brand indicator", "Informational", "Consider BIMI only after SPF, DKIM, and DMARC enforcement are mature."),
    ):
        item = dns_surface[key]
        findings.append({
            "id": finding_id, "category": "Email Transport" if key != "bimi" else "Brand Protection", "title": title,
            "severity": "Passed" if item["present"] else missing_severity,
            "status": "Published" if item["present"] else "Not detected",
            "evidence": "; ".join(item["records"]) if item["records"] else safe(item.get("error")),
            "impact": "This control improves transport visibility, policy enforcement, or trusted brand presentation." if item["present"] else "The related defensive or reporting capability is not visible in public DNS.",
            "remediation": remediation,
        })

    findings.append({
        "id": "DNS-001", "category": "DNS Security", "title": "DNSSEC publication",
        "severity": "Passed" if dns_surface["dnssec"]["published"] else "Low",
        "status": "DNSKEY published" if dns_surface["dnssec"]["published"] else "DNSKEY not detected",
        "evidence": "; ".join(dns_surface["dnssec"]["records"][:3]) if dns_surface["dnssec"]["records"] else safe(dns_surface["dnssec"].get("error")),
        "impact": "DNSSEC helps recipients validate DNS authenticity; this check detects publication but does not perform full chain validation.",
        "remediation": "Enable DNSSEC at the authoritative DNS provider and publish the correct DS record with the registrar.",
    })

    findings.append({
        "id": "DNS-002", "category": "DNS Security", "title": "CAA certificate restrictions",
        "severity": "Passed" if dns_surface["caa"]["present"] else "Low",
        "status": "CAA published" if dns_surface["caa"]["present"] else "CAA not detected",
        "evidence": "; ".join(dns_surface["caa"]["records"]) if dns_surface["caa"]["records"] else safe(dns_surface["caa"].get("error")),
        "impact": "CAA limits which certificate authorities may issue certificates for the domain.",
        "remediation": "Publish CAA records authorizing only the certificate authorities used by the organization.",
    })

    if web_surface.get("reachable"):
        header_map = web_surface.get("headers", {})
        for finding_id, header_name, title, severity in (
            ("WEB-001", "strict-transport-security", "HTTP Strict Transport Security", "Medium"),
            ("WEB-002", "content-security-policy", "Content Security Policy", "Low"),
            ("WEB-003", "x-content-type-options", "MIME sniffing protection", "Low"),
        ):
            present = bool(header_map.get(header_name))
            findings.append({
                "id": finding_id, "category": "Web Surface", "title": title,
                "severity": "Passed" if present else severity, "status": "Present" if present else "Not detected",
                "evidence": safe(header_map.get(header_name), "Header not returned"),
                "impact": "The assessed HTTPS endpoint exposes the related browser security control." if present else "The public website did not return this browser hardening header during the passive check.",
                "remediation": f"Configure and test the {header_name} response header at the web server or CDN.",
            })
    else:
        findings.append({
            "id": "WEB-000", "category": "Web Surface", "title": "HTTPS endpoint reachability", "severity": "Informational",
            "status": "Not assessed", "evidence": safe(web_surface.get("error")),
            "impact": "Web-header checks could not be completed from the scanning environment.",
            "remediation": "Confirm public HTTPS reachability and rerun the assessment from an unrestricted network.",
        })

    subdomains = osint.get("subdomains", [])
    findings.append({
        "id": "OSINT-001", "category": "Exposure Discovery", "title": "Certificate-transparency hostnames", "severity": "Informational",
        "status": f"{len(subdomains)} hostname(s) discovered", "evidence": ", ".join(subdomains[:12]) or safe(osint.get("error"), "No hostnames returned"),
        "impact": "Certificate-transparency history can reveal public or legacy hostnames that require inventory and ownership review.",
        "remediation": "Compare discovered hostnames with the approved asset inventory and retire or secure unexpected services.",
    })

    public_emails = web_surface.get("public_emails", [])
    findings.append({
        "id": "OSINT-002", "category": "Exposure Discovery", "title": "Public corporate email addresses", "severity": "Informational",
        "status": f"{len(public_emails)} address(es) found", "evidence": ", ".join(public_emails[:15]) or "No same-domain address was extracted from the public landing page.",
        "impact": "Public email addresses can support legitimate contact but may also increase phishing and impersonation targeting.",
        "remediation": "Use role-based addresses where appropriate, train exposed users, and monitor for impersonation campaigns.",
    })

    findings.sort(key=lambda item: (SEVERITY_ORDER.get(item["severity"], 99), item["id"]))
    return findings


def calculate_external_score(email_score: int, findings: list[Mapping[str, str]]) -> int:
    score = int(email_score)
    deductions = {"Critical": 12, "High": 8, "Medium": 4, "Low": 2}
    extra = sum(deductions.get(item["severity"], 0) for item in findings if not item["id"].startswith("MAIL-00"))
    return max(0, min(100, score - min(extra, 30)))


def run_full_assessment(domain: str, raw_headers: str, include_web: bool, include_ct: bool) -> dict[str, Any]:
    email_report = core.assess_domain(domain, raw_headers)
    dns_surface = scan_dns_surface(domain)
    web_surface = scan_web_surface(domain) if include_web else {
        "reachable": False, "final_url": None, "status": None, "error": "Web checks disabled",
        "headers": {}, "public_emails": [], "pgp_links": [], "wkd_detected": False, "wkd_url": None,
    }
    osint = enumerate_subdomains(domain) if include_ct else {
        "source": "crt.sh certificate transparency", "subdomains": [], "truncated": False, "error": "Certificate-transparency discovery disabled",
    }
    findings = build_findings(email_report, dns_surface, web_surface, osint)
    external_score = calculate_external_score(email_report["score"], findings)
    posture, exposure, color = core.label_from_score(external_score)

    return {
        "scan_id": email_report["scan_id"].replace("CSC", "NXS"),
        "scanned_at": utc_now(),
        "domain": domain,
        "email": email_report,
        "dns_surface": dns_surface,
        "web_surface": web_surface,
        "osint": osint,
        "findings": findings,
        "score": external_score,
        "email_score": email_report["score"],
        "posture": posture,
        "exposure": exposure,
        "posture_color": color,
        "summary": f"{domain} received an external posture score of {external_score}/100. The assessment combines email-authentication controls with passive DNS, HTTPS, and public exposure signals.",
        "scope": {"web_checks": include_web, "certificate_transparency": include_ct, "raw_headers_supplied": bool(raw_headers.strip())},
    }


def pdf_color(value: str) -> colors.Color:
    return colors.HexColor(value)


def create_executive_pdf(result: Mapping[str, Any]) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"Nexanar Scout Report - {result['domain']}",
        author=BRAND_NAME,
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="NXTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=23, leading=27, textColor=pdf_color(BG), alignment=TA_LEFT, spaceAfter=4 * mm))
    styles.add(ParagraphStyle(name="NXSub", parent=styles["Normal"], fontSize=9, leading=13, textColor=pdf_color("#526A79"), spaceAfter=5 * mm))
    styles.add(ParagraphStyle(name="NXH1", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=13, leading=17, textColor=pdf_color(BG), spaceBefore=5 * mm, spaceAfter=2.5 * mm))
    styles.add(ParagraphStyle(name="NXBody", parent=styles["BodyText"], fontSize=8.5, leading=12, textColor=pdf_color("#263C49")))
    styles.add(ParagraphStyle(name="NXSmall", parent=styles["BodyText"], fontSize=7.2, leading=9.5, textColor=pdf_color("#526A79")))
    styles.add(ParagraphStyle(name="NXCenter", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=8, leading=10, alignment=TA_CENTER, textColor=pdf_color(BG)))

    story: list[Any] = []
    story.append(Paragraph("NEXANAR SCOUT", styles["NXTitle"]))
    story.append(Paragraph(
        f"External Email Security & Exposure Assessment · {html.escape(result['domain'])}<br/>"
        f"Scan ID: {html.escape(result['scan_id'])} · Generated: {html.escape(result['scanned_at'])}",
        styles["NXSub"],
    ))

    severity_counts = {key: 0 for key in SEVERITY_ORDER}
    for finding in result["findings"]:
        severity_counts[finding["severity"]] = severity_counts.get(finding["severity"], 0) + 1

    score_table = Table([
        [Paragraph("EXTERNAL SCORE", styles["NXCenter"]), Paragraph("EMAIL SCORE", styles["NXCenter"]), Paragraph("POSTURE", styles["NXCenter"]), Paragraph("CRITICAL / HIGH", styles["NXCenter"])],
        [Paragraph(f"<b>{result['score']}/100</b>", styles["NXCenter"]), Paragraph(f"<b>{result['email_score']}/100</b>", styles["NXCenter"]), Paragraph(f"<b>{html.escape(result['posture'])}</b>", styles["NXCenter"]), Paragraph(f"<b>{severity_counts['Critical']} / {severity_counts['High']}</b>", styles["NXCenter"])],
    ], colWidths=[44 * mm, 44 * mm, 44 * mm, 44 * mm], rowHeights=[8 * mm, 14 * mm])
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), pdf_color("#E8F1F4")),
        ("BACKGROUND", (0, 1), (0, 1), pdf_color(CYAN)),
        ("BACKGROUND", (1, 1), (1, 1), pdf_color(BLUE)),
        ("BACKGROUND", (2, 1), (2, 1), pdf_color(result["posture_color"])),
        ("BACKGROUND", (3, 1), (3, 1), pdf_color(RED if severity_counts["Critical"] else AMBER if severity_counts["High"] else GREEN)),
        ("TEXTCOLOR", (0, 1), (-1, 1), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, pdf_color("#C9D9E0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(html.escape(result["summary"]), styles["NXBody"]))

    story.append(Paragraph("Executive Control Summary", styles["NXH1"]))
    email_report = result["email"]
    controls = [
        ("DMARC", email_report["evaluations"]["dmarc"]["label"], email_report["evaluations"]["dmarc"]["state"]),
        ("SPF", email_report["evaluations"]["spf"]["label"], email_report["evaluations"]["spf"]["state"]),
        ("MTA-STS", "Published" if result["dns_surface"]["mta_sts"]["present"] else "Not detected", "secure" if result["dns_surface"]["mta_sts"]["present"] else "warning"),
        ("TLS-RPT", "Published" if result["dns_surface"]["tls_rpt"]["present"] else "Not detected", "secure" if result["dns_surface"]["tls_rpt"]["present"] else "warning"),
        ("DNSSEC", "DNSKEY published" if result["dns_surface"]["dnssec"]["published"] else "Not detected", "secure" if result["dns_surface"]["dnssec"]["published"] else "warning"),
        ("HTTPS", "Reachable" if result["web_surface"]["reachable"] else "Not assessed / unreachable", "secure" if result["web_surface"]["reachable"] else "warning"),
    ]
    control_rows = [[Paragraph("CONTROL", styles["NXCenter"]), Paragraph("RESULT", styles["NXCenter"]), Paragraph("STATE", styles["NXCenter"])]]
    for name, value, state in controls:
        state_label = "PASS" if state == "secure" else "REVIEW" if state == "warning" else "FAIL"
        control_rows.append([Paragraph(name, styles["NXBody"]), Paragraph(html.escape(value), styles["NXBody"]), Paragraph(state_label, styles["NXCenter"])])
    control_table = Table(control_rows, colWidths=[38 * mm, 102 * mm, 36 * mm], repeatRows=1)
    styles_list = [
        ("BACKGROUND", (0, 0), (-1, 0), pdf_color(BG)), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, pdf_color("#C9D9E0")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]
    for row_index, (_, _, state) in enumerate(controls, start=1):
        shade = GREEN if state == "secure" else AMBER if state == "warning" else RED
        styles_list.extend([("BACKGROUND", (2, row_index), (2, row_index), pdf_color(shade)), ("TEXTCOLOR", (2, row_index), (2, row_index), colors.white)])
    control_table.setStyle(TableStyle(styles_list))
    story.append(control_table)

    story.append(PageBreak())
    story.append(Paragraph("Prioritized Findings", styles["NXTitle"]))
    findings_rows = [[Paragraph("ID", styles["NXCenter"]), Paragraph("SEVERITY", styles["NXCenter"]), Paragraph("FINDING", styles["NXCenter"]), Paragraph("REMEDIATION", styles["NXCenter"])]]
    report_findings = [item for item in result["findings"] if item["severity"] != "Passed"]
    for item in report_findings[:18]:
        findings_rows.append([
            Paragraph(html.escape(item["id"]), styles["NXSmall"]),
            Paragraph(html.escape(item["severity"]), styles["NXCenter"]),
            Paragraph(f"<b>{html.escape(item['title'])}</b><br/>{html.escape(item['status'])}<br/><font color='#526A79'>{html.escape(item['evidence'][:420])}</font>", styles["NXBody"]),
            Paragraph(html.escape(item["remediation"]), styles["NXBody"]),
        ])
    findings_table = Table(findings_rows, colWidths=[21 * mm, 25 * mm, 70 * mm, 60 * mm], repeatRows=1)
    finding_styles = [
        ("BACKGROUND", (0, 0), (-1, 0), pdf_color(BG)), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.35, pdf_color("#CBD9DF")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for row_index, item in enumerate(report_findings[:18], start=1):
        finding_styles.extend([("BACKGROUND", (1, row_index), (1, row_index), pdf_color(SEVERITY_COLOR[item["severity"]])), ("TEXTCOLOR", (1, row_index), (1, row_index), colors.white)])
    findings_table.setStyle(TableStyle(finding_styles))
    story.append(findings_table)

    story.append(PageBreak())
    story.append(Paragraph("Technical & Exposure Evidence", styles["NXTitle"]))
    story.append(Paragraph("Email Authentication Records", styles["NXH1"]))
    technical_rows = [
        ["DMARC", safe(email_report["dmarc"].get("record"), safe(email_report["dmarc"].get("error")))],
        ["SPF", safe(email_report["spf"].get("record"), safe(email_report["spf"].get("error")))],
        ["MX", ", ".join(safe(item.get("hostname") if isinstance(item, Mapping) else item) for item in (email_report["mx"].get("hosts") or [])[:10]) or safe(email_report["mx"].get("error"))],
        ["MTA-STS", "; ".join(result["dns_surface"]["mta_sts"]["records"]) or safe(result["dns_surface"]["mta_sts"].get("error"))],
        ["TLS-RPT", "; ".join(result["dns_surface"]["tls_rpt"]["records"]) or safe(result["dns_surface"]["tls_rpt"].get("error"))],
    ]
    tech_table = Table([[Paragraph(f"<b>{html.escape(name)}</b>", styles["NXBody"]), Paragraph(html.escape(value), styles["NXSmall"])] for name, value in technical_rows], colWidths=[35 * mm, 141 * mm])
    tech_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.35, pdf_color("#CBD9DF")), ("BACKGROUND", (0, 0), (0, -1), pdf_color("#EDF3F6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(tech_table)

    story.append(Paragraph("Passive Exposure Discovery", styles["NXH1"]))
    subdomains = result["osint"].get("subdomains", [])
    emails = result["web_surface"].get("public_emails", [])
    exposure_rows = [
        ["Certificate transparency", f"{len(subdomains)} hostname(s): " + (", ".join(subdomains[:35]) if subdomains else safe(result["osint"].get("error")))],
        ["Public corporate emails", f"{len(emails)} address(es): " + (", ".join(emails[:25]) if emails else "None extracted from the assessed landing page")],
        ["PGP / WKD", "WKD policy detected" if result["web_surface"].get("wkd_detected") else "No WKD policy endpoint detected"],
        ["Nameservers", ", ".join(result["dns_surface"]["nameservers"].get("records", [])) or safe(result["dns_surface"]["nameservers"].get("error"))],
        ["IP addresses", ", ".join(result["dns_surface"]["addresses"].get("ipv4", []) + result["dns_surface"]["addresses"].get("ipv6", [])) or "Not resolved"],
    ]
    exp_table = Table([[Paragraph(f"<b>{html.escape(name)}</b>", styles["NXBody"]), Paragraph(html.escape(value), styles["NXSmall"])] for name, value in exposure_rows], colWidths=[45 * mm, 131 * mm])
    exp_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.35, pdf_color("#CBD9DF")), ("BACKGROUND", (0, 0), (0, -1), pdf_color("#EDF3F6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(exp_table)

    story.append(Paragraph("Scope & Limitations", styles["NXH1"]))
    story.append(Paragraph(
        "This is a passive external posture assessment based on public DNS responses, HTTPS response headers, certificate-transparency data, and optional user-supplied email headers. It is not a penetration test, formal certification, guarantee of deliverability, or proof that every asset has been discovered. DKIM keys cannot be exhaustively enumerated without known selectors, and DNSSEC publication is not equivalent to complete chain validation.",
        styles["NXBody"],
    ))
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph(f"Prepared by {BRAND_NAME} · {CONTACT_EMAIL} · {WEBSITE}<br/>{COPYRIGHT}", styles["NXSmall"]))

    doc.build(story)
    return buffer.getvalue()


def findings_csv(result: Mapping[str, Any]) -> bytes:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["id", "severity", "category", "title", "status", "evidence", "impact", "remediation"])
    writer.writeheader()
    for finding in result["findings"]:
        writer.writerow({key: finding.get(key, "") for key in writer.fieldnames})
    return output.getvalue().encode("utf-8-sig")


def inject_css() -> None:
    st.markdown(
        f"""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');

        :root {{
            --bg:{BG}; --sidebar:{SIDEBAR}; --panel:{PANEL}; --panel2:{PANEL_2};
            --border:{BORDER}; --text:{TEXT}; --muted:{MUTED};
            --cyan:{CYAN}; --blue:{BLUE}; --green:{GREEN}; --amber:{AMBER}; --red:{RED}; --purple:{PURPLE};
        }}

        html, body, [class*="css"] {{ font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif; }}
        code, .stCode, .record, .finding-id {{ font-family:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,monospace !important; }}

        /* ---------- App shell ---------- */
        .stApp {{
            background:
                radial-gradient(circle at 88% -8%, rgba(32,198,215,.16), transparent 32rem),
                radial-gradient(circle at 8% 8%, rgba(74,140,255,.08), transparent 30rem),
                linear-gradient(180deg,#050d16 0%,#071523 55%,#081827 100%);
            color:var(--text);
        }}
        [data-testid="stSidebar"] {{
            background:linear-gradient(180deg,#050e18 0%,#081726 100%);
            border-right:1px solid #16324580;
            box-shadow:6px 0 30px rgba(0,0,0,.28);
        }}
        [data-testid="stSidebar"] .block-container {{ padding-top:1.1rem; }}
        [data-testid="stSidebarNav"] {{ display:none; }}
        header[data-testid="stHeader"] {{ background:transparent; }}
        #MainMenu, footer {{ visibility:hidden; }}
        .block-container {{ max-width:1340px; padding-top:1.5rem; padding-bottom:3.5rem; }}
        hr {{ border-color:#153146; }}
        ::selection {{ background:rgba(32,198,215,.35); }}

        /* subtle scrollbar */
        ::-webkit-scrollbar {{ width:9px; height:9px; }}
        ::-webkit-scrollbar-track {{ background:#081422; }}
        ::-webkit-scrollbar-thumb {{ background:#1d3d51; border-radius:8px; }}
        ::-webkit-scrollbar-thumb:hover {{ background:var(--cyan); }}

        /* ---------- Logo ---------- */
        .nx-logo {{ display:flex; align-items:center; gap:12px; padding:10px 4px 20px; border-bottom:1px solid #14283a; margin-bottom:14px; }}
        .nx-mark {{ width:34px;height:40px; filter:drop-shadow(0 0 10px rgba(32,198,215,.45)); }}
        .nx-word {{ color:#fff;font-weight:850;letter-spacing:.14em;font-size:1rem; }}
        .nx-product {{ color:var(--cyan);font-size:.62rem;letter-spacing:.17em;text-transform:uppercase;margin-top:2px;opacity:.9; }}

        /* ---------- Sidebar status ---------- */
        .sidebar-status {{
            border:1px solid #1f4258;
            background:linear-gradient(155deg,rgba(20,45,66,.9),rgba(10,26,40,.9));
            border-radius:16px;padding:15px;margin:10px 0 20px;
            box-shadow:inset 0 1px 0 rgba(255,255,255,.03), 0 10px 26px rgba(0,0,0,.25);
        }}
        .sidebar-kicker {{ color:var(--muted);font-size:.6rem;text-transform:uppercase;letter-spacing:.15em;font-weight:600; }}
        .sidebar-domain {{ color:#fff;font-weight:750;font-size:.92rem;margin-top:6px;overflow-wrap:anywhere; }}
        .sidebar-score {{ color:var(--cyan);font-size:1.6rem;font-weight:900;margin-top:8px;text-shadow:0 0 18px rgba(32,198,215,.5); }}

        /* Restyle sidebar radio nav into a modern nav list */
        [data-testid="stSidebar"] div[role="radiogroup"] {{ gap:3px; }}
        [data-testid="stSidebar"] div[role="radiogroup"] label {{
            background:transparent; border:1px solid transparent; border-radius:10px;
            padding:9px 12px !important; transition:all .16s ease; margin-bottom:2px;
        }}
        [data-testid="stSidebar"] div[role="radiogroup"] label:hover {{
            background:rgba(32,198,215,.08); border-color:rgba(32,198,215,.25);
        }}
        [data-testid="stSidebar"] div[role="radiogroup"] label p {{
            color:#b7cbd6 !important; font-size:.85rem !important; font-weight:600 !important;
        }}
        [data-testid="stSidebar"] div[role="radiogroup"] label[data-baseweb="radio"] > div:first-child {{
            border-color:#2c5468 !important;
        }}

        /* ---------- Page header ---------- */
        .page-head {{ display:flex;justify-content:space-between;gap:20px;align-items:flex-end;margin-bottom:20px; }}
        .page-kicker {{ color:var(--cyan);font-size:.7rem;text-transform:uppercase;letter-spacing:.17em;font-weight:750; }}
        .page-head h1 {{ color:#fff;font-size:2.15rem;line-height:1.1;margin:.4rem 0 .4rem;letter-spacing:-.04em;font-weight:850; }}
        .page-head p {{ color:var(--muted);font-size:.92rem;margin:0;max-width:760px;line-height:1.6; }}
        .scan-meta {{ color:#7d99a8;font-size:.7rem;text-align:right;line-height:1.6;font-family:'JetBrains Mono',monospace; }}

        /* ---------- Hero ---------- */
        .hero-grid {{ display:grid;grid-template-columns:1.25fr .75fr;gap:18px;margin-bottom:22px; }}
        .hero-card {{
            position:relative; overflow:hidden;
            background:linear-gradient(135deg,rgba(17,44,64,.98),rgba(7,25,39,.98));
            border:1px solid #23495f;border-radius:22px;padding:28px;min-height:225px;
            box-shadow:0 20px 60px rgba(0,0,0,.28), inset 0 1px 0 rgba(255,255,255,.04);
        }}
        .hero-card::before {{
            content:"";position:absolute;top:-40%;right:-15%;width:320px;height:320px;border-radius:50%;
            background:radial-gradient(circle,rgba(32,198,215,.16),transparent 70%);pointer-events:none;
        }}
        .hero-card h2 {{ color:#fff;font-size:1.85rem;letter-spacing:-.035em;margin:.5rem 0 .7rem;max-width:700px;font-weight:800; }}
        .hero-card p {{ color:#9db2bd;max-width:720px;line-height:1.65;font-size:.9rem; }}
        .hero-pills {{ display:flex;flex-wrap:wrap;gap:8px;margin-top:20px; }}
        .pill {{
            border:1px solid #2b5670;background:rgba(10,34,52,.85);color:#aec7d1;border-radius:999px;
            padding:6px 12px;font-size:.68rem;font-weight:600;letter-spacing:.01em;
        }}
        .score-panel {{
            background:linear-gradient(160deg,rgba(32,198,215,.16),rgba(14,33,51,.97));
            border:1px solid #2a6a80;border-radius:22px;padding:26px;min-height:225px;
            display:flex;flex-direction:column;justify-content:center;
            box-shadow:0 20px 60px rgba(0,0,0,.25), inset 0 1px 0 rgba(255,255,255,.05);
        }}
        .score-label {{ color:#93b2bf;text-transform:uppercase;letter-spacing:.13em;font-size:.65rem;font-weight:700; }}
        .score-big {{ color:#fff;font-size:4.2rem;font-weight:900;line-height:1;letter-spacing:-.07em;margin:10px 0;
            text-shadow:0 0 34px rgba(32,198,215,.35); }}
        .score-big span {{ color:#6f8b9a;font-size:1rem;letter-spacing:0;font-weight:600; }}
        .posture {{ font-weight:800;font-size:1.02rem; }}

        /* ---------- Generic metric card ---------- */
        .card {{
            background:linear-gradient(160deg,rgba(16,38,56,.92),rgba(10,25,38,.92));
            border:1px solid var(--border);border-radius:16px;padding:17px;height:100%;
            box-shadow:0 10px 28px rgba(0,0,0,.16), inset 0 1px 0 rgba(255,255,255,.025);
            transition:border-color .18s ease, transform .18s ease;
        }}
        .card:hover {{ border-color:rgba(32,198,215,.4); transform:translateY(-1px); }}
        .card-top {{ display:flex;justify-content:space-between;gap:10px;align-items:flex-start; }}
        .card-label {{ color:#8fa8b5;text-transform:uppercase;letter-spacing:.12em;font-size:.62rem;font-weight:750; }}
        .card-value {{ color:#fff;font-size:1.2rem;font-weight:800;margin-top:8px;line-height:1.25; }}
        .card-detail {{ color:#93abb7;font-size:.77rem;line-height:1.5;margin-top:8px; }}
        .dot {{ width:10px;height:10px;border-radius:50%;box-shadow:0 0 16px currentColor;flex:0 0 auto;margin-top:3px; }}

        .section-title {{
            color:#fff;font-size:1.02rem;font-weight:800;margin:28px 0 12px;letter-spacing:-.015em;
            display:flex;align-items:center;gap:9px;
        }}
        .section-title::before {{ content:"";width:4px;height:16px;border-radius:3px;
            background:linear-gradient(180deg,var(--cyan),var(--blue));display:inline-block; }}

        .record {{
            background:#050f18;border:1px solid #1c3b4e;border-radius:13px;padding:13px 14px;
            color:#b8ccd5;font-size:.72rem;line-height:1.6;overflow-wrap:anywhere;
            box-shadow:inset 0 1px 4px rgba(0,0,0,.35);
        }}

        /* ---------- Finding rows ---------- */
        .finding {{
            border:1px solid var(--border);
            background:linear-gradient(150deg,rgba(16,38,56,.85),rgba(9,24,37,.85));
            border-radius:15px;padding:15px 17px;margin-bottom:11px;
            border-left:3px solid transparent;
            transition:border-color .16s ease, transform .16s ease;
        }}
        .finding:hover {{ transform:translateX(2px); }}
        .finding-head {{ display:flex;justify-content:space-between;gap:12px;align-items:center; }}
        .finding-title {{ color:#fff;font-size:.92rem;font-weight:750; }}
        .finding-id {{ color:#7692a1;font-size:.65rem;margin-right:8px;letter-spacing:.02em; }}
        .badge {{
            display:inline-block;padding:5px 10px;border-radius:999px;font-size:.6rem;font-weight:850;
            color:#07111d;text-transform:uppercase;letter-spacing:.05em;
            box-shadow:0 0 14px -2px currentColor;
        }}
        .finding-body {{ color:#93abb7;font-size:.76rem;line-height:1.55;margin-top:8px; }}

        /* ---------- Info grid ---------- */
        .info-grid {{ display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px; }}
        .info-row {{
            border:1px solid var(--border);border-radius:13px;padding:13px;
            background:linear-gradient(160deg,rgba(13,32,48,.85),rgba(8,22,34,.85));
        }}
        .info-name {{ color:#809aaa;text-transform:uppercase;font-size:.61rem;letter-spacing:.12em;font-weight:700; }}
        .info-value {{ color:#eaf5f8;font-size:.8rem;margin-top:6px;line-height:1.55;overflow-wrap:anywhere; }}

        .empty {{
            border:1px dashed #2c5064;border-radius:18px;padding:30px;text-align:center;color:#8ba4b1;
            background:rgba(9,25,39,.5);
        }}
        .copyright {{ color:#5f7c8c;font-size:.65rem;border-top:1px solid #153046;padding-top:14px;margin-top:22px;line-height:1.5; }}

        /* ---------- Streamlit component overrides ---------- */
        div[data-testid="stForm"] {{
            border:1px solid var(--border);
            background:linear-gradient(160deg,rgba(16,38,56,.85),rgba(9,24,37,.85));
            border-radius:20px;padding:22px;
            box-shadow:0 14px 40px rgba(0,0,0,.2);
        }}
        div[data-testid="stMetric"] {{
            border:1px solid var(--border);
            background:linear-gradient(160deg,rgba(16,38,56,.85),rgba(9,24,37,.85));
            border-radius:15px;padding:14px;
        }}
        div[data-testid="stMetricValue"] {{ color:#fff; font-weight:800; }}
        div[data-testid="stExpander"] {{
            border:1px solid var(--border);background:rgba(10,26,40,.7);border-radius:14px;overflow:hidden;
        }}
        div[data-testid="stExpander"] summary {{ font-weight:650; }}

        .stTextInput input, .stTextArea textarea {{
            background:#081826 !important; border:1px solid #1e3f54 !important; color:#eef7fa !important;
            border-radius:10px !important;
        }}
        .stTextInput input:focus, .stTextArea textarea:focus {{
            border-color:var(--cyan) !important; box-shadow:0 0 0 1px var(--cyan) !important;
        }}

        .stButton button, .stDownloadButton button, div[data-testid="stFormSubmitButton"] button {{
            border-radius:11px;border:1px solid rgba(32,198,215,.45);font-weight:750;
            background:linear-gradient(160deg,rgba(20,44,62,.95),rgba(10,26,40,.95));
            color:#eef7fa; transition:all .18s ease;
        }}
        .stButton button:hover, .stDownloadButton button:hover, div[data-testid="stFormSubmitButton"] button:hover {{
            border-color:var(--cyan); box-shadow:0 0 22px -4px rgba(32,198,215,.65); transform:translateY(-1px);
        }}
        .stButton button[kind="primary"], div[data-testid="stFormSubmitButton"] button[kind="primary"] {{
            background:linear-gradient(120deg,var(--cyan),var(--blue)); border:none; color:#031019;
            box-shadow:0 8px 24px -6px rgba(32,198,215,.55);
        }}
        .stButton button[kind="primary"]:hover, div[data-testid="stFormSubmitButton"] button[kind="primary"]:hover {{
            box-shadow:0 10px 30px -4px rgba(32,198,215,.85); transform:translateY(-1px);
        }}

        .stTabs [data-baseweb="tab-list"] {{ gap:4px; border-bottom:1px solid #173247; }}
        .stTabs [data-baseweb="tab"] {{
            color:#8fa8b5; font-weight:650; border-radius:8px 8px 0 0; padding:8px 14px;
        }}
        .stTabs [aria-selected="true"] {{ color:var(--cyan) !important; }}

        @media(max-width:800px){{
            .hero-grid{{grid-template-columns:1fr}}
            .info-grid{{grid-template-columns:1fr}}
            .page-head{{display:block}}
            .scan-meta{{text-align:left;margin-top:8px}}
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def logo_html() -> str:
    return """
    <div class="nx-logo">
      <svg class="nx-mark" viewBox="0 0 60 68" aria-hidden="true">
        <path d="M30 2 L57 14 L51 49 L30 66 L9 49 L3 14 Z" fill="#20C6D7"/>
        <path d="M18 34 L27 43 L44 24" fill="none" stroke="#07111D" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <div><div class="nx-word">NEXANAR</div><div class="nx-product">Scout / External Security</div></div>
    </div>
    """


def page_header(kicker: str, title: str, description: str, result: Mapping[str, Any] | None = None) -> None:
    scan_meta = ""
    if result:
        scan_meta = f"<div class='scan-meta'>{html.escape(result['domain'])}<br/>{html.escape(result['scan_id'])}<br/>{html.escape(result['scanned_at'])}</div>"
    st.markdown(
        f"<div class='page-head'><div><div class='page-kicker'>{html.escape(kicker)}</div><h1>{html.escape(title)}</h1><p>{html.escape(description)}</p></div>{scan_meta}</div>",
        unsafe_allow_html=True,
    )


def status_card(label: str, value: str, detail: str, severity: str) -> None:
    color = SEVERITY_COLOR.get(severity, BLUE)
    st.markdown(
        f"<div class='card' style='border-left:3px solid {color}'><div class='card-top'><div><div class='card-label'>{html.escape(label)}</div><div class='card-value'>{html.escape(value)}</div></div><span class='dot' style='background:{color};color:{color}'></span></div><div class='card-detail'>{html.escape(detail)}</div></div>",
        unsafe_allow_html=True,
    )


def finding_card(item: Mapping[str, str], compact: bool = False) -> None:
    color = SEVERITY_COLOR.get(item["severity"], BLUE)
    body = html.escape(item["status"] if compact else f"{item['status']} — {item['impact']}")
    st.markdown(
        f"<div class='finding' style='border-left-color:{color}'><div class='finding-head'><div class='finding-title'><span class='finding-id'>{html.escape(item['id'])}</span>{html.escape(item['title'])}</div><span class='badge' style='background:{color}'>{html.escape(item['severity'])}</span></div><div class='finding-body'>{body}</div></div>",
        unsafe_allow_html=True,
    )


def require_result() -> Mapping[str, Any] | None:
    result = st.session_state.get("assessment")
    if not result:
        st.markdown("<div class='empty'><b>No assessment loaded.</b><br/>Open New Assessment and run a scan to populate this section.</div>", unsafe_allow_html=True)
        if st.button("Open New Assessment", use_container_width=True):
            st.session_state.navigation = "New Assessment"
            st.rerun()
        return None
    return result


def severity_counts(result: Mapping[str, Any]) -> dict[str, int]:
    counts = {key: 0 for key in SEVERITY_ORDER}
    for item in result["findings"]:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
    return counts


def render_overview() -> None:
    result = st.session_state.get("assessment")
    page_header("Security intelligence dashboard", "External risk at a glance", "Review email-spoofing controls, public exposure signals, and prioritized remediation from one navigable workspace.", result)

    if not result:
        st.markdown(
            """
            <div class="hero-grid">
              <div class="hero-card"><div class="page-kicker">Passive B2B security assessment</div><h2>Assess whether attackers can impersonate a company domain.</h2><p>Nexanar Scout evaluates SPF and DMARC enforcement, mail-routing posture, transport controls, DNS exposure, HTTPS hardening, certificate-transparency hostnames, public corporate email addresses, and optional raw-header evidence.</p><div class="hero-pills"><span class="pill">Read-only checks</span><span class="pill">No database</span><span class="pill">In-memory report</span><span class="pill">Executive PDF</span></div></div>
              <div class="score-panel"><div class="score-label">Assessment status</div><div class="score-big">—<span>/100</span></div><div class="posture" style="color:#90A8B7">No scan completed</div><p class="card-detail">Run a new assessment to populate the dashboard.</p></div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Start a new assessment", type="primary", use_container_width=True):
            st.session_state.navigation = "New Assessment"
            st.rerun()
        return

    counts = severity_counts(result)
    st.markdown(
        f"""
        <div class="hero-grid">
          <div class="hero-card"><div class="page-kicker">Assessment completed</div><h2>{html.escape(result['domain'])} external security posture</h2><p>{html.escape(result['summary'])}</p><div class="hero-pills"><span class="pill">{counts['Critical']} critical</span><span class="pill">{counts['High']} high</span><span class="pill">{len(result['osint'].get('subdomains', []))} hostnames</span><span class="pill">{len(result['web_surface'].get('public_emails', []))} public emails</span></div></div>
          <div class="score-panel"><div class="score-label">Composite external score</div><div class="score-big">{result['score']}<span>/100</span></div><div class="posture" style="color:{result['posture_color']}">{html.escape(result['posture'])} posture</div><p class="card-detail">Email-specific score: {result['email_score']}/100 · Spoofing exposure: {html.escape(result['email']['exposure'])}</p></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    email = result["email"]
    cols = st.columns(4)
    with cols[0]:
        ev = email["evaluations"]["dmarc"]
        sev = "Critical" if ev["state"] == "critical" else "Medium" if ev["state"] == "warning" else "Passed"
        status_card("DMARC", ev["label"], ev["detail"], sev)
    with cols[1]:
        ev = email["evaluations"]["spf"]
        sev = "High" if ev["state"] == "critical" else "Medium" if ev["state"] == "warning" else "Passed"
        status_card("SPF", ev["label"], ev["detail"], sev)
    with cols[2]:
        mta = result["dns_surface"]["mta_sts"]
        status_card("MTA-STS", "Published" if mta["present"] else "Not detected", "SMTP transport policy visibility.", "Passed" if mta["present"] else "Medium")
    with cols[3]:
        status_card("HTTPS", "Reachable" if result["web_surface"]["reachable"] else "Unavailable", safe(result["web_surface"].get("final_url"), safe(result["web_surface"].get("error"))), "Passed" if result["web_surface"]["reachable"] else "Informational")

    st.markdown("<div class='section-title'>Priority findings</div>", unsafe_allow_html=True)
    actionable = [item for item in result["findings"] if item["severity"] in {"Critical", "High", "Medium"}]
    for item in actionable[:6]:
        finding_card(item, compact=True)
    if not actionable:
        st.success("No critical, high, or medium findings were generated by the passive checks.")


def render_new_assessment() -> None:
    result = st.session_state.get("assessment")
    page_header("Assessment workflow", "Run a new passive scan", "Enter a corporate domain and select the external checks to perform. Results remain in session state while you navigate and export the report.", result)

    with st.form("full_assessment_form", clear_on_submit=False):
        domain_value = result["domain"] if result else st.session_state.get("last_domain", "")
        domain_input = st.text_input("Corporate domain", value=domain_value, placeholder="company.de", help="A URL or email address is normalized to its registrable-looking hostname format.")
        raw_headers = st.text_area("Raw email headers (optional)", height=160, placeholder="Paste Authentication-Results, Received-SPF, From, Return-Path, and related header lines...")
        col1, col2 = st.columns(2)
        with col1:
            include_web = st.checkbox("Inspect HTTPS headers and public contact exposure", value=True)
        with col2:
            include_ct = st.checkbox("Discover certificate-transparency hostnames", value=True)
        consent = st.checkbox("I confirm this is a passive assessment of a domain I am authorized to review.", value=False)
        submitted = st.form_submit_button("Run complete assessment", type="primary", use_container_width=True)

    if submitted:
        if not consent:
            st.error("Confirm authorization before running the assessment.")
            return
        try:
            domain = normalize_domain(domain_input)
            progress = st.progress(0, text="Preparing assessment...")
            progress.progress(15, text="Checking SPF, DMARC, MX, and email-header evidence...")
            # The core routine and optional modules run as one bounded passive workflow.
            progress.progress(35, text="Checking DNS transport and brand-protection controls...")
            progress.progress(55, text="Inspecting public HTTPS signals...")
            progress.progress(72, text="Querying certificate-transparency data...")
            result = run_full_assessment(domain, raw_headers, include_web, include_ct)
            progress.progress(88, text="Building findings and executive report...")
            pdf_bytes = create_executive_pdf(result)
            progress.progress(100, text="Assessment complete")
            st.session_state.assessment = result
            st.session_state.pdf_bytes = pdf_bytes
            st.session_state.last_domain = domain
            st.session_state.navigation = "Overview"
            st.success(f"Assessment completed for {domain}.")
            st.rerun()
        except ValueError as exc:
            st.error(str(exc))
        except Exception as exc:
            st.error(f"The assessment could not be completed: {exc}")

    st.markdown("<div class='section-title'>Included modules</div>", unsafe_allow_html=True)
    cols = st.columns(3)
    module_data = [
        ("Email authentication", "SPF, DMARC, MX, optional SPF/DKIM/DMARC header outcomes."),
        ("Transport & DNS", "MTA-STS, TLS-RPT, BIMI, DNSSEC publication, CAA, NS, A and AAAA."),
        ("Exposure discovery", "Certificate-transparency hostnames, public same-domain emails, PGP/WKD signals, HTTPS headers."),
    ]
    for column, (title, detail) in zip(cols, module_data):
        with column:
            status_card(title, "Enabled", detail, "Passed")


def render_email_security() -> None:
    result = require_result()
    if not result:
        return
    page_header("Email security", "Spoofing and mail-control analysis", "Review enforcement policies, raw DNS evidence, mail routing, and any authentication outcomes extracted from supplied message headers.", result)
    email = result["email"]

    cols = st.columns(4)
    metrics = [
        ("Spoofing exposure", email["exposure"], "Based primarily on DMARC enforcement.", "Critical" if email["exposure"] == "High" else "Medium" if email["exposure"] == "Medium" else "Passed"),
        ("DMARC policy", safe(email["dmarc"].get("policy")).upper(), email["evaluations"]["dmarc"]["label"], "Critical" if email["evaluations"]["dmarc"]["state"] == "critical" else "Medium" if email["evaluations"]["dmarc"]["state"] == "warning" else "Passed"),
        ("SPF policy", email["evaluations"]["spf"]["label"], f"DNS lookups: {safe(email['spf'].get('dns_lookups'), 'Not available')}", "High" if email["evaluations"]["spf"]["state"] == "critical" else "Medium" if email["evaluations"]["spf"]["state"] == "warning" else "Passed"),
        ("Mail routing", email["evaluations"]["mx"]["label"], email["evaluations"]["mx"]["detail"], "High" if email["evaluations"]["mx"]["state"] == "critical" else "Passed"),
    ]
    for column, metric in zip(cols, metrics):
        with column:
            status_card(*metric)

    st.markdown("<div class='section-title'>Published policy records</div>", unsafe_allow_html=True)
    left, right = st.columns(2, gap="large")
    with left:
        st.markdown("**DMARC**")
        st.markdown(f"<div class='record'>{html.escape(safe(email['dmarc'].get('record'), safe(email['dmarc'].get('error'))))}</div>", unsafe_allow_html=True)
        st.caption(f"Policy: {safe(email['dmarc'].get('policy'))} · Subdomain: {safe(email['dmarc'].get('subdomain_policy'))} · pct: {safe(email['dmarc'].get('pct'), '100')}%")
    with right:
        st.markdown("**SPF**")
        st.markdown(f"<div class='record'>{html.escape(safe(email['spf'].get('record'), safe(email['spf'].get('error'))))}</div>", unsafe_allow_html=True)
        st.caption("A restrictive terminal mechanism and valid lookup count are important for reliable authorization.")

    st.markdown("<div class='section-title'>Mail exchangers</div>", unsafe_allow_html=True)
    mx_hosts = email["mx"].get("hosts") or []
    if mx_hosts:
        rows = []
        for item in mx_hosts:
            if isinstance(item, Mapping):
                rows.append({"Preference": item.get("preference", item.get("preference", "—")), "Hostname": item.get("hostname", item.get("host", safe(item)))})
            else:
                rows.append({"Preference": "—", "Hostname": safe(item)})
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.info(safe(email["mx"].get("error"), "No MX results were returned."))

    header = email["header_analysis"]
    st.markdown("<div class='section-title'>Message-header evidence</div>", unsafe_allow_html=True)
    if header.get("provided"):
        cols = st.columns(3)
        for column, mechanism in zip(cols, ("spf", "dkim", "dmarc")):
            status = header["statuses"].get(mechanism, "not-found")
            sev = "Passed" if status == "pass" else "High" if status in {"fail", "permerror"} else "Informational"
            with column:
                status_card(mechanism.upper(), status.upper(), "Reported by the receiving mail system.", sev)
        with st.expander("Header identity details", expanded=True):
            st.write(f"**From domain:** {safe(header.get('from_domain'))}")
            st.write(f"**Return-Path domain:** {safe(header.get('return_path_domain'))}")
            st.write(f"**Message-ID:** {safe(header.get('message_id'))}")
            for value in header.get("authentication_results", []):
                st.code(value, language=None)
            st.caption(header.get("note", ""))
    else:
        st.info("No raw headers were supplied. DKIM cannot be conclusively assessed from the domain alone without known selectors.")


def render_exposure_discovery() -> None:
    result = require_result()
    if not result:
        return
    page_header("Passive OSINT", "Exposure discovery", "Review hostnames, public corporate contacts, DNS infrastructure, transport controls, and public PGP/WKD signals discovered without authentication.", result)

    tab1, tab2, tab3, tab4 = st.tabs(["Subdomains", "Public emails", "Infrastructure", "PGP / WKD"])
    with tab1:
        subdomains = result["osint"].get("subdomains", [])
        cols = st.columns(3)
        with cols[0]: st.metric("Discovered", len(subdomains))
        with cols[1]: st.metric("Source", "Certificate transparency")
        with cols[2]: st.metric("Truncated", "Yes" if result["osint"].get("truncated") else "No")
        if subdomains:
            st.dataframe([{"Hostname": item, "Depth": item.count(".") - result["domain"].count(".")} for item in subdomains], use_container_width=True, hide_index=True)
        else:
            st.info(safe(result["osint"].get("error"), "No certificate-transparency hostnames were returned."))
    with tab2:
        emails = result["web_surface"].get("public_emails", [])
        st.caption("Addresses are extracted only from the assessed public landing page and are not sourced from private datasets.")
        if emails:
            st.dataframe([{"Public corporate email": item, "Domain": item.split("@", 1)[-1]} for item in emails], use_container_width=True, hide_index=True)
        else:
            st.info("No same-domain email address was extracted from the public landing page, or web checks were unavailable.")
    with tab3:
        dns_surface = result["dns_surface"]
        info = {
            "IPv4": ", ".join(dns_surface["addresses"]["ipv4"]) or "Not resolved",
            "IPv6": ", ".join(dns_surface["addresses"]["ipv6"]) or "Not resolved",
            "Nameservers": ", ".join(dns_surface["nameservers"]["records"]) or safe(dns_surface["nameservers"].get("error")),
            "CAA": "; ".join(dns_surface["caa"]["records"]) or "Not detected",
            "DNSSEC": "DNSKEY published" if dns_surface["dnssec"]["published"] else "DNSKEY not detected",
            "MTA-STS": "; ".join(dns_surface["mta_sts"]["records"]) or "Not detected",
            "TLS-RPT": "; ".join(dns_surface["tls_rpt"]["records"]) or "Not detected",
            "BIMI": "; ".join(dns_surface["bimi"]["records"]) or "Not detected",
        }
        st.markdown("<div class='info-grid'>" + "".join(f"<div class='info-row'><div class='info-name'>{html.escape(key)}</div><div class='info-value'>{html.escape(value)}</div></div>" for key, value in info.items()) + "</div>", unsafe_allow_html=True)

        st.markdown("<div class='section-title'>HTTPS response headers</div>", unsafe_allow_html=True)
        web = result["web_surface"]
        if web["reachable"]:
            rows = [{"Header": key, "Value": safe(value, "Not detected")} for key, value in web["headers"].items()]
            st.dataframe(rows, use_container_width=True, hide_index=True)
            st.caption(f"Final URL: {safe(web.get('final_url'))} · HTTP status: {safe(web.get('status'))}")
        else:
            st.info(safe(web.get("error"), "HTTPS checks were unavailable."))
    with tab4:
        web = result["web_surface"]
        cols = st.columns(2)
        with cols[0]:
            status_card("WKD policy", "Detected" if web.get("wkd_detected") else "Not detected", safe(web.get("wkd_url"), "A policy endpoint was not discovered."), "Passed" if web.get("wkd_detected") else "Informational")
        with cols[1]:
            status_card("Public PGP links", str(len(web.get("pgp_links", []))), "PGP key or fingerprint links extracted from the landing page.", "Informational")
        for link in web.get("pgp_links", []):
            st.code(link, language=None)
        st.caption("A domain-wide scan cannot prove that no PGP key exists; key discovery normally requires a known mailbox or selector.")


def render_findings() -> None:
    result = require_result()
    if not result:
        return
    page_header("Risk register", "Detailed findings", "Filter the generated findings by severity, then review evidence, impact, and remediation guidance for each passive signal.", result)
    counts = severity_counts(result)
    cols = st.columns(5)
    for column, severity in zip(cols, ("Critical", "High", "Medium", "Low", "Informational")):
        with column:
            st.metric(severity, counts[severity])

    selection = st.multiselect("Severity filter", options=["Critical", "High", "Medium", "Low", "Informational", "Passed"], default=["Critical", "High", "Medium", "Low", "Informational"])
    filtered = [item for item in result["findings"] if item["severity"] in selection]
    for item in filtered:
        color = SEVERITY_COLOR[item["severity"]]
        with st.expander(f"{item['id']} · {item['severity']} · {item['title']}", expanded=item["severity"] in {"Critical", "High"}):
            st.markdown(f"<span class='badge' style='background:{color}'>{html.escape(item['severity'])}</span>", unsafe_allow_html=True)
            st.write(f"**Category:** {item['category']}")
            st.write(f"**Status:** {item['status']}")
            st.write("**Evidence**")
            st.code(item["evidence"], language=None)
            st.write(f"**Impact:** {item['impact']}")
            st.write(f"**Recommended remediation:** {item['remediation']}")
    if not filtered:
        st.info("No findings match the selected severities.")


def render_executive_report() -> None:
    result = require_result()
    if not result:
        return
    page_header("Deliverables", "Executive report and exports", "Download the branded PDF brief, a structured JSON evidence package, or a CSV remediation register without clearing the current assessment.", result)
    counts = severity_counts(result)
    cols = st.columns(4)
    with cols[0]: status_card("External score", f"{result['score']}/100", f"{result['posture']} posture", "Critical" if result["score"] < 40 else "Medium" if result["score"] < 65 else "Passed")
    with cols[1]: status_card("Email score", f"{result['email_score']}/100", f"Spoofing exposure: {result['email']['exposure']}", "Critical" if result["email"]["exposure"] == "High" else "Medium" if result["email"]["exposure"] == "Medium" else "Passed")
    with cols[2]: status_card("Actionable findings", str(counts["Critical"] + counts["High"] + counts["Medium"]), "Critical, high, and medium priorities.", "Critical" if counts["Critical"] else "High" if counts["High"] else "Medium" if counts["Medium"] else "Passed")
    with cols[3]: status_card("Evidence modules", "5", "Email, DNS, transport, HTTPS, and OSINT.", "Passed")

    st.markdown("<div class='section-title'>Download files</div>", unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    with c1:
        st.download_button("Download executive PDF", data=st.session_state["pdf_bytes"], file_name=f"Nexanar_Scout_{result['domain'].replace('.', '_')}.pdf", mime="application/pdf", use_container_width=True, type="primary")
    with c2:
        st.download_button("Download findings CSV", data=findings_csv(result), file_name=f"Nexanar_Scout_Findings_{result['domain'].replace('.', '_')}.csv", mime="text/csv", use_container_width=True)
    with c3:
        st.download_button("Download evidence JSON", data=json.dumps(result, ensure_ascii=False, indent=2, default=str).encode("utf-8"), file_name=f"Nexanar_Scout_Evidence_{result['domain'].replace('.', '_')}.json", mime="application/json", use_container_width=True)

    st.markdown("<div class='section-title'>Report contents</div>", unsafe_allow_html=True)
    st.markdown("""
    <div class="info-grid">
      <div class="info-row"><div class="info-name">Page 1</div><div class="info-value">Executive scorecard, control summary, and issue counts.</div></div>
      <div class="info-row"><div class="info-name">Page 2+</div><div class="info-value">Prioritized findings with evidence and remediation.</div></div>
      <div class="info-row"><div class="info-name">Technical evidence</div><div class="info-value">SPF, DMARC, MX, MTA-STS, TLS-RPT, DNS infrastructure, HTTPS and OSINT signals.</div></div>
      <div class="info-row"><div class="info-name">Limitations</div><div class="info-value">Clear passive-scan scope, non-penetration-test statement, and evidence constraints.</div></div>
    </div>
    """, unsafe_allow_html=True)


def render_methodology() -> None:
    page_header("Transparency", "Methodology and limitations", "Understand exactly what the application checks, what it does not check, and how to interpret the score and discovered exposure signals.", st.session_state.get("assessment"))
    sections = [
        ("Email authentication", "Uses checkdmarc and dnspython-compatible DNS resolution to evaluate SPF, DMARC, MX, policy validity, enforcement mode, and relevant warnings. Optional raw headers are parsed for receiver-reported SPF, DKIM, and DMARC outcomes."),
        ("Transport and DNS", "Checks for public MTA-STS, TLS-RPT, BIMI, CAA, nameserver, address, and DNSKEY publication signals. DNSKEY publication is not the same as full DNSSEC chain validation."),
        ("Exposure discovery", "Queries public certificate-transparency data for hostnames and inspects the public HTTPS landing page for same-domain email addresses, PGP links, WKD policy endpoints, and selected browser-security headers."),
        ("No active exploitation", "The app does not authenticate, brute force, send email, enumerate private data, exploit vulnerabilities, change DNS, or bypass access controls."),
        ("Score interpretation", "The score is a prioritization aid. DMARC carries the highest weighting because it directly controls visible From-domain enforcement. Missing transport, DNS, and web controls apply smaller deductions."),
        ("Data handling", "Assessment data is retained only in Streamlit session state. PDF, CSV, and JSON outputs are built in memory. No application database is required."),
    ]
    for title, body in sections:
        with st.expander(title, expanded=True):
            st.write(body)
    st.warning("Only assess domains you own or are explicitly authorized to review. Public data can still contain business-sensitive information and should be handled appropriately.")


def initialize_state() -> None:
    defaults = {"assessment": None, "pdf_bytes": None, "last_domain": "", "navigation": "Overview"}
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def render_sidebar() -> str:
    st.sidebar.markdown(logo_html(), unsafe_allow_html=True)
    result = st.session_state.get("assessment")
    if result:
        st.sidebar.markdown(
            f"<div class='sidebar-status'><div class='sidebar-kicker'>Active assessment</div><div class='sidebar-domain'>{html.escape(result['domain'])}</div><div class='sidebar-score'>{result['score']}/100</div><div class='card-detail'>{html.escape(result['posture'])} external posture</div></div>",
            unsafe_allow_html=True,
        )
    else:
        st.sidebar.markdown("<div class='sidebar-status'><div class='sidebar-kicker'>Workspace status</div><div class='sidebar-domain'>No active assessment</div><div class='card-detail'>Run a scan to populate all modules.</div></div>", unsafe_allow_html=True)

    current = st.session_state.get("navigation", "Overview")
    if current not in NAV_ITEMS:
        current = "Overview"

    with st.sidebar:
        selected = option_menu(
            menu_title=None,
            options=NAV_ITEMS,
            icons=[NAV_ICONS[item] for item in NAV_ITEMS],
            menu_icon="cast",
            default_index=NAV_ITEMS.index(current),
            styles={
                "container": {
                    "padding": "0",
                    "margin": "4px 0 18px",
                    "background-color": "transparent",
                },
                "icon": {
                    "color": "#7fa1ae",
                    "font-size": "15px",
                },
                "nav-link": {
                    "font-family": "'Inter',sans-serif",
                    "font-size": "0.85rem",
                    "font-weight": "600",
                    "color": "#b7cbd6",
                    "text-align": "left",
                    "margin": "0 0 3px",
                    "padding": "10px 12px",
                    "border-radius": "10px",
                    "border": "1px solid transparent",
                    "background-color": "transparent",
                    "--hover-color": "#0e2233",
                },
                "nav-link:hover": {
                    "background-color": "rgba(0,255,102,0.08)",
                    "border": f"1px solid {NAV_ACCENT}40",
                    "color": "#eef7fa",
                },
                "nav-link-selected": {
                    "background-color": "rgba(0,255,102,0.12)",
                    "border": f"1px solid {NAV_ACCENT}",
                    "color": "#ffffff",
                    "font-weight": "750",
                    "box-shadow": f"0 0 16px -3px {NAV_ACCENT}80",
                },
                "nav-link-selected .icon": {
                    "color": NAV_ACCENT,
                },
                "icon-selected": {
                    "color": NAV_ACCENT,
                },
            },
        )
    st.session_state.navigation = selected

    if result:
        if st.sidebar.button("Run another assessment", use_container_width=True):
            st.session_state.navigation = "New Assessment"
            st.rerun()
        if st.sidebar.button("Clear current results", use_container_width=True):
            st.session_state.assessment = None
            st.session_state.pdf_bytes = None
            st.session_state.navigation = "Overview"
            st.rerun()

    st.sidebar.markdown(f"<div class='copyright'>{COPYRIGHT}<br/>v{APP_VERSION} · Passive external assessment</div>", unsafe_allow_html=True)
    return selected


def main() -> None:
    st.set_page_config(page_title=f"{APP_NAME} | External Security Dashboard", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
    inject_css()
    initialize_state()
    page = render_sidebar()

    renderers = {
        "Overview": render_overview,
        "New Assessment": render_new_assessment,
        "Email Security": render_email_security,
        "Exposure Discovery": render_exposure_discovery,
        "Findings": render_findings,
        "Executive Report": render_executive_report,
        "Methodology": render_methodology,
    }
    renderers[page]()


if __name__ == "__main__":
    main()