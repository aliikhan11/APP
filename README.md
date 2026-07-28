# Nexanar Scout v2 — Streamlit External Security Dashboard

Nexanar Scout is a passive B2B security-assessment application built with Streamlit. It combines email-spoofing controls with public DNS, HTTPS, certificate-transparency, and OSINT signals, then produces executive and technical exports entirely in memory.

## Interface and navigation

The application uses a persistent sidebar and separate workspace sections:

- Overview
- New Assessment
- Email Security
- Exposure Discovery
- Findings
- Executive Report
- Methodology

Results remain available in `st.session_state` while moving between sections or downloading files.

## Assessment modules

### Email security

- SPF discovery, parsing, and policy classification
- DMARC discovery, validation, enforcement mode, subdomain policy, and coverage
- MX discovery
- Optional parsing of receiver-reported SPF, DKIM, and DMARC outcomes from raw headers
- Spoofing-exposure and email-security scoring

### Transport and DNS

- MTA-STS TXT discovery
- TLS-RPT TXT discovery
- BIMI TXT discovery
- DNSKEY publication signal
- CAA records
- Authoritative nameservers
- IPv4 and IPv6 addresses

### Passive exposure discovery

- Certificate-transparency hostname enumeration through `crt.sh`
- Public same-domain email extraction from the assessed landing page
- Public PGP link and Web Key Directory policy signals
- HTTPS reachability and selected browser-security response headers

The CT and web checks require outbound HTTPS access from the machine or Streamlit deployment.

## Deliverables generated in memory

- Branded multi-page ReportLab executive PDF
- Findings and remediation CSV
- Structured JSON evidence package

No application database is required.

## Local setup in VS Code on Windows

Use Python 3.10–3.12.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m streamlit run app.py
```

Open `http://localhost:8501` when the browser does not open automatically.

## Streamlit Community Cloud

1. Upload `app.py`, `core.py`, `requirements.txt`, and `.streamlit/config.toml` to a GitHub repository.
2. Create a new Streamlit Community Cloud app.
3. Select `app.py` as the entry point.
4. Deploy. No database or mandatory secrets are required.

## Branding placeholders

Update these constants near the top of `app.py` when final client details are available:

- `BRAND_NAME`
- `CONTACT_EMAIL`
- `WEBSITE`
- `COPYRIGHT`
- Theme color constants

The current shield is inline SVG/CSS and does not require an image file.

## File roles

- `app.py`: v2 navigation, expanded passive modules, findings, and enhanced exports
- `core.py`: tested SPF/DMARC/MX, header-analysis, risk-model, and original PDF utilities
- `test_core.py`: dependency-light regression tests for critical parsing and classification logic

## Scope and authorization

This is a read-only external posture assessment. It does not authenticate, brute force, exploit vulnerabilities, send email, modify DNS, or bypass access controls. Certificate-transparency and website results are public-data signals and may not represent a complete asset inventory. DKIM cannot be exhaustively assessed from a domain alone without known selectors.

Only assess domains you own or are explicitly authorized to review.

© 2026 Nexanar Deutschland. All rights reserved.
