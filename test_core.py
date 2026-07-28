"""Small dependency-light smoke tests for core input/header/risk helpers."""

import importlib.util
import pathlib
import sys
import types

# Streamlit is only needed by the UI. A stub lets core helpers be imported in lean CI.
sys.modules.setdefault("streamlit", types.ModuleType("streamlit"))

APP_PATH = pathlib.Path(__file__).with_name("app.py")
spec = importlib.util.spec_from_file_location("cyber_scout_app", APP_PATH)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


def test_domain_normalization():
    assert module.normalize_domain("https://www.Example.com/path") == "example.com"
    assert module.normalize_domain("user@example.com") == "example.com"


def test_header_parsing():
    raw = """From: Finance <finance@example.com>
Return-Path: <bounce@mail.example.com>
Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=mail.example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com
Message-ID: <abc@example.com>
"""
    result = module.analyze_headers(raw)
    assert result["provided"] is True
    assert result["statuses"] == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert result["from_domain"] == "example.com"


def test_dmarc_classification():
    assert module.evaluate_dmarc({"valid": True, "record": "v=DMARC1; p=none", "policy": "none", "pct": "100"})["state"] == "critical"
    assert module.evaluate_dmarc({"valid": True, "record": "v=DMARC1; p=reject", "policy": "reject", "pct": "100"})["state"] == "secure"


def test_spf_classification():
    assert module.evaluate_spf({"valid": True, "record": "v=spf1 include:_spf.example.com -all"})["state"] == "secure"
    assert module.evaluate_spf({"valid": True, "record": "v=spf1 +all"})["state"] == "critical"
