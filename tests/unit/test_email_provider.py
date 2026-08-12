# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Unit tests for the email provider boundary (v1.8.3, Phase B).

Covers the MIME builder, the in-memory fake provider, SMTP error
classification, provider selection, and the settings validation that keeps a
half-configured relay from booting while never requiring email at all.
"""

from __future__ import annotations

import pytest

from services.email.factory import email_from_address, get_email_provider
from services.email.fake_provider import FakeEmailProvider
from services.email.provider import (
    OutgoingEmail,
    PermanentEmailError,
    TransientEmailError,
    build_mime,
)
from services.email.smtp_provider import SMTPProvider, _classify_by_code


def _msg(**over) -> OutgoingEmail:
    base = {
        "to_addr": "user@example.com",
        "subject": "Your password was changed",
        "text_body": "Hello, your password was changed.",
        "html_body": "<p>Hello, your password was changed.</p>",
        "from_addr": "no-reply@wrapsec.com",
        "from_name": "WrapSec",
    }
    base.update(over)
    return OutgoingEmail(**base)


# -- build_mime ------------------------------------------------------
def test_build_mime_multipart_when_html_present():
    mime = build_mime(_msg())
    assert mime.get_content_type() == "multipart/alternative"
    parts = [p.get_content_type() for p in mime.iter_parts()]
    assert "text/plain" in parts and "text/html" in parts


def test_build_mime_plain_only_when_no_html():
    mime = build_mime(_msg(html_body=None))
    assert mime.get_content_type() == "text/plain"


def test_build_mime_sets_core_headers_and_display_name():
    mime = build_mime(_msg())
    assert mime["To"] == "user@example.com"
    assert mime["Subject"] == "Your password was changed"
    assert "WrapSec" in str(mime["From"])
    assert "no-reply@wrapsec.com" in str(mime["From"])


def test_build_mime_generates_message_id_when_absent():
    mime = build_mime(_msg())
    assert mime["Message-ID"] and str(mime["Message-ID"]).startswith("<")


def test_build_mime_preserves_supplied_message_id():
    mime = build_mime(_msg(message_id="<fixed@wrapsec>"))
    assert str(mime["Message-ID"]) == "<fixed@wrapsec>"


def test_build_mime_extra_headers_cannot_override_core():
    mime = build_mime(_msg(headers={"To": "attacker@evil.com", "Auto-Submitted": "auto-generated"}))
    # The core To header is untouched; the benign extra header is applied once.
    assert mime["To"] == "user@example.com"
    assert mime["Auto-Submitted"] == "auto-generated"


# -- FakeEmailProvider ----------------------------------------------
async def test_fake_provider_records_sent():
    provider = FakeEmailProvider()
    mid = await provider.send(_msg())
    assert mid
    assert len(provider.sent) == 1
    assert provider.sent[0].to_addr == "user@example.com"


async def test_fake_provider_injects_transient_then_clears():
    provider = FakeEmailProvider()
    provider.fail_next = "transient"
    with pytest.raises(TransientEmailError):
        await provider.send(_msg())
    # One-shot: the next send succeeds.
    await provider.send(_msg())
    assert len(provider.sent) == 1


async def test_fake_provider_injects_permanent():
    provider = FakeEmailProvider()
    provider.fail_next = "permanent"
    with pytest.raises(PermanentEmailError):
        await provider.send(_msg())


# -- SMTP classification --------------------------------------------
def test_classify_transient_for_4xx_and_unknown():
    assert isinstance(_classify_by_code(450, "x"), TransientEmailError)
    assert isinstance(_classify_by_code(421, "x"), TransientEmailError)
    assert isinstance(_classify_by_code(None, "x"), TransientEmailError)


def test_classify_permanent_for_5xx():
    assert isinstance(_classify_by_code(550, "x"), PermanentEmailError)
    assert isinstance(_classify_by_code(554, "x"), PermanentEmailError)


def test_smtp_provider_rejects_both_tls_modes():
    with pytest.raises(ValueError):
        SMTPProvider(
            host="mail", port=587, username=None, password=None,
            use_tls=True, start_tls=True, timeout=15,
        )


# -- provider selection ---------------------------------------------
def _settings(**over):
    from config.settings import get_settings

    s = get_settings()
    # get_settings is lru_cached; build a shallow copy we can mutate freely.
    data = s.model_dump()
    data.update(over)
    from config.settings import Settings

    return Settings(**data)


def test_factory_returns_none_in_production_without_smtp():
    provider = get_email_provider(_settings(smtp_host=None, environment="production"))
    assert provider is None


def test_factory_returns_fake_in_dev_without_smtp():
    provider = get_email_provider(_settings(smtp_host=None, environment="development"))
    assert isinstance(provider, FakeEmailProvider)


def test_factory_returns_smtp_when_host_set():
    provider = get_email_provider(
        _settings(smtp_host="mail.example.com", smtp_from="no-reply@example.com", environment="production")
    )
    assert isinstance(provider, SMTPProvider)


def test_email_from_address_uses_settings():
    addr, name = email_from_address(_settings(smtp_from="alerts@example.com", smtp_from_name="WrapSec Security"))
    assert addr == "alerts@example.com"
    assert name == "WrapSec Security"


# -- settings validation (email is optional but must be coherent) ----
def test_validate_email_config_noop_without_host(monkeypatch):
    monkeypatch.setenv("TESTING", "false")
    _settings(smtp_host=None).validate_email_config()  # must not raise


def test_validate_email_config_requires_from_when_host_set(monkeypatch):
    monkeypatch.setenv("TESTING", "false")
    with pytest.raises(ValueError):
        _settings(smtp_host="mail", smtp_from=None).validate_email_config()


def test_validate_email_config_rejects_both_tls_modes(monkeypatch):
    monkeypatch.setenv("TESTING", "false")
    with pytest.raises(ValueError):
        _settings(
            smtp_host="mail", smtp_from="a@b.com", smtp_use_tls=True, smtp_start_tls=True
        ).validate_email_config()
