# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import pytest

from security.url_validator import is_ssrf_target, validate_llm_base_url


# ── is_ssrf_target ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "http://127.0.0.1:11434",
    "http://127.0.0.5:8000",
    "http://10.0.0.1",
    "http://10.255.255.255",
    "http://172.16.0.1",
    "http://172.31.255.254",
    "http://192.168.1.1",
    "http://169.254.169.254",       # AWS/GCP metadata endpoint
    "http://169.254.169.254/latest/meta-data/",
    "http://0.0.0.0",
    "http://localhost",
    "http://localhost:11434",
    "http://metadata.google.internal",
    "http://metadata.goog",
    "http://[::1]",
    "http://[fe80::1]",
    "http://[fc00::1]",
])
def test_ssrf_target_rejects_private_and_metadata(url):
    assert is_ssrf_target(url) is True


@pytest.mark.parametrize("url", [
    "https://api.openai.com",
    "https://api.openai.com/v1",
    "http://ollama:11434",             # Docker service name, allowed
    "http://api.example.com:8000",
    "https://api.groq.com/openai/v1",
    "https://8.8.8.8",                 # public IP
    "http://172.15.0.1",               # just outside 172.16/12
    "http://172.32.0.1",               # just outside 172.16/12 (upper)
    "http://11.0.0.1",                 # just outside 10/8
])
def test_ssrf_target_allows_public(url):
    assert is_ssrf_target(url) is False


def test_ssrf_target_case_insensitive_hostname():
    assert is_ssrf_target("http://LOCALHOST:8000") is True
    assert is_ssrf_target("http://LocalHost") is True


# ── validate_llm_base_url ──────────────────────────────────────────────────────

def test_validate_strips_trailing_slash():
    assert validate_llm_base_url("https://api.openai.com/v1/") == "https://api.openai.com/v1"


def test_validate_returns_url_unchanged_when_no_slash():
    assert validate_llm_base_url("https://api.openai.com/v1") == "https://api.openai.com/v1"


def test_validate_rejects_missing_scheme():
    with pytest.raises(ValueError, match="http:// or https://"):
        validate_llm_base_url("api.openai.com")


def test_validate_rejects_ftp_scheme():
    with pytest.raises(ValueError, match="http:// or https://"):
        validate_llm_base_url("ftp://api.openai.com")


def test_validate_rejects_file_scheme():
    with pytest.raises(ValueError, match="http:// or https://"):
        validate_llm_base_url("file:///etc/passwd")


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:11434",
    "http://localhost",
    "http://169.254.169.254",
    "http://10.0.0.1",
    "http://192.168.1.1",
    "http://[::1]",
    "http://metadata.google.internal",
])
def test_validate_rejects_ssrf_targets(url):
    with pytest.raises(ValueError, match="private or internal"):
        validate_llm_base_url(url)


def test_validate_accepts_public_https():
    assert validate_llm_base_url("https://api.openai.com/v1") == "https://api.openai.com/v1"


def test_validate_accepts_docker_service_name():
    # "ollama" is not a valid IP so hostname is allowed through -- required for
    # docker-compose deployments where the LLM runs on a service alias.
    assert validate_llm_base_url("http://ollama:11434") == "http://ollama:11434"
