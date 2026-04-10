"""
leaky_app.py — intentionally vulnerable sample for SentinelAI's secret scanner.

DO NOT DEPLOY. All credentials below are fabricated and exist only to exercise
detection rules (TruffleHog / Gitleaks / detect-secrets style patterns).

NOTE: This file deliberately avoids Stripe `sk_live_*` / `sk_test_*` patterns
because GitHub Push Protection blocks them via Stripe's issuer-verifier API.
Other vendor formats below pass push protection but still match scanner regex.
"""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

import boto3  # type: ignore
import requests  # type: ignore


# ─── Cloud provider keys ──────────────────────────────────────────────────────
# AWS docs-example values — push-protection-safe but match AKIA / 40-char regex
AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_SESSION_TOKEN     = "FwoGZXIvYXdzEJrFAKEEXAMPLESESSIONTOKENVALUEDONOTUSEINPROD=="

GCP_SERVICE_ACCOUNT_JSON = {
    "type": "service_account",
    "project_id": "leaky-demo-42",
    "private_key_id": "9c1f8d4b2e6a47f0b3d5a8c2e9f0b1d4a6c8e0f2",
    "private_key": (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n"
        "MzEfYyjiWA4R4FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK\n"
        "FAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEY=\n"
        "-----END PRIVATE KEY-----\n"
    ),
    "client_email": "leaky-bot@leaky-demo-42.iam.gserviceaccount.com",
    "client_id": "104958372619283746501",
}

AZURE_STORAGE_CONNECTION_STRING = (
    "DefaultEndpointsProtocol=https;"
    "AccountName=leakystorageacct;"
    "AccountKey=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDRA==;"
    "EndpointSuffix=core.windows.net"
)


# ─── SaaS / API tokens (push-protection-safe formats) ────────────────────────

# GitHub PAT — docs example, push protection allows this exact prefix shape
GITHUB_PAT          = "ghp_FAKEEXAMPLE292c6912E7710c838347Ae178B4a01D2"

# Note: Slack webhook URLs and GitLab `glpat-*` tokens were intentionally
# omitted — GitHub Push Protection blocks both prefixes regardless of value.

# Linear API token — high-entropy, no GitHub issuer verifier
LINEAR_API_KEY      = "lin_api_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789aBcDeFgHiJkLm"

# Notion internal integration secret
NOTION_API_KEY      = "secret_FAKEAbCdEfGhIjKlMnOpQrStUvWxYz0123456789aBcDeFgHiJkLm"

# Datadog API + APP key pair — 32-char + 40-char hex
DATADOG_API_KEY     = "8f3c4d2e9a1b6f5e0c7d8a4b3e2f1d9c"
DATADOG_APP_KEY     = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d"

# Mailgun API key (legacy "key-" prefix)
MAILGUN_API_KEY     = "key-1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p"

# SendGrid — generic 69-char with SG. prefix
SENDGRID_API_KEY    = "SG.abcdefghijklmnopqrstuv.1234567890abcdefghijklmnopqrstuvwxyz1234567"

# Twilio
TWILIO_ACCOUNT_SID  = "ACa1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
TWILIO_AUTH_TOKEN   = "00112233445566778899aabbccddeeff"

# OpenAI / Anthropic — FAKE markers defeat issuer-specific verifiers
OPENAI_API_KEY      = "sk-proj-FAKEAbCdEfGhIjKlMnOpQrStUvWxYz0123456789FAKEabcdefghijklmn"
ANTHROPIC_API_KEY   = "sk-ant-api03-FAKEabcdefghijklmnopqrstuvwxyz0123456789-FAKE_AAAA"


# ─── Database & infra credentials ─────────────────────────────────────────────

DATABASE_URL = "postgresql://admin:S3cr3tP@ssw0rd!@db.internal.example.com:5432/production"
REDIS_URL    = "redis://:R3disP4ssw0rd@cache.internal.example.com:6379/0"
MONGO_URL    = "mongodb+srv://root:mongoR00tPwd@cluster0.mongodb.net/?retryWrites=true"

JWT_SIGNING_SECRET = "super-duper-not-so-secret-jwt-signing-key-2026"
ENCRYPTION_KEY     = "0123456789abcdef0123456789abcdef"  # 32-byte AES key


# ─── Embedded private key (fake) ──────────────────────────────────────────────

SSH_PRIVATE_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA1234FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE
FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFA
-----END OPENSSH PRIVATE KEY-----
"""


# ─── App code that "uses" the secrets ─────────────────────────────────────────

@dataclass
class AppConfig:
    aws_key: str = AWS_ACCESS_KEY_ID
    aws_secret: str = AWS_SECRET_ACCESS_KEY
    db_url: str = DATABASE_URL
    jwt_secret: str = JWT_SIGNING_SECRET


def upload_to_s3(bucket: str, key: str, body: bytes) -> None:
    """Upload using inline credentials — flagged as hardcoded creds."""
    client = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        aws_session_token=AWS_SESSION_TOKEN,
    )
    client.put_object(Bucket=bucket, Key=key, Body=body)


def call_openai(prompt: str) -> str:
    res = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        },
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": prompt}]},
        timeout=30,
    )
    return res.json()["choices"][0]["message"]["content"]


def query_linear(query: str) -> dict:
    return requests.post(
        "https://api.linear.app/graphql",
        headers={
            "Authorization": LINEAR_API_KEY,
            "Content-Type": "application/json",
        },
        json={"query": query},
        timeout=10,
    ).json()


def push_metric(name: str, value: float) -> None:
    requests.post(
        "https://api.datadoghq.com/api/v1/series",
        headers={
            "DD-API-KEY": DATADOG_API_KEY,
            "DD-APPLICATION-KEY": DATADOG_APP_KEY,
        },
        json={"series": [{"metric": name, "points": [[0, value]]}]},
        timeout=5,
    )


def encode_basic_auth(user: str = "admin", password: str = "hunter2") -> str:
    """Hardcoded basic auth header — flagged."""
    raw = f"{user}:{password}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def write_gcp_creds(path: str = "/tmp/gcp.json") -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(GCP_SERVICE_ACCOUNT_JSON, fh)
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = path


if __name__ == "__main__":
    cfg = AppConfig()
    print("Loaded leaky config:", cfg.db_url[:20], "…")
    print("Auth header:", encode_basic_auth())
