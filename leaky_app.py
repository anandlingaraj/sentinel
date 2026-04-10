"""
leaky_app.py — intentionally vulnerable sample for SentinelAI's secret scanner.

DO NOT DEPLOY. All credentials below are fabricated and exist only to exercise
detection rules (TruffleHog / Gitleaks / detect-secrets style patterns).
"""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

import boto3  # type: ignore
import requests  # type: ignore


# ─── Cloud provider keys ──────────────────────────────────────────────────────

GCP_SERVICE_ACCOUNT_JSON = {
    "type": "service_account",
    "project_id": "leaky-demo-42",
    "private_key_id": "9c1f8d4b2e6a47f0b3d5a8c2e9f0b1d4a6c8e0f2",
    "private_key": (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n"
        "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n"
        "FAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEY=\n"
        "-----END PRIVATE KEY-----\n"
    ),
    "client_email": "leaky-bot@leaky-demo-42.iam.gserviceaccount.com",
    "client_id": "104958372619283746501",
}

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


def post_to_slack(message: str) -> None:
    requests.post(
        SLACK_WEBHOOK_URL,
        json={"text": message},
        headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
        timeout=5,
    )


def charge_customer(customer_id: str, amount_cents: int) -> dict:
    return requests.post(
        "https://api.stripe.com/v1/charges",
        auth=(STRIPE_LIVE_KEY, ""),
        data={"customer": customer_id, "amount": amount_cents, "currency": "usd"},
        timeout=10,
    ).json()


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
