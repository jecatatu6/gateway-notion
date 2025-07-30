import asyncio
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient
from app import app, gen_jwt, SECRET, ISSUER
import asyncio

client = TestClient(app)

@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(autouse=True)
async def connect_db():
    await app.db.connect()
    yield
    await app.db.disconnect()

@pytest.fixture
def valid_token():
    return gen_jwt("test@example.com", 1)

@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(autouse=True)
async def connect_db():
    await client.app.db.connect()
    yield
    await client.app.db.disconnect()

def test_webhook_subscription_created(monkeypatch):
    payload = {
        "event": "subscription.created",
        "data": {"customer_email": "test@example.com"}
    }
    headers = {}
    # Patch WEBHOOK_TOKEN to None to disable token check
    monkeypatch.setattr("app.WEBHOOK_TOKEN", None)
    response = client.post("/webhook/kiwify", json=payload, headers=headers)
    assert response.status_code == 200
    assert "token" in response.json()

def test_webhook_subscription_canceled(monkeypatch):
    payload = {
        "event": "subscription.canceled",
        "data": {"customer_email": "test@example.com"}
    }
    headers = {}
    monkeypatch.setattr("app.WEBHOOK_TOKEN", None)
    response = client.post("/webhook/kiwify", json=payload, headers=headers)
    assert response.status_code == 200

def test_webhook_unauthorized(monkeypatch):
    payload = {
        "event": "subscription.created",
        "data": {"customer_email": "test@example.com"}
    }
    headers = {"x-kiwify-token": "wrongtoken"}
    monkeypatch.setattr("app.WEBHOOK_TOKEN", "correcttoken")
    response = client.post("/webhook/kiwify", json=payload, headers=headers)
    assert response.status_code == 401

def test_access_valid_token(valid_token):
    response = client.get(f"/a/{valid_token}")
    # Since the token is not in DB, expect 403
    assert response.status_code == 403

def test_access_invalid_token():
    response = client.get("/a/invalidtoken")
    assert response.status_code == 403