"""Negative security tests: vulnerable route accepts, secure route rejects."""

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from app import (
    ACCESS_TOKEN_LIFETIME_SECONDS,
    ACTIVE_KID,
    AUDIENCE,
    ISSUER,
    KEYRING,
    LAB_WEAK_SECRET,
    app,
)


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as testing_client:
        yield testing_client


def auth(token):
    return {'Authorization': f'Bearer {token}'}


def login(client, route):
    response = client.post(route, json={'username': 'demo', 'password': 'demo-pass'})
    assert response.status_code == 200
    return response.json['access_token']


def valid_secure_claims():
    now = datetime.now(timezone.utc)
    return {
        'sub': 'demo',
        'iss': ISSUER,
        'aud': AUDIENCE,
        'iat': now,
        'nbf': now,
        'exp': now + timedelta(seconds=ACCESS_TOKEN_LIFETIME_SECONDS),
        'token_use': 'access',
        'scope': 'read:profile',
    }


def sign_secure(claims, kid=ACTIVE_KID):
    return jwt.encode(claims, KEYRING[kid], algorithm='HS256', headers={'kid': kid})


def test_valid_secure_token(client):
    token = login(client, '/secure/login')
    response = client.get('/secure/profile', headers=auth(token))
    assert response.status_code == 200
    assert response.json == {'subject': 'demo', 'scope': 'read:profile'}
    decoded = jwt.decode(token, KEYRING[ACTIVE_KID], algorithms=['HS256'], audience=AUDIENCE, issuer=ISSUER)
    assert 'email' not in decoded
    assert 'billing_address' not in decoded


def test_weak_secret_allows_forgery_in_vulnerable_api(client):
    fake = jwt.encode({'sub': 'attacker', 'role': 'admin'}, LAB_WEAK_SECRET, algorithm='HS256')
    response = client.get('/vulnerable/profile', headers=auth(fake))
    assert response.status_code == 200
    assert response.json['role'] == 'admin'
    assert client.get('/secure/profile', headers=auth(fake)).status_code == 401


def test_unsigned_none_token_is_accepted_only_by_unverified_api(client):
    fake = jwt.encode(
        {'sub': 'attacker', 'role': 'admin'},
        key='',
        algorithm='none',
        headers={'kid': ACTIVE_KID},
    )
    assert client.get('/vulnerable/unverified-profile', headers=auth(fake)).status_code == 200
    assert client.get('/secure/profile', headers=auth(fake)).status_code == 401


def test_missing_exp_accepted_only_by_vulnerable_api(client):
    token = login(client, '/vulnerable/login')
    payload = jwt.decode(token, LAB_WEAK_SECRET, algorithms=['HS256'])
    assert 'exp' not in payload
    assert 'billing_address' in payload
    assert client.get('/vulnerable/profile', headers=auth(token)).status_code == 200
    assert client.get('/secure/profile', headers=auth(token)).status_code == 401


def test_expired_token_is_rejected(client):
    claims = valid_secure_claims()
    claims['exp'] = datetime.now(timezone.utc) - timedelta(seconds=1)
    token = sign_secure(claims)
    assert client.get('/secure/profile', headers=auth(token)).status_code == 401


def test_missing_exp_rejected_even_if_signed_with_strong_key(client):
    claims = valid_secure_claims()
    del claims['exp']
    token = sign_secure(claims)
    assert client.get('/secure/profile', headers=auth(token)).status_code == 401


def test_wrong_audience_is_rejected(client):
    claims = valid_secure_claims()
    claims['aud'] = 'some-other-api'
    token = sign_secure(claims)
    assert client.get('/secure/profile', headers=auth(token)).status_code == 401


def test_excessively_long_lifetime_is_rejected(client):
    claims = valid_secure_claims()
    claims['exp'] = datetime.now(timezone.utc) + timedelta(hours=24)
    token = sign_secure(claims)
    assert client.get('/secure/profile', headers=auth(token)).status_code == 401


def test_key_rotation_retirement(client, monkeypatch):
    old_key_token = sign_secure(valid_secure_claims(), kid='v1')
    assert client.get('/secure/profile', headers=auth(old_key_token)).status_code == 200
    monkeypatch.delitem(KEYRING, 'v1')
    assert client.get('/secure/profile', headers=auth(old_key_token)).status_code == 401
