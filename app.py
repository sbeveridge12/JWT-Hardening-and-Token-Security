"""Local-only JWT security lab. Vulnerable routes are intentionally insecure.

Do not deploy this sample to an internet-accessible host.
"""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from dotenv import load_dotenv
from flask import Flask, jsonify, request

load_dotenv(Path(__file__).with_name('.env'))

app = Flask(__name__)

# INTENTIONALLY WEAK: for the local vulnerable demonstration ONLY.
LAB_WEAK_SECRET = 'secret123'
ISSUER = 'jwt-lab'
AUDIENCE = 'jwt-lab-api'
ACCESS_TOKEN_LIFETIME_SECONDS = 300
ACTIVE_KID = os.getenv('JWT_ACTIVE_KID', 'v2')

# Trusted server-side allowlist. Never accept keys/URLs from token headers.
KEYRING = {
    kid: key
    for kid in ('v1', 'v2')
    if (key := os.getenv(f'JWT_KEY_{kid.upper()}'))
}
if ACTIVE_KID not in KEYRING:
    raise RuntimeError('Run `python init_keys.py` to generate local signing keys.')
if any(len(key.encode('utf-8')) < 32 for key in KEYRING.values()):
    raise RuntimeError('JWT signing keys must be securely generated and at least 32 bytes.')


def demo_login_is_valid():
    """Fixed, fake demo credentials; NOT a production login system."""
    data = request.get_json(silent=True) or {}
    return data.get('username') == 'demo' and data.get('password') == 'demo-pass'


def bearer_token():
    scheme, separator, token = request.headers.get('Authorization', '').partition(' ')
    if not separator or scheme.lower() != 'bearer' or not token.strip():
        return None
    return token.strip()


def unauthorized():
    return jsonify(error='Unauthorized or invalid token'), 401


@app.post('/vulnerable/login')
def vulnerable_login():
    if not demo_login_is_valid():
        return unauthorized()

    # INTENTIONAL FLAWS: weak, hard-coded secret; missing exp; excessive data.
    claims = {
        'sub': 'demo',
        'role': 'user',
        'email': 'demo@example.test',
        'billing_address': '123 Example Street (FICTIONAL)',
    }
    token = jwt.encode(claims, LAB_WEAK_SECRET, algorithm='HS256')
    return jsonify(access_token=token)


@app.get('/vulnerable/profile')
def vulnerable_profile():
    token = bearer_token()
    if token is None:
        return unauthorized()
    try:
        # Signature validation is enabled, but secret is easily guessed;
        # the missing exp is NOT required, so timeless tokens are accepted.
        claims = jwt.decode(token, LAB_WEAK_SECRET, algorithms=['HS256'])
    except jwt.InvalidTokenError:
        return unauthorized()
    return jsonify(subject=claims.get('sub'), role=claims.get('role'))


@app.get('/vulnerable/unverified-profile')
def vulnerable_unverified_profile():
    token = bearer_token()
    if token is None:
        return unauthorized()
    try:
        # INTENTIONAL FLAW: no signature validation. Also accepts alg:none.
        # This option is for controlled demonstration, NEVER authentication.
        claims = jwt.decode(token, options={'verify_signature': False})
    except jwt.InvalidTokenError:
        return unauthorized()
    return jsonify(subject=claims.get('sub'), role=claims.get('role'))


@app.post('/secure/login')
def secure_login():
    if not demo_login_is_valid():
        return unauthorized()

    now = datetime.now(timezone.utc)
    claims = {
        'sub': 'demo',
        'iss': ISSUER,
        'aud': AUDIENCE,
        'iat': now,
        'nbf': now,
        'exp': now + timedelta(seconds=ACCESS_TOKEN_LIFETIME_SECONDS),
        'token_use': 'access',
        'scope': 'read:profile',
    }
    token = jwt.encode(
        claims,
        KEYRING[ACTIVE_KID],
        algorithm='HS256',
        headers={'kid': ACTIVE_KID},
    )
    return jsonify(access_token=token, expires_in=ACCESS_TOKEN_LIFETIME_SECONDS)


@app.get('/secure/profile')
def secure_profile():
    token = bearer_token()
    if token is None:
        return unauthorized()

    try:
        # Header is not verified yet: use it ONLY to pick from our fixed keyring.
        header = jwt.get_unverified_header(token)
        kid = header.get('kid')
        if header.get('alg') != 'HS256' or kid not in KEYRING:
            return unauthorized()
        if any(field in header for field in ('jku', 'jwk', 'x5u')):
            return unauthorized()

        claims = jwt.decode(
            token,
            KEYRING[kid],
            algorithms=['HS256'],  # fixed allowlist, never taken from header
            issuer=ISSUER,
            audience=AUDIENCE,
            options={
                'require': [
                    'sub', 'iss', 'aud', 'iat', 'nbf', 'exp',
                    'token_use', 'scope',
                ]
            },
        )
        if claims['token_use'] != 'access':
            return unauthorized()
        if claims['scope'] != 'read:profile':
            return unauthorized()
        if claims['exp'] - claims['iat'] > ACCESS_TOKEN_LIFETIME_SECONDS:
            return unauthorized()
        if claims['exp'] <= claims['iat']:
            return unauthorized()

    except (jwt.InvalidTokenError, TypeError, ValueError):
        return unauthorized()

    return jsonify(subject=claims['sub'], scope=claims['scope'])


if __name__ == '__main__':
    # Bind to loopback only; this contains deliberately vulnerable endpoints.
    app.run(host='127.0.0.1', port=5000, debug=False)
