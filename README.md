# JWT Security Testing Lab

A local-only Flask lab contrasting intentionally vulnerable JWT handling and hardened JWT handling. The lab demonstrates weak HMAC keys, missing expiration, excessive claims, unsigned `alg:none` tokens, strict signature verification, strong keys, and local key rotation.

**Safety:** This contains deliberate vulnerabilities. Keep it bound to `127.0.0.1`, do not deploy to a public server, and never use real credentials or personal data.

## Setup

Use Python 3.10+.

### Windows PowerShell

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python init_keys.py
python app.py
```

If script execution is blocked by PowerShell policy, run `.venv\Scripts\python.exe -m pip install -r requirements.txt` and `.venv\Scripts\python.exe app.py` instead of activating the environment.

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python init_keys.py
python app.py
```

Local API base URL: `http://127.0.0.1:5000`.

## Login requests

In Postman, create a POST request to either:

- `http://127.0.0.1:5000/vulnerable/login`
- `http://127.0.0.1:5000/secure/login`

Body type: JSON

```json
{"username": "demo", "password": "demo-pass"}
```

Copy the `access_token` from the response. Send a GET request to the corresponding profile endpoint, using header `Authorization: Bearer <token>`:

- `/vulnerable/profile`: validates with an intentionally weak secret, does not require expiry.
- `/vulnerable/unverified-profile`: deliberately skips all signature validation and accepts unsigned tokens.
- `/secure/profile`: validates signature, allowed algorithm, audience, issuer, expiry, purpose, scope, duration, and trusted key ID.

**Note:** The demo login uses fixed fake credentials for simplicity, not a production password/authentication design.

## Run security regression tests

Stop the running Flask process or open another terminal, activate the same virtual environment, then run:

```bash
python -m pytest -v
```

Expected: 9 tests passed. The vulnerable endpoints are deliberately accepted in specific tests; the secure API must reject those same invalid or forged tokens.

## Explore with jwt.io or Burp Suite

1. Login to `/vulnerable/login`; inspect your **lab-only** token in jwt.io (header and payload only; do not paste production tokens or secrets into websites).
2. Observe the deliberately excessive `billing_address` claim (fictional example) and missing `exp`.
3. Create an unsigned token locally using PyJWT:

```python
import jwt
forged = jwt.encode({'sub': 'attacker', 'role': 'admin'}, key='', algorithm='none', headers={'kid': 'v2'})
print(forged)
```

4. Send it to `/vulnerable/unverified-profile`; record the success.
5. Send the same forged token to `/secure/profile`; record the `401` rejection.
6. For a weak-key demonstration, sign a fabricated token with `secret123` and HS256 and send it to `/vulnerable/profile`; it will succeed despite not being issued by `/vulnerable/login`.

## Rotate signing keys

The `init_keys.py` script creates `v1` and `v2`, and selects `v2` as active in `.env`.

To demonstrate a non-disruptive key rotation:

1. Set `JWT_ACTIVE_KID=v1` in `.env`, restart the Flask app, and issue a token via `/secure/login`.
2. Change `JWT_ACTIVE_KID=v2`, restart, and verify the `v1` token still works while both keys exist.
3. Remove `JWT_KEY_V1` from `.env` and restart; the previous `v1` token now receives `401`.
4. New tokens are always signed with the active `v2` key. Do steps 1–3 within five minutes (before the old token expires).

This sample supports key rotation via trusted configuration and restarts. Production rotation should use a secret manager/KMS, coordinated key publication, audit logs, and appropriately timed old-key retirement.

## Recommended report / screenshots

1. Token anatomy: header, payload, signature; highlight that base64url encoding does not encrypt claims.
2. Findings matrix: vulnerability, exploit/test, impact, fix, CWE, ASVS.
3. Before-and-after Postman screenshots showing vulnerable 200 vs hardened 401.
4. A key rotation demo showing an old token valid during overlap and invalid after retirement.
5. Automated test run and 3-week work log.

## Standards references

- OWASP ASVS 5.0: V9.1.1 signature verification; V9.1.2 algorithm allowlisting; V9.1.3 trusted key sources; V9.2.1 token validity windows; V9.2.2 token purpose; V9.2.3 audience restriction.
- CWE-347: improper verification of cryptographic signatures.
- CWE-321: use of hard-coded cryptographic key.
- CWE-613: insufficient session expiration (requires contextual care in mapping).
- CWE-201: insertion of sensitive information into sent data.
- OWASP JWT Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html
- ASVS V9: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x18-V9-Self-contained-Tokens.md
- PyJWT docs: https://pyjwt.readthedocs.io/en/latest/usage.html
