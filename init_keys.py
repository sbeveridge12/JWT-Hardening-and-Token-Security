"""Create unique local lab keys. Run once. Never commit the generated .env."""

from pathlib import Path
from secrets import token_hex

out = Path(__file__).with_name('.env')
if out.exists():
    raise SystemExit('.env already exists. Keeping your current keys unchanged.')

out.write_text(
    '# Generated for local JWT lab ONLY. Do not commit.\n'
    f'JWT_KEY_V1={token_hex(32)}\n'
    f'JWT_KEY_V2={token_hex(32)}\n'
    'JWT_ACTIVE_KID=v2\n',
    encoding='utf-8',
)
print('Created .env with two strong signing keys; active key is v2.')
