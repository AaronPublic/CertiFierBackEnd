import os
import base64
from nacl.signing import SigningKey, VerifyKey

# Load signing key from environment
SIGNING_KEY_HEX = os.getenv("CERT_EDDSA_SIGNING_KEY")

if SIGNING_KEY_HEX:
    SIGNING_KEY = SigningKey(bytes.fromhex(SIGNING_KEY_HEX))
else:
    SIGNING_KEY = SigningKey.generate()
    print("⚠️ WARNING: No persistent signing key set!")
    print("SAVE THIS KEY:", SIGNING_KEY.encode().hex())

VERIFY_KEY = SIGNING_KEY.verify_key


def sign_data(data: str) -> str:
    """Sign data and return base64 signature"""
    signed = SIGNING_KEY.sign(data.encode('utf-8'))
    return base64.b64encode(signed.signature).decode('utf-8')


def verify_signature(data: str, signature_b64: str, public_key_hex: str) -> bool:
    """Verify using stored public key"""
    try:
        signature = base64.b64decode(signature_b64)

        verify_key = VerifyKey(bytes.fromhex(public_key_hex))

        verify_key.verify(data.encode('utf-8'), signature)

        return True
    except Exception:
        return False