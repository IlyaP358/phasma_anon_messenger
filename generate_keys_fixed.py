from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import base64

def to_b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

# Generate key pair
private_key = ec.generate_private_key(ec.SECP256R1())

# Get private key bytes (32 bytes)
private_value = private_key.private_numbers().private_value
private_bytes = private_value.to_bytes(32, byteorder='big')

# Get public key bytes (Uncompressed Point format, 65 bytes)
public_key = private_key.public_key()
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)

print(f"VAPID_PRIVATE_KEY={to_b64url(private_bytes)}")
print(f"VAPID_PUBLIC_KEY={to_b64url(public_bytes)}")
