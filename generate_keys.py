from py_vapid import Vapid
import base64

v = Vapid()
v.generate_keys()
private_key = v.private_key.decode('utf-8')
public_key = v.public_key.decode('utf-8')

print(f"VAPID_PRIVATE_KEY={private_key}")
print(f"VAPID_PUBLIC_KEY={public_key}")
