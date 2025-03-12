'''
WRONG! This does not reuse the nonce. See next exanple, baseEx2.py for the correct version.

Base example for extractKey from chatgpt 4o
'''

from ecdsa import SigningKey, NIST256p
from hashlib import sha256
from sympy import mod_inverse

# ECDSA Key Generation
sk = SigningKey.generate(curve=NIST256p)
pk = sk.verifying_key
private_key = sk.privkey.secret_multiplier

# Message Hashing
msg1 = b"Hello, world!"
msg2 = b"Different message"
hash1 = int.from_bytes(sha256(msg1).digest(), byteorder='big')
hash2 = int.from_bytes(sha256(msg2).digest(), byteorder='big')

# Fake signature generation with nonce reuse
k = 123456789  # Bad practice: using a fixed nonce
r, s1 = sk.sign_deterministic(msg1, hashfunc=sha256)[:32], None
r, s2 = sk.sign_deterministic(msg2, hashfunc=sha256)[:32], None
r = int.from_bytes(r, byteorder='big')

# Extracting signature values manually
def extract_signature(msg):
    signature = sk.sign_deterministic(msg, hashfunc=sha256)
    r_val = int.from_bytes(signature[:32], byteorder='big')
    s_val = int.from_bytes(signature[32:], byteorder='big')
    return r_val, s_val

r1, s1 = extract_signature(msg1)
r2, s2 = extract_signature(msg2)

# Recovering the private key
n = sk.curve.order
numerator = (hash1 - hash2) % n
denominator = mod_inverse((s1 - s2) % n, n)
recovered_private_key = (numerator * denominator) % n

print("Original Private Key:", private_key)
print("Recovered Private Key:", recovered_private_key)
print("Keys Match:", private_key == recovered_private_key)
