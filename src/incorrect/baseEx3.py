'''
baseEx2.py was not correct. When informed, chatgpat replied with the following:



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

# Fixed nonce (bad practice, used for demonstration purposes)
k = 123456789
n = sk.curve.order

# Manually generate ECDSA signatures with reused nonce
def sign_with_fixed_nonce(sk, msg, k):
    hash_val = int.from_bytes(sha256(msg).digest(), byteorder='big')
    r = (sk.curve.generator * k).x() % n
    s = ((hash_val + private_key * r) * mod_inverse(k, n)) % n 
    return r, s

r1, s1 = sign_with_fixed_nonce(sk, msg1, k)
r2, s2 = sign_with_fixed_nonce(sk, msg2, k)

# Recovering the private key
numerator = (s1 - s2) % n
if numerator == 0:
    raise ValueError("Nonce reuse attack failed due to invalid signature values.")

denominator = (hash1 - hash2) % n
if denominator == 0:
    raise ValueError("Hash values resulted in zero denominator.")

denominator_inv = mod_inverse(denominator, n)
private_key_recovered = (numerator * denominator_inv) % n

print("Original Private Key:", private_key)
print("Recovered Private Key:", private_key_recovered)
print("Keys Match:", private_key == private_key_recovered)
