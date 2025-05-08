# This example demonstrates adaptor signatures using chatGPT.
"""
Warning: This is not very useful as the logic is not that precise.

I realized there was something wrong in this ECDSA example. This is an illsutration of
the limitations (current limitations) of vibe coding! We need to insepct the code carefully 
and make sure it is correct

# in what follows, the above r_t and R_t are not used because this is a ECDSA example. 
# tryign to lock the signature with T in ECDSA would not work 
# these are actually meant to be used in Schnorr signatures for adaptor signatures



High level overview of the code:
* Alice creates a signature that is incomplete without t.
* Once t is revealed (or learned), she completes the signature.
* Bob can then extract t from the difference between s and s'.

Warning:
* This example does not verify the signature — it's focused on the locking/unlocking mechanism.
* Real-world use would involve Schnorr signatures (e.g., BIP-340), which are more suitable for adaptor signatures than ECDSA.
    * Schnorr signatures are linear in the nonce, allowing for the addition of signatures.
    * so they are better solution for multi-signature schemes.
* Bitcoin does not yet natively support adaptor signatures, but tools like Taproot and MuSig2 are pushing toward this capability. 
"""


import os
import hashlib
from ecdsa import SECP256k1, SigningKey, VerifyingKey, ellipticcurve

# Utility: SHA256 hash
def sha256(b):
    return hashlib.sha256(b).digest()

# Step 1: Key Generation
curve = SECP256k1
G = curve.generator
n = curve.order

# Alice's signing key
alice_sk = SigningKey.generate(curve=SECP256k1)
alice_vk = alice_sk.verifying_key

# Step 2: Message to be signed
msg = b"Atomic Swap: Alice pays Bob 1 BTC"
z = int.from_bytes(sha256(msg), 'big') % n # Hash of the message encoded as an integer

# Step 3: Bob generates secret adaptor
t = int.from_bytes(os.urandom(32), 'big') % n
T = t * G  # Public adaptor point

# Step 4: Alice creates an adaptor signature (r, s')
k = int.from_bytes(os.urandom(32), 'big') % n # Alice's private nonce
R = k * G 
r = R.x() % n   

# Adaptor public nonce: R + T
R_t = R + T #EC addition.. to lock the signature
r_t = R_t.x() % n



# Calculate s' = k⁻¹ * (z + r * alice_priv)
k_inv = pow(k, -1, n)
s_adaptor = (k_inv * (z + r * alice_sk.privkey.secret_multiplier)) % n

# Adaptor signature = (r, s_adaptor), locked with T
print(f"Adaptor signature: (r={r}, s'={s_adaptor})")

# Step 5: Alice learns t, completes signature
s_final = (s_adaptor + t) % n
print(f"Final signature: (r={r}, s={s_final})")

# Step 6: Bob recovers secret t
recovered_t = (s_final - s_adaptor) % n
print(f"Recovered t: {recovered_t}")
print(f"Original t == Recovered t? {t == recovered_t}")

