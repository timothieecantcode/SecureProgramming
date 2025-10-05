from SOCP.client.crypto_km import gen_rsa_4096, pub_der, pub_from_der
from SOCP.client.crypto_api import sign_pss, verify_pss, wrap_key_rsa_oaep, unwrap_key_rsa_oaep, aesgcm_encrypt, aesgcm_decrypt
import os

# --- RSA PSS ---
sk = gen_rsa_4096()
pk = sk.public_key()
msg = b"hello secure world"
sig = sign_pss(sk, msg)
print("verify (ok):", verify_pss(pk, sig, msg))
print("verify (tamper):", verify_pss(pk, sig, b"tampered"))

# --- RSA OAEP wrap/unwrap ---
aes_key = os.urandom(32)
wrapped = wrap_key_rsa_oaep(pk, aes_key)
unwrapped = unwrap_key_rsa_oaep(sk, wrapped)
print("wrap/unwrap ok:", aes_key == unwrapped)

# --- AES-GCM encrypt/decrypt ---
iv, ct, tag = aesgcm_encrypt(aes_key, b"super secret msg", b"aad-test")
pt = aesgcm_decrypt(aes_key, iv, ct, tag, b"aad-test")
print("AES roundtrip:", pt.decode())
