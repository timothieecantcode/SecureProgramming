from SOCP.client.crypto_km import gen_rsa_4096
from SOCP.client.crypto_api import sign_pss, verify_pss

sk = gen_rsa_4096()
pk = sk.public_key()
msg = b"hello secure world"
sig = sign_pss(sk, msg)
print("verify (ok):", verify_pss(pk, sig, msg))
print("verify (tamper):", verify_pss(pk, sig, b"tampered"))
