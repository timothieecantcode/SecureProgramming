from SOCP.client.crypto_km import gen_rsa_4096, save_pem_priv, load_pem_priv, pub_der, pub_der_b64u

sk = gen_rsa_4096()
save_pem_priv(sk, "alice_priv.pem", password=b"secret123")
sk2 = load_pem_priv("alice_priv.pem", password=b"secret123")

pub1 = pub_der(sk)
pub2 = pub_der(sk2)
assert pub1 == pub2, "pub mismatch after reload"

print("pub_b64url:", pub_der_b64u(sk)[:60] + "...")  # ready for JSON payloads
print("OK")
