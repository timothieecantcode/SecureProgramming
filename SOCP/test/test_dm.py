from SOCP.client.crypto_km import gen_rsa_4096, pub_der_b64u
from SOCP.client.crypto_dm import make_dm_payload, open_dm_payload

alice_sk = gen_rsa_4096()
bob_sk = gen_rsa_4096()
bob_pub_b64u = pub_der_b64u(bob_sk)

from_id, to_id, ts = "Alice", "Bob", 1700000400000
payload = make_dm_payload(alice_sk, bob_pub_b64u,
                          b"hey cutie?", from_id, to_id, ts)

pt, sender_pub = open_dm_payload(bob_sk, payload, from_id, to_id, ts)
print("Decrypted:", pt.decode())

# Tamper set
# try:
#     bad = payload.copy()
#     bad["to"] = "Tim"
#     open_dm_payload(bob_sk, bad, from_id, "Tim", ts)
# except Exception as e:
#     print("Tamper caught:", e)
