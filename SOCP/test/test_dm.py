# run with: python3 - <<'PY'
from SOCP.client.crypto_km import gen_rsa_4096, pub_der_b64u
from SOCP.client.crypto_dm import make_dm_payload, open_dm_payload

alice = gen_rsa_4096()
bob = gen_rsa_4096()
payload = make_dm_payload(alice, pub_der_b64u(
    bob), b"hi bob", "Alice", "Bob", 1700000400000)
pt, _ = open_dm_payload(bob, payload, "Alice", "Bob", 1700000400000)
print("DM:", pt.decode())

# tamper
bad = dict(payload)
bad["ciphertext"] = bad["ciphertext"][:-2] + "AA"
try:
    open_dm_payload(bob, bad, "Alice", "Bob", 1700000400000)
    print("tamper NOT caught")
except Exception as e:
    print("tamper caught:", e)
# PY
