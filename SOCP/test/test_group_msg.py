from SOCP.client.crypto_km import gen_rsa_4096
from SOCP.client.crypto_group import make_group_msg_payload, open_group_msg_payload
import os

sender = gen_rsa_4096()
group_key = os.urandom(32)

payload = make_group_msg_payload(
    sender, "group_abc", group_key, b"hi team", "Bob", 1700000600000)
pt, pub = open_group_msg_payload(group_key, payload, "Bob", 1700000600000)
print("Decrypted:", pt.decode())

# # tamper test
# bad = payload.copy()
# bad["iv"] = payload["iv"][:-2] + "AA"
# try:
#     open_group_msg_payload(group_key, bad, "Bob", 1700000600000)
# except Exception as e:
#     print("Tamper caught:", e)
