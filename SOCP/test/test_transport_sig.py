from SOCP.server.transport_sig import server_sign_payload, server_verify_payload
from SOCP.client.crypto_km import gen_rsa_4096, pub_der_b64u

srv = gen_rsa_4096()
pub_b64u = pub_der_b64u(srv)

payload = {"user_id": "Alice", "location": "server_123"}
sig = server_sign_payload(srv, payload)
print("verify ok:", server_verify_payload(pub_b64u, payload, sig))

# tamper the payload
tampered = {**payload, "location": "server_999"}
print("verify tamper:", server_verify_payload(pub_b64u, tampered, sig))
