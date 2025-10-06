Crypto API — quick usage

# Generate / Load RSA Keys

from SOCP.client.crypto_km import gen_rsa_4096, save_pem_priv, load_pem_priv, pub_der_b64u

sk = gen_rsa_4096()
save_pem_priv(sk, "me.pem", password=b"pwd")
sk = load_pem_priv("me.pem", password=b"pwd")
pub_b64u = pub_der_b64u(sk) # share this with others

# Direct Message (DM)

from SOCP.client.crypto_dm import make_dm_payload, open_dm_payload

## Sender

payload = make_dm_payload(my_priv, peer_pub_b64u, b"hi there", "Alice", "Bob", 1700000400000)
envelope = {
"type": "MSG_DIRECT",
"from": "Alice",
"to": "Bob",
"ts": 1700000400000,
"payload": payload,
"sig": ""
}

## Receiver

pt, sender_pub = open_dm_payload(
my_priv, envelope["payload"], envelope["from"], envelope["to"], envelope["ts"]
)
print(pt.decode())

# File Transfer (RSA-OAEP)

Each file chunk is encrypted directly with the receiver’s RSA-4096 public key.

from SOCP.client.crypto_file import make_file_chunk_payload, open_file_chunk_payload
from SOCP.client.crypto_km import gen_rsa_4096, pub_der_b64u

sender = gen_rsa_4096()
receiver = gen_rsa_4096()
receiver_pub_b64u = pub_der_b64u(receiver)

file_id = "uuid-123"
payload = make_file_chunk_payload(receiver_pub_b64u, file_id, 0, b"chunk data")

## Receiver side

pt = open_file_chunk_payload(receiver, payload)
print("Decrypted chunk:", pt)

# Public Channel Messages

Messages broadcasted to everyone but still encrypted per recipient with RSA-OAEP.

from SOCP.client.crypto_public import make_public_payload, open_public_payload

payload = make_public_payload(
sender_priv, receiver_pub_b64u, b"hello world", "user_A", 1700000600000
)
pt, spk = open_public_payload(receiver_priv, payload, "user_A", 1700000600000)

# Server Transport Signatures

Used for verifying that inter-server payloads aren’t tampered with.

from SOCP.server.transport_sig import server_sign_payload, server_verify_payload
from SOCP.client.crypto_km import gen_rsa_4096, pub_der_b64u

srv = gen_rsa_4096()
pub_b64u = pub_der_b64u(srv)

payload = {"user_id": "Alice", "location": "server_123"}
sig = server_sign_payload(srv, payload)
ok = server_verify_payload(pub_b64u, payload, sig)
print("Verify OK:", ok)
