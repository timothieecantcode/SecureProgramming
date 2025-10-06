from SOCP.common.b64url import b64u, ub64u
from SOCP.common.canon import sha256_bytes
from SOCP.client.crypto_api import (
    aesgcm_encrypt, aesgcm_decrypt, wrap_key_rsa_oaep, unwrap_key_rsa_oaep, sign_pss, verify_pss)
from SOCP.client.crypto_km import pub_from_der, pub_der, pub_der_b64u
import os


# ---- Content hash ---- #
def dm_content_hash(cipher_b64u, iv_b64u, tag_b64u, from_id, to_id, ts_ms):
    return sha256_bytes(ub64u(cipher_b64u), ub64u(iv_b64u), ub64u(tag_b64u), from_id.encode(), to_id.encode(), str(ts_ms).encode(),)


# ---- Build payload for sender ---- #
def make_dm_payload(sender_priv, receiver_pub_der_b64u, plaintext, from_id, to_id, ts_ms):
    key32 = os.urandom(32)
    iv, ct, tag = aesgcm_encrypt(key32, plaintext, b"")
    recv_pub = pub_from_der(ub64u(receiver_pub_der_b64u))
    wrapped_key = wrap_key_rsa_oaep(recv_pub, key32)

    cipher_b64u, iv_b64u, tag_b64u = b64u(ct), b64u(iv), b64u(tag)
    h = dm_content_hash(cipher_b64u, iv_b64u, tag_b64u, from_id, to_id, ts_ms)
    sig = sign_pss(sender_priv, h)

    return {
        "ciphertext": cipher_b64u,
        "iv": iv_b64u,
        "tag": tag_b64u,
        "wrapped_key": b64u(wrapped_key),
        "sender_pub": pub_der_b64u(sender_priv),
        "content_sig": b64u(sig),
    }


# ---- Verify + Decrypt for receiver ---- #
def open_dm_payload(receiver_priv, payload, from_id, to_id, ts_ms):
    h = dm_content_hash(
        payload["ciphertext"], payload["iv"], payload["tag"], from_id, to_id, ts_ms)
    sender_pub = pub_from_der(ub64u(payload["sender_pub"]))
    if not verify_pss(sender_pub, ub64u(payload["content_sig"]), h):
        raise ValueError("INVALID_SIG")

    key32 = unwrap_key_rsa_oaep(receiver_priv, ub64u(payload["wrapped_key"]))
    pt = aesgcm_decrypt(key32, ub64u(payload["iv"]), ub64u(
        payload["ciphertext"]), ub64u(payload["tag"]), b"")
    return pt, sender_pub
