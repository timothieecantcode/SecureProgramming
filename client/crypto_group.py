from SOCP.common.b64url import b64u, ub64u
from SOCP.common.canon import canon, sha256_bytes
from SOCP.client.crypto_km import pub_from_der, pub_der, pub_der_b64u
from SOCP.client.crypto_api import wrap_key_rsa_oaep, unwrap_key_rsa_oaep, \
    sign_pss, verify_pss
import os
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa
from SOCP.client.crypto_api import aesgcm_encrypt, aesgcm_decrypt


# ---- Group key shares from creators to member ---- #
def make_group_shares(creator_priv: rsa.RSAPrivateKey, group_id: str, member_pub_map: Dict[str, str],) -> Dict[str, Any]:
    group_key = os.urandom(32)
    shares = []
    for member, der_b64u in member_pub_map.items():
        pk = pub_from_der(ub64u(der_b64u))
        shares.append({
            "member": member,
            "wrapped_group_key": b64u(wrap_key_rsa_oaep(pk, group_key))
        })

    content = {
        "group_id": group_id,
        "shares": shares,
        "creator_pub": pub_der_b64u(creator_priv),
    }
    h = sha256_bytes(canon(content))
    content["content_sig"] = b64u(sign_pss(creator_priv, h))
    return content  # drop content into MSG type "GROUP_KEY_SHARE" payload


def verify_group_shares(creator_pub_der_b64u: str, content: Dict[str, Any]) -> bool:
    creator_pub = pub_from_der(ub64u(creator_pub_der_b64u))
    signed_object = {
        "group_id": content["group_id"],
        "shares": content["shares"],
        "creator_pub": content["creator_pub"],
    }
    h = sha256_bytes(canon(signed_object))
    return verify_pss(creator_pub, ub64u(content["content_sig"]), h)


# ---- Helper to recover a clear group key ---- #
def unwrap_group_key_for_me(my_priv: rsa.RSAPrivateKey, content: Dict[str, Any], my_user_id: str,) -> bytes:
    for sh in content["shares"]:
        if sh["member"] == my_user_id:
            return unwrap_key_rsa_oaep(my_priv, ub64u(sh["wrapped_group_key"]))
    raise KeyError("No share for this member")


# ---- Group key share from sender to group ---- #
def group_content_hash(cipher_b64u, iv_b64u, tag_b64u, group_id, from_id, ts_ms):
    return sha256_bytes(
        ub64u(cipher_b64u),
        ub64u(iv_b64u),
        ub64u(tag_b64u),
        group_id.encode(),
        from_id.encode(),
        str(ts_ms).encode(),
    )


def make_group_msg_payload(
    sender_priv: rsa.RSAPrivateKey,
    group_id: str,
    group_key32: bytes,
    plaintext: bytes,
    from_id: str,
    ts_ms: int,
) -> Dict[str, Any]:
    iv, ct, tag = aesgcm_encrypt(group_key32, plaintext, b"")
    cipher_b64u, iv_b64u, tag_b64u = b64u(ct), b64u(iv), b64u(tag)
    h = group_content_hash(cipher_b64u, iv_b64u,
                           tag_b64u, group_id, from_id, ts_ms)
    sig = sign_pss(sender_priv, h)
    return {
        "group_id": group_id,
        "ciphertext": cipher_b64u,
        "iv": iv_b64u,
        "tag": tag_b64u,
        "sender_pub": pub_der_b64u(sender_priv),
        "content_sig": b64u(sig),
    }


def open_group_msg_payload(
    group_key32: bytes,
    payload: Dict[str, Any],
    from_id: str,
    ts_ms: int,
) -> Tuple[bytes, rsa.RSAPublicKey]:
    h = group_content_hash(payload["ciphertext"], payload["iv"], payload["tag"],
                           payload["group_id"], from_id, ts_ms)
    sender_pub = pub_from_der(ub64u(payload["sender_pub"]))
    ok = verify_pss(sender_pub, ub64u(payload["content_sig"]), h)
    if not ok:
        raise ValueError("INVALID_SIG")
    pt = aesgcm_decrypt(group_key32,
                        ub64u(payload["iv"]),
                        ub64u(payload["ciphertext"]),
                        ub64u(payload["tag"]),
                        b"")
    return pt, sender_pub
