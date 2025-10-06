# SOCP/client/crypto_file.py
from __future__ import annotations
from typing import Dict, Any, Tuple
from SOCP.common.b64url import b64u, ub64u
from SOCP.common.canon import canon
from SOCP.client.crypto_api import aesgcm_encrypt, aesgcm_decrypt, wrap_key_rsa_oaep, unwrap_key_rsa_oaep
from SOCP.client.crypto_km import pub_from_der
import os

# ---- Per-file symmetric key helpers ---- #


def gen_file_key32() -> bytes:
    return os.urandom(32)


def wrap_file_key_for_dm(receiver_pub_der_b64u: str, file_key32: bytes) -> str:
    pk = pub_from_der(ub64u(receiver_pub_der_b64u))
    return b64u(wrap_key_rsa_oaep(pk, file_key32))  # wrap key


def unwrap_file_key_for_dm(receiver_priv, wrapped_b64u: str) -> bytes:
    return unwrap_key_rsa_oaep(receiver_priv, ub64u(wrapped_b64u))

# ---- Chunk crypto  ---- #


def make_file_chunk_payload(
    key32: bytes,
    file_id: str,
    index: int,
    plaintext_chunk: bytes,
) -> Dict[str, Any]:
    aad = canon({"file_id": file_id, "index": index})
    iv, ct, tag = aesgcm_encrypt(key32, plaintext_chunk, aad)
    return {
        "file_id": file_id,
        "index": index,
        "ciphertext": b64u(ct),
        "iv": b64u(iv),
        "tag": b64u(tag),
    }


def open_file_chunk_payload(
    key32: bytes,
    payload: Dict[str, Any],
) -> bytes:

    aad = canon({"file_id": payload["file_id"], "index": payload["index"]})
    return aesgcm_decrypt(
        key32,
        ub64u(payload["iv"]),
        ub64u(payload["ciphertext"]),
        ub64u(payload["tag"]),
        aad,
    )
