from __future__ import annotations
import os
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from common.b64url import b64u


# ---- RSAA-4096 generation ---- #
def gen_rsa_4096() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def assert_rsa4096_key(key) -> None:
    size = getattr(key, "key_size", None)
    if size != 4096:
        raise ValueError("RSA key must be 4096 bits")
