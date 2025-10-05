import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---- Sign/ Verify with RSA-PSS ---- #
def sign_pss(sk: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return sk.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256(),)


def verify_pss(pk: rsa.RSAPublicKey, sig: bytes, data: bytes) -> bool:
    try:
        pk.verify(sig, data, padding.PSS(mgf=padding.MGF1(
            hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256(),)
        return True
    except Exception:
        return False


# ---- Wrap/ Unwrap AES key with RSA-OAEP ---- #
def wrap_key_rsa_oaep(pk: rsa.RSAPublicKey, key32: bytes) -> bytes:
    return pk.encrypt(key32, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None,),)


def unwrap_key_rsa_oaep(sk: rsa.RSAPrivateKey, wrapped: bytes) -> bytes:
    return sk.decrypt(wrapped, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),)


# ---- AES-256-GCM ---- #
def aesgcm_encrypt(key32: bytes, plaintext: bytes, aad: bytes):
    """Returns (iv, ciphertext, tag)"""
    assert len(key32) == 32, "AES key must be 256 bits (32 bytes)"
    iv = os.urandom(12)  # random 96-bit initialisation vector
    aesgcm = AESGCM(key32)
    ct_tag = aesgcm.encrypt(iv, plaintext, aad)
    # last 16 bytes = authentication tag, the rest = encrypted ciphertext
    return iv, ct_tag[:-16], ct_tag[-16:]


def aesgcm_decrypt(key32: bytes, iv: bytes, ct: bytes, tag: bytes, aad: bytes) -> bytes:
    assert len(key32) == 32
    aesgcm = AESGCM(key32)
    return aesgcm.decrypt(iv, ct + tag, aad)
