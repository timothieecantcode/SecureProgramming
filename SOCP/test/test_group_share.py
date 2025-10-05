from SOCP.client.crypto_km import gen_rsa_4096, pub_der_b64u
from SOCP.client.crypto_group import make_group_shares, verify_group_shares, unwrap_group_key_for_me

creator = gen_rsa_4096()
alice = gen_rsa_4096()
bob = gen_rsa_4096()

content = make_group_shares(
    creator_priv=creator,
    group_id="group_abc",
    member_pub_map={
        "Alice": pub_der_b64u(alice),
        "Bob":   pub_der_b64u(bob),
    },
)
print("verify shares:", verify_group_shares(content["creator_pub"], content))

gk_alice = unwrap_group_key_for_me(alice, content, "Alice")
gk_bob = unwrap_group_key_for_me(bob,   content, "Bob")
print("same group key for all:", gk_alice == gk_bob, len(gk_alice))
