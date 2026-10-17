from api.app import _hash_password,_verify_password


def test_password_hash_is_salted_and_verified():
    one=_hash_password("a-long-local-admin-password")
    two=_hash_password("a-long-local-admin-password")
    assert one!=two
    assert _verify_password("a-long-local-admin-password",one)
    assert not _verify_password("wrong-password",one)
