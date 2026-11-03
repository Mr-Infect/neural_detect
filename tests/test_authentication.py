from uuid import uuid4

from core.authentication.service import decode_token, hash_password, issue_token, verify_password
from core.database.models import User


def test_password_hash_is_salted_and_verifiable() -> None:
    first = hash_password("correct horse battery staple")
    second = hash_password("correct horse battery staple")
    assert first != second
    assert verify_password("correct horse battery staple", first)
    assert not verify_password("incorrect", first)


def test_signed_token_round_trip_and_tamper_rejection() -> None:
    user = User(id=uuid4(), email="phase-test@example.invalid", role="analyst", tenant_id=uuid4())
    token, ttl = issue_token(user, "tenant-a")
    claims = decode_token(token)
    assert ttl > 0
    assert claims["sub"] == str(user.id)
    assert claims["tenant_id"] == "tenant-a"
    try:
        decode_token(token[:-1] + ("A" if token[-1] != "A" else "B"))
    except ValueError:
        pass
    else:
        raise AssertionError("tampered bearer token was accepted")
