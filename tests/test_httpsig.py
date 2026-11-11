import base64

import pytest

from grantproof import httpsig
from grantproof.errors import SignatureError
from grantproof.keys import KeySet, SigningKey

URL = "https://notes.example/v1/notes?draft=1"
BODY = b'{"title":"hello"}'
NOW = 1_800_000_000
COMPONENTS = ("@method", "@target-uri", "content-digest", "grant-proof")


def signed(key, **overrides):
    headers = {"Content-Digest": httpsig.content_digest(BODY), "Grant-Proof": "token-value"}
    args = dict(method="POST", url=URL, headers=headers, components=COMPONENTS,
                created=NOW, expires=NOW + 30, tag="grant-proof")
    args.update(overrides)
    headers.update(httpsig.sign_request(key, **args))
    return headers


def verify(key, headers, **overrides):
    args = dict(method="POST", url=URL, headers=headers, body=BODY,
                required_components=COMPONENTS, tag="grant-proof", now=NOW + 1)
    args.update(overrides)
    return httpsig.verify_request(KeySet.of(key), **args)


# -- conformance with the RFCs' own examples --------------------------------


def test_content_digest_matches_rfc_9530_appendix_d():
    assert httpsig.content_digest(b'{"hello": "world"}') == (
        "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
    )


def test_signature_base_verifies_rfc_9421_appendix_b_2_6():
    """The Ed25519 example from RFC 9421, checked with the RFC's test key."""
    keys = KeySet.from_jwks({"keys": [{
        "kty": "OKP", "crv": "Ed25519", "kid": "test-key-ed25519",
        "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
    }]})
    raw = ('("date" "@method" "@path" "@authority" "content-type" "content-length")'
           ';created=1618884473;keyid="test-key-ed25519"')
    components, params = httpsig._parse_signature_params(raw)
    assert params == {"created": 1618884473, "keyid": "test-key-ed25519"}
    base = httpsig._signature_base(
        components, raw, "POST", "https://example.com/foo?param=Value&Pet=dog",
        {"Date": "Tue, 20 Apr 2021 02:07:55 GMT", "Content-Type": "application/json",
         "Content-Length": "18"},
    )
    signature = base64.b64decode(
        "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw=="
    )
    keys.verify("test-key-ed25519", signature, base)


def test_authority_drops_default_port_and_lowercases():
    assert httpsig._authority("https://Example.COM:443/x") == "example.com"
    assert httpsig._authority("http://example.com:8080/x") == "example.com:8080"


# -- round trip and tampering -----------------------------------------------


def test_round_trip():
    key = SigningKey.generate()
    info = verify(key, signed(key))
    assert info.keyid == key.kid and info.tag == "grant-proof" and info.nonce
    assert info.components == COMPONENTS


def test_header_names_are_case_insensitive():
    key = SigningKey.generate()
    verify(key, {name.upper(): value for name, value in signed(key).items()})


@pytest.mark.parametrize("change, code", [
    (dict(body=b'{"title":"HELLO"}'), "digest_mismatch"),
    (dict(method="PUT"), "invalid_signature"),
    (dict(url="https://notes.example/v1/notes?draft=0"), "invalid_signature"),
    (dict(now=NOW + 60), "signature_expired"),
    (dict(now=NOW - 60), "signature_not_yet_valid"),
    (dict(tag="other"), "signature_missing"),
])
def test_any_change_to_the_request_is_rejected(change, code):
    key = SigningKey.generate()
    with pytest.raises(SignatureError) as caught:
        verify(key, signed(key), **change)
    assert caught.value.code == code


def test_swapped_proof_header_is_rejected():
    key = SigningKey.generate()
    headers = signed(key)
    headers["Grant-Proof"] = "another-token"
    with pytest.raises(SignatureError):
        verify(key, headers)


def test_digest_header_rewritten_to_match_new_body_is_rejected():
    key = SigningKey.generate()
    headers = signed(key)
    new_body = b'{"title":"evil"}'
    headers["Content-Digest"] = httpsig.content_digest(new_body)
    with pytest.raises(SignatureError) as caught:
        verify(key, headers, body=new_body)
    assert caught.value.code == "invalid_signature"


def test_signature_from_an_unknown_key_is_rejected():
    key, other = SigningKey.generate(), SigningKey.generate()
    with pytest.raises(SignatureError) as caught:
        verify(other, signed(key))
    assert caught.value.code == "unknown_key"


def test_signature_must_cover_required_components():
    key = SigningKey.generate()
    headers = signed(key, components=("@method", "@target-uri", "content-digest"))
    with pytest.raises(SignatureError) as caught:
        verify(key, headers)
    assert caught.value.code == "signature_incomplete"


def test_overlong_lifetime_is_rejected():
    key = SigningKey.generate()
    with pytest.raises(SignatureError) as caught:
        verify(key, signed(key, expires=NOW + 3600))
    assert caught.value.code == "signature_lifetime"


def test_other_signatures_on_the_request_are_ignored():
    key = SigningKey.generate()
    headers = signed(key)
    headers["Signature-Input"] = 'proxy=("@method");created=1;keyid="a,b";tag="x", ' + headers[
        "Signature-Input"]
    headers["Signature"] = "proxy=:AAAA:, " + headers["Signature"]
    verify(key, headers)
