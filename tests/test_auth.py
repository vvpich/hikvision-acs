"""Тесты HTTP Digest/Basic, реализованных вручную в alertstream.py."""
from __future__ import annotations

import base64
import re


def _params(header: str) -> dict[str, str]:
    values = {}
    for m in re.finditer(r'(\w+)=(?:"([^"]*)"|([^\s,]+))', header):
        values[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return values


def test_parse_challenge_full(alertstream):
    header = (
        'Digest realm="testrealm@host.com", qop="auth,auth-int", '
        'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
        'opaque="5ccc069c403ebaf9f0171e9517f40e41", algorithm=MD5'
    )
    challenge = alertstream._parse_digest_challenge(header)
    assert challenge.realm == "testrealm@host.com"
    assert challenge.nonce == "dcd98b7102dd2f0e8b11d0f600bfb0c093"
    assert challenge.qop == "auth"  # из списка выбираем поддерживаемый
    assert challenge.opaque == "5ccc069c403ebaf9f0171e9517f40e41"
    assert challenge.algorithm == "MD5"


def test_parse_challenge_without_qop(alertstream):
    challenge = alertstream._parse_digest_challenge('Digest realm="r", nonce="n"')
    assert challenge.qop is None
    assert challenge.opaque is None


def test_digest_response_matches_rfc2617_vector(alertstream, monkeypatch):
    """Эталонный пример из RFC 2617 §3.5."""
    monkeypatch.setattr(alertstream.os, "urandom", lambda n: bytes.fromhex("0a4f113b"))
    challenge = alertstream._DigestChallenge(
        realm="testrealm@host.com",
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        qop="auth",
        opaque=None,
    )
    header = alertstream._build_digest_header(
        "Mufasa", "Circle Of Life", "GET", "/dir/index.html", challenge, nc=1
    )
    values = _params(header)
    assert values["cnonce"] == "0a4f113b"
    assert values["nc"] == "00000001"
    assert values["response"] == "6629fae49393a05397450978507c4ef1"


def test_digest_uri_includes_query_string(alertstream, const):
    """URI в Digest должен совпадать с request-target, вместе с ?format=json."""
    challenge = alertstream._DigestChallenge(realm="r", nonce="n", qop="auth", opaque=None)
    header = alertstream._build_digest_header(
        "u", "p", "GET", const.ALERT_STREAM_PATH, challenge, nc=3
    )
    assert _params(header)["uri"] == const.ALERT_STREAM_PATH
    assert _params(header)["nc"] == "00000003"


def test_digest_md5_sess_differs_from_md5(alertstream, monkeypatch):
    monkeypatch.setattr(alertstream.os, "urandom", lambda n: b"\x00" * n)
    base = alertstream._DigestChallenge(realm="r", nonce="n", qop="auth", opaque=None)
    sess = alertstream._DigestChallenge(
        realm="r", nonce="n", qop="auth", opaque=None, algorithm="MD5-sess"
    )
    plain_header = alertstream._build_digest_header("u", "p", "GET", "/x", base, nc=1)
    sess_header = alertstream._build_digest_header("u", "p", "GET", "/x", sess, nc=1)
    assert _params(plain_header)["response"] != _params(sess_header)["response"]
    assert _params(sess_header)["algorithm"] == "MD5-sess"


def test_opaque_echoed_back(alertstream):
    challenge = alertstream._DigestChallenge(realm="r", nonce="n", qop=None, opaque="op")
    header = alertstream._build_digest_header("u", "p", "GET", "/x", challenge, nc=1)
    assert _params(header)["opaque"] == "op"
    assert "qop" not in _params(header)


def test_basic_header(alertstream):
    header = alertstream._build_basic_header("user", "pa:ss")
    assert header == "Basic " + base64.b64encode(b"user:pa:ss").decode()


def test_digest_preferred_over_basic(alertstream):
    picked = alertstream._pick_challenge(['Basic realm="r"', 'Digest realm="r", nonce="n"'])
    assert picked is not None and picked[0] == "digest"

    picked = alertstream._pick_challenge(['Basic realm="r"'])
    assert picked is not None and picked[0] == "basic"

    assert alertstream._pick_challenge(['Negotiate']) is None
