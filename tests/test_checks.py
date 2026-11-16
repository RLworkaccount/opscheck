from datetime import datetime, timedelta, timezone

import pytest

from opscheck.checks.certs import assess_expiry
from opscheck.checks.maildns import analyse_dmarc, analyse_mx, analyse_spf
from opscheck.server import _validate_host

NOW = datetime(2026, 11, 16, tzinfo=timezone.utc)


@pytest.mark.parametrize("days,expected", [
    (90, "ok"), (30, "warning"), (8, "warning"), (7, "critical"), (1, "critical"),
])
def test_assess_expiry(days, expected):
    status, remaining = assess_expiry(NOW + timedelta(days=days), now=NOW)
    assert status == expected
    assert remaining == days


def test_assess_expiry_expired():
    status, remaining = assess_expiry(NOW - timedelta(days=3), now=NOW)
    assert status == "expired"
    assert remaining < 0


def test_spf_missing():
    assert analyse_spf(["google-site-verification=abc"])["status"] == "critical"


def test_spf_multiple_records():
    r = analyse_spf(["v=spf1 -all", "v=spf1 mx -all"])
    assert r["status"] == "critical"


def test_spf_plus_all():
    assert analyse_spf(["v=spf1 +all"])["status"] == "critical"


def test_spf_good():
    r = analyse_spf(["v=spf1 mx include:_spf.google.com -all"])
    assert r["status"] == "ok"
    assert r["dns_lookups_top_level"] == 2


def test_spf_too_many_lookups():
    incs = " ".join(f"include:s{i}.example.com" for i in range(11))
    assert analyse_spf([f"v=spf1 {incs} -all"])["status"] == "critical"


def test_dmarc_missing():
    assert analyse_dmarc([])["status"] == "critical"


def test_dmarc_none_policy():
    r = analyse_dmarc(["v=DMARC1; p=none; rua=mailto:d@example.com"])
    assert r["status"] == "warning"
    assert r["policy"] == "none"


def test_dmarc_reject_good():
    r = analyse_dmarc(["v=DMARC1; p=reject; rua=mailto:d@example.com"])
    assert r["status"] == "ok"


def test_mx_none():
    assert analyse_mx([])["status"] == "warning"


@pytest.mark.parametrize("bad", ["", "foo bar", "-bad.com", "a;rm -rf /", "x" * 300])
def test_validate_host_rejects(bad):
    with pytest.raises(ValueError):
        _validate_host(bad)


def test_validate_host_accepts():
    assert _validate_host("mail.example.co.uk.") == "mail.example.co.uk"
