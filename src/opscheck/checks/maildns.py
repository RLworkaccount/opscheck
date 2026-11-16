"""Mail-related DNS checks: MX, SPF, DKIM and DMARC.

Read-only: these are ordinary DNS lookups. The analyse_* functions are pure
so they can be unit-tested without touching the network.
"""

from __future__ import annotations

import dns.exception
import dns.resolver

# Selectors commonly used by big providers and popular MTAs. Override per call
# if you know the selector(s) your domain uses.
COMMON_DKIM_SELECTORS = [
    "default", "selector1", "selector2", "google", "k1", "s1", "s2",
    "mail", "dkim", "smtp",
]

# Mechanisms/modifiers that count towards SPF's 10-DNS-lookup limit (RFC 7208 4.6.4).
_SPF_LOOKUP_TERMS = ("include:", "a:", "a/", "mx:", "mx/", "ptr:", "exists:", "redirect=")


def _txt(name: str, resolver: dns.resolver.Resolver) -> list[str]:
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    # TXT records can be split into multiple strings; join them back up.
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]


# ---------------------------------------------------------------- analysers

def analyse_spf(txt_records: list[str]) -> dict:
    spf = [r for r in txt_records if r.lower().startswith("v=spf1")]
    out: dict = {"record": None, "status": "ok", "findings": []}
    if not spf:
        out["status"] = "critical"
        out["findings"].append("No SPF record found.")
        return out
    if len(spf) > 1:
        out["status"] = "critical"
        out["findings"].append(
            f"{len(spf)} SPF records found; RFC 7208 requires exactly one (permerror)."
        )
    record = spf[0]
    out["record"] = record
    terms = record.lower().split()[1:]

    lookups = 0
    for t in terms:
        bare = t.lstrip("+-~?")
        if bare in ("a", "mx", "ptr") or bare.startswith(_SPF_LOOKUP_TERMS):
            lookups += 1
    out["dns_lookups_top_level"] = lookups
    if lookups > 10:
        out["status"] = "critical"
        out["findings"].append(f"{lookups} DNS-querying terms; the limit is 10.")
    elif lookups >= 8:
        _bump(out, "warning")
        out["findings"].append(
            f"{lookups} DNS-querying terms at top level; includes can push this past 10."
        )

    if any(t.lstrip("+-~?") == "ptr" for t in terms):
        _bump(out, "warning")
        out["findings"].append("Uses 'ptr', which RFC 7208 says SHOULD NOT be used.")

    all_terms = [t for t in terms if t.lstrip("+-~?") == "all"]
    if not all_terms and not any(t.startswith("redirect=") for t in terms):
        _bump(out, "warning")
        out["findings"].append("No 'all' mechanism; the policy is open-ended.")
    elif all_terms:
        q = all_terms[-1][0] if all_terms[-1][0] in "+-~?" else "+"
        if q == "+":
            out["status"] = "critical"
            out["findings"].append("'+all' authorises every sender on the internet.")
        elif q == "?":
            _bump(out, "warning")
            out["findings"].append("'?all' is neutral and gives receivers nothing to act on.")
        elif q == "~":
            out["findings"].append("'~all' (softfail): fine, '-all' is stricter once you're confident.")
    return out


def analyse_dmarc(txt_records: list[str]) -> dict:
    recs = [r for r in txt_records if r.lower().startswith("v=dmarc1")]
    out: dict = {"record": None, "policy": None, "status": "ok", "findings": []}
    if not recs:
        out["status"] = "critical"
        out["findings"].append("No DMARC record at _dmarc.<domain>.")
        return out
    if len(recs) > 1:
        out["status"] = "critical"
        out["findings"].append("Multiple DMARC records; receivers will ignore them all.")
    record = recs[0]
    out["record"] = record
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "").lower()
    out["policy"] = policy or None
    if policy not in ("none", "quarantine", "reject"):
        out["status"] = "critical"
        out["findings"].append(f"Missing or invalid p= tag ({policy!r}).")
    elif policy == "none":
        _bump(out, "warning")
        out["findings"].append("p=none only monitors; nothing is blocked.")

    pct = tags.get("pct")
    if pct and pct != "100":
        _bump(out, "warning")
        out["findings"].append(f"pct={pct}: policy only applies to part of the mail.")
    if "rua" not in tags:
        _bump(out, "warning")
        out["findings"].append("No rua= address, so you get no aggregate reports.")
    return out


def analyse_mx(hosts: list[tuple[int, str]]) -> dict:
    out: dict = {"records": [{"preference": p, "host": h} for p, h in hosts],
                 "status": "ok", "findings": []}
    if not hosts:
        out["status"] = "warning"
        out["findings"].append("No MX records; senders will fall back to the A record.")
    elif len(hosts) == 1 and hosts[0][1] in (".", ""):
        out["findings"].append("Null MX (RFC 7505): domain explicitly accepts no mail.")
    elif len(hosts) == 1:
        out["findings"].append("Single MX host; no fallback if it is down.")
    return out


_ORDER = {"ok": 0, "info": 0, "warning": 1, "critical": 2}


def _bump(d: dict, status: str) -> None:
    if _ORDER[status] > _ORDER[d["status"]]:
        d["status"] = status


# ---------------------------------------------------------------- live check

def check_mail_dns(
    domain: str,
    dkim_selectors: list[str] | None = None,
    timeout: float = 5.0,
) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    domain = domain.strip().rstrip(".").lower()
    result: dict = {"domain": domain}

    try:
        try:
            mx_answer = resolver.resolve(domain, "MX")
            mx = sorted(
                (r.preference, r.exchange.to_text().rstrip(".") or ".") for r in mx_answer
            )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            mx = []
        result["mx"] = analyse_mx(mx)
        result["spf"] = analyse_spf(_txt(domain, resolver))
        result["dmarc"] = analyse_dmarc(_txt(f"_dmarc.{domain}", resolver))

        selectors = dkim_selectors or COMMON_DKIM_SELECTORS
        found = {}
        for sel in selectors:
            recs = [r for r in _txt(f"{sel}._domainkey.{domain}", resolver)
                    if "p=" in r]
            if recs:
                found[sel] = recs[0][:120] + ("…" if len(recs[0]) > 120 else "")
        dkim = {"selectors_checked": selectors, "found": found, "status": "ok", "findings": []}
        if not found:
            dkim["status"] = "warning"
            dkim["findings"].append(
                "No DKIM key found for the selectors checked. This may just mean the "
                "domain uses a selector not in the list; pass dkim_selectors to check it."
            )
        result["dkim"] = dkim
    except dns.exception.DNSException as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["overall"] = "error"
        return result

    worst = max((result[k]["status"] for k in ("mx", "spf", "dkim", "dmarc")),
                key=lambda s: _ORDER[s])
    result["overall"] = worst
    return result
