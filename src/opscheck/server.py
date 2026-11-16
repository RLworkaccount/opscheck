"""opscheck MCP server.

Exposes read-only infrastructure health checks as MCP tools. Runs over stdio,
so it can be plugged straight into Claude Desktop or any other MCP client.

Note: stdio servers must never print to stdout (it carries the protocol), so
all logging goes to stderr.
"""

from __future__ import annotations

import logging
import re
import sys

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from opscheck.checks.certs import check_certificate
from opscheck.checks.maildns import check_mail_dns as _check_mail_dns

logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("opscheck")

mcp = MCPServer(
    "opscheck",
    instructions="Read-only infrastructure health checks. No tool here changes anything.",
)

# Tells MCP clients these tools never modify anything and talk to external hosts.
READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=True)

# Hostnames (RFC 1123 labels) or IPv4 literals. Keeps junk and injection-ish
# input away from sockets and the resolver.
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
MAX_BULK_TARGETS = 25


def _validate_host(host: str) -> str:
    host = host.strip()
    if not _HOST_RE.match(host):
        raise ValueError(f"Not a valid hostname: {host!r}")
    return host.rstrip(".")


def _validate_port(port: int) -> int:
    if not 1 <= port <= 65535:
        raise ValueError(f"Port out of range: {port}")
    return port


@mcp.tool(annotations=READ_ONLY)
def check_cert_expiry(host: str, port: int = 443, warn_days: int = 30) -> dict:
    """Check the TLS certificate presented by host:port.

    Returns expiry date, days remaining, issuer, SANs, negotiated TLS version
    and whether the chain verifies. Ports 25 and 587 use SMTP STARTTLS
    automatically. Status is one of ok / warning / critical / expired / error.
    Read-only: only performs a TLS handshake.
    """
    host = _validate_host(host)
    port = _validate_port(port)
    log.info("check_cert_expiry %s:%s", host, port)
    return check_certificate(host, port, warn_days=warn_days).to_dict()


@mcp.tool(annotations=READ_ONLY)
def check_cert_expiry_bulk(targets: list[str], warn_days: int = 30) -> dict:
    """Check certificates for several endpoints at once.

    targets: list of "host" or "host:port" strings (max 25). Results are sorted
    so the most urgent (expired, then fewest days left) come first.
    """
    if len(targets) > MAX_BULK_TARGETS:
        raise ValueError(f"Too many targets ({len(targets)}); max {MAX_BULK_TARGETS}.")
    results = []
    for t in targets:
        host, _, port_s = t.strip().partition(":")
        try:
            r = check_certificate(_validate_host(host),
                                  _validate_port(int(port_s or 443)),
                                  warn_days=warn_days).to_dict()
        except ValueError as exc:
            r = {"host": host, "port": port_s or 443, "status": "error", "error": str(exc)}
        results.append(r)

    def urgency(r: dict):
        days = r.get("days_remaining")
        return (r["status"] == "error", days if days is not None else 10**6)

    results.sort(key=urgency)
    summary: dict[str, int] = {}
    for r in results:
        summary[r["status"]] = summary.get(r["status"], 0) + 1
    return {"summary": summary, "results": results}


@mcp.tool(annotations=READ_ONLY)
def check_mail_dns(domain: str, dkim_selectors: list[str] | None = None) -> dict:
    """Audit a domain's mail DNS: MX, SPF, DKIM and DMARC.

    Flags common problems (multiple SPF records, +all, >10 SPF lookups,
    DMARC p=none, missing rua, etc.) with plain-English findings.
    dkim_selectors: optional list of selectors to check; otherwise a set of
    common ones is tried. Read-only: only performs DNS lookups.
    """
    domain = _validate_host(domain)
    log.info("check_mail_dns %s", domain)
    return _check_mail_dns(domain, dkim_selectors)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
