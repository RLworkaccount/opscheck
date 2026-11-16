# opscheck

**Read-only infrastructure health checks for AI agents, exposed as an [MCP](https://modelcontextprotocol.io) server.**

Ask Claude (or any MCP client) things like:

> "Which of these endpoints have certificates expiring in the next 30 days?"
> "Is the mail DNS for example.co.uk set up properly?"
> "Does mail.example.com offer STARTTLS on 25, and what TLS version does it negotiate?"

…and it answers using real checks rather than guessing.

<img width="907" height="869" alt="image" src="https://github.com/user-attachments/assets/c89150e8-21af-43f6-9181-522ee30fea5a" />


## Why read-only?

Giving an AI agent access to production is risky. Every tool in opscheck is
**observe-only by design**: it performs a TLS handshake or DNS lookup and
nothing else. Each tool is also marked with MCP's `readOnlyHint` /
`destructiveHint=false` annotations so clients can see that it is safe to call.
Inputs are validated (hostname format, port range, bulk limits) before anything
touches the network.

The aim is to have the agent do the tedious checking while a human still makes
and carries out any changes.

## Tools

| Tool | What it does |
|---|---|
| `check_cert_expiry(host, port=443, warn_days=30)` | Expiry, days remaining, issuer, SANs, TLS version, chain verification. Ports 25/587 automatically use SMTP STARTTLS. |
| `check_cert_expiry_bulk(targets, warn_days=30)` | Up to 25 `host[:port]` targets, sorted most-urgent first, with a status summary. |
| `check_mail_dns(domain, dkim_selectors=None)` | MX, SPF, DKIM and DMARC audit with plain-English findings (multiple SPF records, `+all`, >10 SPF lookups, `p=none`, missing `rua`, etc.). |

Statuses: `ok` · `warning` · `critical` · `expired` · `error`.

## Quick start (Windows)

```powershell
cd E:\Claude\opscheck
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest
```

Requires Python 3.11+.

### Try it with the MCP Inspector

```powershell
npx @modelcontextprotocol/inspector .\.venv\Scripts\python.exe -m opscheck.server
```

### Connect it to Claude Desktop

Add this to `%APPDATA%\Claude\claude_desktop_config.json` (see
`claude_desktop_config.example.json`), then restart Claude Desktop:

```json
{
  "mcpServers": {
    "opscheck": {
      "command": "E:\\Claude\\opscheck\\.venv\\Scripts\\python.exe",
      "args": ["-m", "opscheck.server"]
    }
  }
}
```

## Project layout

```
src/opscheck/
  server.py          MCP server: tool definitions + input validation
  checks/certs.py    TLS / STARTTLS certificate checks
  checks/maildns.py  MX / SPF / DKIM / DMARC lookups + pure analysers
tests/               Unit tests for analysers and validation (no network needed)
```

The analysis logic is kept separate from the network calls, so it can be
tested offline.

## Roadmap

- [x] TLS certificate expiry (HTTPS + SMTP STARTTLS)
- [x] Mail DNS audit (MX, SPF, DKIM, DMARC)
- [ ] `check_smtp`: banner, EHLO extensions, STARTTLS, TLS version
- [ ] Windows checks via PowerShell: pending updates, last patch date, service status
- [ ] Postfix queue stats from a RHEL host
- [ ] Container image + GitHub Actions CI
- [ ] Run against a self-hosted open model as part of a private AI stack

## Licence

MIT
