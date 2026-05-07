# ActionLoggR

**A complete DNS and network audit trail for every GitHub Actions run.**

ActionLoggR is a GitHub Composite Action that records every domain queried and every outbound connection made during your CI pipeline. The log is saved as a workflow artifact — so when a supply chain compromise is disclosed weeks later, you can look back at every run and know immediately whether your pipeline called out to an affected domain.

No infrastructure. No secrets. One step.

---

## The problem it solves

Supply chain compromises are rarely discovered in real time. The typical scenario:

1. A GitHub Action or npm package is compromised
2. Your pipeline runs it for days or weeks without incident
3. The compromise is publicly disclosed — by a researcher, a vendor, or a CISA advisory
4. You now need to answer: **did any of our runs talk to that domain?**

Without ActionLoggR, the answer requires digging through raw runner logs hoping someone printed a curl command. With ActionLoggR, the answer is a single search across structured JSON artifacts that were saved automatically on every run.

---

## What it records

Every run produces a `report.json` artifact containing:

- **`all_domains`** — every domain queried, deduplicated, across DNS, TLS SNI, and reverse-DNS
- **`all_ips`** — every non-private IP address contacted
- **`events`** — the raw event stream showing which capture source saw each domain
- **`ioc_matches`** — any matches against an optional threat intel list you provide at run time

The artifact also includes `dns.log` (timestamped, one domain per line) and the raw `capture.pcap` — both preserved for the duration of your retention window.

---

## Retroactive investigation

When a domain is later identified as malicious, checking your history is straightforward:

**Search the JSON report for a specific domain:**
```bash
cat report.json | python3 -m json.tool | grep "suspicious-domain.com"
```

**Search across all downloaded artifacts at once:**
```bash
grep -r "suspicious-domain.com" ./artifacts/*/report.json
```

**Re-run IoC matching against a saved artifact** (no runner required):
```bash
python3 scripts/report.py \
  --output-dir ./downloaded-artifact \
  --ioc-list "newly-disclosed-c2.com" \
  --report-all true
```

This works because the artifact contains the raw `dns.log` and `capture.pcap` — the reporter re-parses them with your new IoC list and produces a fresh report.

---

## When to implement it

- **You use third-party Actions** — any `uses: some-org/some-action@v2` is code you don't control running with access to your secrets
- **Your workflows handle credentials** — `GITHUB_TOKEN`, cloud IAM roles, npm tokens, signing keys
- **You want retroactive blast-radius analysis** — when a compromise is disclosed, know within minutes whether you were affected and during which runs
- **You work in a regulated environment** — SOC 2, FedRAMP, and ISO 27001 all require evidence that you can detect and scope unauthorized data egress
- **You don't know what your CI talks to** — ActionLoggR answers that question on the first run

---

## Quickstart

Add ActionLoggR as the **first step** in your job (before checkout), and add the artifact upload step at the end.

**No `permissions` block is required for basic usage.** See [Permissions](#permissions) below.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Start ActionLoggR
        uses: drewklauser/ActionLoggR@main

      - uses: actions/checkout@v4
      # ... rest of your build

      # Required: upload the report so it survives after the job ends.
      # Without this step, the report files are deleted when the runner
      # is recycled and cannot be retrieved.
      - name: Upload ActionLoggR report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: actionloggr-${{ github.run_id }}
          path: /tmp/actionloggr/
          retention-days: 90
```

ActionLoggR writes its report to `/tmp/actionloggr/` on the runner. That directory only exists for the lifetime of the job — **the `upload-artifact` step is what makes the report accessible after the run.** Once uploaded, the artifact appears under the run summary in the Actions UI and can be downloaded for retroactive investigation.

---

## Permissions

ActionLoggR requires **no additional permissions** for a standard run. The default `GITHUB_TOKEN` permissions are sufficient to capture traffic, generate the report, and upload it as a workflow artifact.

Two optional features require elevated permissions:

| Feature | Permission needed |
|---|---|
| Upload IoC matches to the GitHub Security tab (SARIF) | `security-events: write` |
| Authenticate webhook delivery with an OIDC token | `id-token: write` |

If you are using either of those features, add only the permissions you need:

```yaml
permissions:
  contents: read
  security-events: write # only if you want findings in the GitHub Security tab
  id-token: write        # only if you are using webhook-url with OIDC auth
```

Omit the `permissions` block entirely if you are not using those features.

---

## Adding real-time IoC matching

If you have a threat intel feed, you can match against it at run time. Matches are flagged in the Actions log, uploaded to the GitHub Security tab as SARIF alerts, and can optionally fail the job.

```yaml
- name: Start ActionLoggR
  uses: drewklauser/ActionLoggR@main
  with:
    # Comma-separated, or a URL to a newline-delimited blocklist:
    ioc-list: 'https://raw.githubusercontent.com/my-org/threat-intel/main/ci-iocs.txt'
    fail-on-match: 'true'
```

IoC matching is optional. The audit trail is always written regardless.

---

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `ioc-list` | No | — | Comma-separated domains/IPs **or** a URL to a newline-delimited blocklist file |
| `fail-on-match` | No | `false` | Exit the job with an error if any IoC is matched |
| `report-all-traffic` | No | `true` | Include all observed domains and IPs in the report, not just matches |
| `webhook-url` | No | — | HTTPS endpoint to receive the JSON report (authenticated via OIDC) |
| `capture-filter` | No | — | Custom BPF filter to narrow tcpdump scope |
| `output-dir` | No | `/tmp/actionloggr` | Directory for report files |

## Outputs

| Output | Description |
|---|---|
| `report-path` | Absolute path to the JSON report |
| `sarif-path` | Absolute path to the SARIF file |
| `ioc-matches` | Count of IoC matches found |

---

## Report format

```json
{
  "generated_at": "2025-04-15T14:23:01Z",
  "run_id": "12345678",
  "run_url": "https://github.com/my-org/my-repo/actions/runs/12345678",
  "repository": "my-org/my-repo",
  "workflow": "CI",
  "all_domains": [
    "api.github.com",
    "registry.npmjs.org",
    "objects.githubusercontent.com"
  ],
  "all_ips": ["140.82.121.4", "104.16.99.52"],
  "ioc_matches": [],
  "events": [
    {
      "src_ip": "10.0.0.2",
      "dst_ip": "140.82.121.4",
      "dst_port": 443,
      "protocol": "TCP/TLS",
      "domain": "api.github.com",
      "source": "sni"
    }
  ]
}
```

`all_domains` is the primary field for retroactive lookups. `events` provides the raw source trace — which capture method saw the domain and on which IP and port.

---

## Sending reports to your SIEM

ActionLoggR can POST the JSON report to any HTTPS endpoint, authenticated with a GitHub Actions OIDC token. Your receiver can verify the token's `sub` claim to confirm the request came from a specific repository and workflow — no long-lived secrets required.

```yaml
- uses: drewklauser/ActionLoggR@main
  with:
    webhook-url: ${{ secrets.SIEM_INGEST_URL }}
```

---

## GitHub Security tab integration

When IoC matches are found, ActionLoggR uploads a SARIF file to the GitHub Security tab via `github/codeql-action/upload-sarif`. Findings appear as code scanning alerts without requiring access to raw workflow logs. Requires `security-events: write` permission.

---

## Full example

See [`example/workflow.yml`](example/workflow.yml) for a complete working workflow with correct step ordering, output consumption, artifact upload, and annotated notes on which permissions are needed for which optional features.

---

## How it works

```
Runner boot
    │
    ▼
monitor-start.sh
    ├── tcpdump -w capture.pcap     (full packet capture)
    ├── tcpdump → awk → dns.log     (DNS query text log, one domain per line)
    ├── conntrack -E NEW            (new connection events)
    └── iptables LOG + dmesg tail   (kernel connection log)
    │
    ▼
[ Your build steps run here ]
    │
    ▼  (always, even on failure)
monitor-stop.sh → report.py
    ├── parse pcap → extract TLS SNI from ClientHello bytes
    ├── parse pcap → extract DNS queries (Scapy if available, raw parser fallback)
    ├── parse dns.log, conntrack.log, iptables.log
    ├── deduplicate domains + IPs, reverse-DNS uncategorised IPs
    ├── match against IoC list (if provided)
    ├── write report.json + results.sarif
    ├── emit ::warning:: annotations for any matches
    └── POST to webhook with OIDC token (if configured)
```

**TLS SNI extraction** works without decryption. The TLS `ClientHello` message contains the destination hostname in plaintext — ActionLoggR reads it from raw packet bytes. This gives HTTPS destination visibility without a MITM proxy or certificate.

---

## Requirements

- GitHub-hosted **ubuntu** runner (any size)
- No additional `permissions` required for basic usage (see [Permissions](#permissions))

ActionLoggR installs `tcpdump`, `conntrack`, and optionally `scapy` at runtime. Setup typically takes under 15 seconds.

---

## Limitations

- **Linux only** — `tcpdump`, `iptables`, and `conntrack` are Linux primitives. macOS and Windows runners are not supported.
- **Observer, not enforcer** — ActionLoggR records and reports. It does not block connections. Use `fail-on-match: true` to halt the job after egress is detected, but the connection will have already been made.
- **Destination visibility only** — SNI reveals where traffic went, not what was sent. ActionLoggR cannot tell you whether secrets were included in a request.
- **Retention window** — retroactive investigation depends on artifacts being within their retention window. Set `retention-days` to match your incident response SLA.

---

## Contributing

Issues and PRs welcome. Areas of particular interest:

- Additional IoC feed integrations (MISP, OpenCTI, Abuse.ch URLhaus)
- Egress allowlist mode (flag anything *not* on an approved list)
- Support for self-hosted runner environments with pre-installed tooling
- Webhook receiver reference implementation

---

## License

MIT
