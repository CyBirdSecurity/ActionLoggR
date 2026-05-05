#!/usr/bin/env python3
"""
report.py — parse captured pcap/logs, extract TLS SNI + DNS queries + IPs,
match against IoC list, write JSON report and SARIF file, optionally POST
to a webhook authenticated with a GitHub Actions OIDC token.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

# ── Scapy is an optional heavy dependency; fall back to raw pcap parsing ──────
try:
    from scapy.all import rdpcap, TCP, UDP, IP, IPv6, Raw, DNS, DNSQR  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class NetworkEvent:
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    domain: Optional[str] = None       # from SNI or DNS
    source: str = "unknown"            # "sni", "dns", "conntrack", "iptables"
    timestamp: Optional[str] = None


@dataclass
class Report:
    generated_at: str
    run_id: str
    run_url: str
    repository: str
    workflow: str
    all_domains: list[str] = field(default_factory=list)
    all_ips: list[str] = field(default_factory=list)
    ioc_matches: list[dict] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# TLS SNI extraction (raw bytes, no decryption needed)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_sni_from_payload(payload: bytes) -> Optional[str]:
    """
    Parse a TLS ClientHello handshake message and extract the SNI hostname.
    Returns None if the payload is not a valid ClientHello or has no SNI.

    TLS record layer:
      byte 0      : content type (0x16 = handshake)
      bytes 1-2   : legacy version
      bytes 3-4   : record length
    Handshake header:
      byte 5      : handshake type (0x01 = ClientHello)
      bytes 6-8   : handshake length (3 bytes, big-endian)
    ClientHello body:
      bytes 9-10  : client_version
      bytes 11-42 : random (32 bytes)
      byte 43     : session_id length
      ...
    """
    try:
        if len(payload) < 5:
            return None
        if payload[0] != 0x16:          # not a TLS handshake record
            return None
        if payload[5] != 0x01:          # not a ClientHello
            return None

        # skip record header (5) + handshake header (4) + client_version (2) + random (32)
        pos = 5 + 4 + 2 + 32

        if pos >= len(payload):
            return None

        # session ID
        session_id_len = payload[pos]
        pos += 1 + session_id_len

        if pos + 2 > len(payload):
            return None

        # cipher suites
        cipher_suites_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2 + cipher_suites_len

        if pos + 1 > len(payload):
            return None

        # compression methods
        compression_len = payload[pos]
        pos += 1 + compression_len

        if pos + 2 > len(payload):
            return None

        # extensions length
        extensions_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        end = pos + extensions_len

        while pos + 4 <= end and pos + 4 <= len(payload):
            ext_type = int.from_bytes(payload[pos:pos + 2], "big")
            ext_len  = int.from_bytes(payload[pos + 2:pos + 4], "big")
            pos += 4

            if ext_type == 0x0000:   # server_name extension
                # SNI list length (2), entry type (1), name length (2)
                if pos + 5 > len(payload):
                    break
                name_len = int.from_bytes(payload[pos + 3:pos + 5], "big")
                name_start = pos + 5
                if name_start + name_len > len(payload):
                    break
                return payload[name_start:name_start + name_len].decode("ascii", errors="replace")

            pos += ext_len

    except Exception:
        pass
    return None


def extract_sni_scapy(pcap_path: Path) -> list[NetworkEvent]:
    events: list[NetworkEvent] = []
    try:
        packets = rdpcap(str(pcap_path))
    except Exception as exc:
        return events

    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue
        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            continue

        raw = bytes(pkt[Raw])
        sni = _extract_sni_from_payload(raw)
        if sni is None:
            continue

        ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        events.append(NetworkEvent(
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            dst_port=pkt[TCP].dport,
            protocol="TCP/TLS",
            domain=sni,
            source="sni",
        ))

    return events


def extract_sni_raw(pcap_path: Path) -> list[NetworkEvent]:
    """
    Minimal pcap parser — reads global header, then each packet record,
    extracts IP/TCP layers, attempts SNI extraction.  No external libs required.
    """
    events: list[NetworkEvent] = []
    try:
        data = pcap_path.read_bytes()
    except Exception:
        return events

    if len(data) < 24:
        return events

    magic = int.from_bytes(data[0:4], "little")
    if magic == 0xA1B2C3D4:
        endian = "little"
    elif magic == 0xD4C3B2A1:
        endian = "big"
    else:
        return events

    # global header is 24 bytes
    pos = 24

    while pos + 16 <= len(data):
        # packet record header: ts_sec(4) ts_usec(4) incl_len(4) orig_len(4)
        incl_len = int.from_bytes(data[pos + 8:pos + 12], endian)
        pos += 16

        if pos + incl_len > len(data):
            break

        pkt = data[pos:pos + incl_len]
        pos += incl_len

        # Ethernet: 14 bytes header, ethertype at bytes 12-13
        if len(pkt) < 14:
            continue
        ethertype = int.from_bytes(pkt[12:14], "big")

        if ethertype == 0x0800:         # IPv4
            ip_start = 14
            if len(pkt) < ip_start + 20:
                continue
            ihl = (pkt[ip_start] & 0x0F) * 4
            proto = pkt[ip_start + 9]
            src_ip = ".".join(str(b) for b in pkt[ip_start + 12:ip_start + 16])
            dst_ip = ".".join(str(b) for b in pkt[ip_start + 16:ip_start + 20])
            tcp_start = ip_start + ihl
        elif ethertype == 0x86DD:       # IPv6
            ip_start = 14
            if len(pkt) < ip_start + 40:
                continue
            proto = pkt[ip_start + 6]
            src_ip = _fmt_ipv6(pkt[ip_start + 8:ip_start + 24])
            dst_ip = _fmt_ipv6(pkt[ip_start + 24:ip_start + 40])
            tcp_start = ip_start + 40
        else:
            continue

        if proto != 6:                  # not TCP
            continue

        if len(pkt) < tcp_start + 20:
            continue
        dport = int.from_bytes(pkt[tcp_start + 2:tcp_start + 4], "big")
        data_offset = ((pkt[tcp_start + 12] >> 4) * 4)
        payload_start = tcp_start + data_offset

        if payload_start >= len(pkt):
            continue

        payload = pkt[payload_start:]
        sni = _extract_sni_from_payload(payload)
        if sni:
            events.append(NetworkEvent(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dport,
                protocol="TCP/TLS",
                domain=sni,
                source="sni",
            ))

    return events


def _fmt_ipv6(raw: bytes) -> str:
    return ":".join(f"{raw[i]:02x}{raw[i+1]:02x}" for i in range(0, 16, 2))


# ─────────────────────────────────────────────────────────────────────────────
# DNS log parser
# ─────────────────────────────────────────────────────────────────────────────

def extract_dns_from_log(dns_log: Path) -> list[NetworkEvent]:
    events: list[NetworkEvent] = []
    if not dns_log.exists():
        return events
    for line in dns_log.read_text(errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[-1].rstrip(".")
            if domain:
                events.append(NetworkEvent(
                    src_ip="",
                    dst_ip="",
                    dst_port=53,
                    protocol="DNS",
                    domain=domain,
                    source="dns",
                    timestamp=parts[0],
                ))
    return events


def extract_dns_from_pcap_scapy(pcap_path: Path) -> list[NetworkEvent]:
    events: list[NetworkEvent] = []
    if not SCAPY_AVAILABLE:
        return events
    try:
        packets = rdpcap(str(pcap_path))
    except Exception:
        return events
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # query
            for i in range(pkt[DNS].qdcount):
                try:
                    qname = pkt[DNS].qd.qname.decode().rstrip(".")
                    ip_layer = pkt[IP] if pkt.haslayer(IP) else (pkt[IPv6] if pkt.haslayer(IPv6) else None)
                    events.append(NetworkEvent(
                        src_ip=ip_layer.src if ip_layer else "",
                        dst_ip=ip_layer.dst if ip_layer else "",
                        dst_port=53,
                        protocol="DNS",
                        domain=qname,
                        source="dns",
                    ))
                except Exception:
                    pass
    return events


# ─────────────────────────────────────────────────────────────────────────────
# conntrack / iptables log parsers
# ─────────────────────────────────────────────────────────────────────────────

_CONNTRACK_RE = re.compile(
    r"(?P<proto>tcp|udp)\s+\d+\s+\d+\s+.*?src=(?P<src>[\d.]+).*?dst=(?P<dst>[\d.]+).*?dport=(?P<dport>\d+)"
)

def extract_conntrack(conntrack_log: Path) -> list[NetworkEvent]:
    events: list[NetworkEvent] = []
    if not conntrack_log.exists():
        return events
    for line in conntrack_log.read_text(errors="replace").splitlines():
        m = _CONNTRACK_RE.search(line)
        if m:
            events.append(NetworkEvent(
                src_ip=m.group("src"),
                dst_ip=m.group("dst"),
                dst_port=int(m.group("dport")),
                protocol=m.group("proto").upper(),
                source="conntrack",
            ))
    return events


_IPTABLES_SRC_RE = re.compile(r"SRC=([\d.a-fA-F:]+)")
_IPTABLES_DST_RE = re.compile(r"DST=([\d.a-fA-F:]+)")
_IPTABLES_DPT_RE = re.compile(r"DPT=(\d+)")
_IPTABLES_PROTO_RE = re.compile(r"PROTO=(\w+)")

def extract_iptables(iptables_log: Path) -> list[NetworkEvent]:
    events: list[NetworkEvent] = []
    if not iptables_log.exists():
        return events
    for line in iptables_log.read_text(errors="replace").splitlines():
        if "ACTIONLOGGR_OUT" not in line:
            continue
        src  = (_IPTABLES_SRC_RE.search(line) or type("", (), {"group": lambda *_: ""})()).group(1)
        dst  = (_IPTABLES_DST_RE.search(line) or type("", (), {"group": lambda *_: ""})()).group(1)
        dpt  = (_IPTABLES_DPT_RE.search(line) or type("", (), {"group": lambda *_: "0"})()).group(1)
        prot = (_IPTABLES_PROTO_RE.search(line) or type("", (), {"group": lambda *_: "UNKNOWN"})()).group(1)
        if dst:
            events.append(NetworkEvent(
                src_ip=src,
                dst_ip=dst,
                dst_port=int(dpt),
                protocol=prot,
                source="iptables",
            ))
    return events


# ─────────────────────────────────────────────────────────────────────────────
# IoC list loading
# ─────────────────────────────────────────────────────────────────────────────

def load_ioc_list(ioc_input: str) -> set[str]:
    """
    Accept comma-separated values, or a URL to a newline-delimited text file.
    Strips whitespace, lowercases, drops blank lines and comments (#).
    """
    iocs: set[str] = set()
    if not ioc_input.strip():
        return iocs

    if ioc_input.startswith("http://") or ioc_input.startswith("https://"):
        try:
            with urllib.request.urlopen(ioc_input, timeout=10) as resp:
                content = resp.read().decode("utf-8", errors="replace")
            lines = content.splitlines()
        except Exception as exc:
            print(f"[actionloggr] Warning: could not fetch IoC list from {ioc_input}: {exc}", file=sys.stderr)
            lines = []
    else:
        lines = ioc_input.replace(",", "\n").splitlines()

    for line in lines:
        entry = line.strip().lower().lstrip("*.")
        if entry and not entry.startswith("#"):
            iocs.add(entry)

    return iocs


# ─────────────────────────────────────────────────────────────────────────────
# Reverse DNS
# ─────────────────────────────────────────────────────────────────────────────

_rdns_cache: dict[str, str] = {}

def reverse_dns(ip: str) -> Optional[str]:
    if not ip:
        return None
    if ip in _rdns_cache:
        return _rdns_cache[ip]
    try:
        # skip private/loopback
        parsed = ipaddress.ip_address(ip)
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
            _rdns_cache[ip] = None
            return None
        hostname = socket.gethostbyaddr(ip)[0]
        _rdns_cache[ip] = hostname
        return hostname
    except Exception:
        _rdns_cache[ip] = None
        return None


# ─────────────────────────────────────────────────────────────────────────────
# IoC matching
# ─────────────────────────────────────────────────────────────────────────────

def _domain_matches_ioc(domain: str, ioc: str) -> bool:
    """Exact match or suffix match (ioc is a parent domain)."""
    d = domain.lower().rstrip(".")
    return d == ioc or d.endswith("." + ioc)


def match_iocs(events: list[NetworkEvent], iocs: set[str]) -> list[dict]:
    if not iocs:
        return []
    matches: list[dict] = []
    seen: set[str] = set()

    for ev in events:
        for ioc in iocs:
            key = None

            # domain match
            if ev.domain and _domain_matches_ioc(ev.domain, ioc):
                key = f"domain:{ev.domain}:{ioc}"
                if key not in seen:
                    seen.add(key)
                    matches.append({
                        "ioc": ioc,
                        "match_type": "domain",
                        "observed_value": ev.domain,
                        "dst_ip": ev.dst_ip,
                        "dst_port": ev.dst_port,
                        "source": ev.source,
                    })

            # IP match
            if ev.dst_ip and ev.dst_ip.lower() == ioc:
                key = f"ip:{ev.dst_ip}:{ioc}"
                if key not in seen:
                    seen.add(key)
                    matches.append({
                        "ioc": ioc,
                        "match_type": "ip",
                        "observed_value": ev.dst_ip,
                        "dst_port": ev.dst_port,
                        "source": ev.source,
                    })

            # reverse-DNS of dst_ip
            if ev.dst_ip:
                rdns = reverse_dns(ev.dst_ip)
                if rdns and _domain_matches_ioc(rdns, ioc):
                    key = f"rdns:{ev.dst_ip}:{ioc}"
                    if key not in seen:
                        seen.add(key)
                        matches.append({
                            "ioc": ioc,
                            "match_type": "reverse_dns",
                            "observed_value": rdns,
                            "dst_ip": ev.dst_ip,
                            "dst_port": ev.dst_port,
                            "source": ev.source,
                        })

    return matches


# ─────────────────────────────────────────────────────────────────────────────
# SARIF output
# ─────────────────────────────────────────────────────────────────────────────

SARIF_TEMPLATE = {
    "version": "2.1.0",
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "runs": [{
        "tool": {
            "driver": {
                "name": "ActionLoggR",
                "version": "1.0.0",
                "informationUri": "https://github.com/drewklauser/ActionLoggR",
                "rules": []
            }
        },
        "results": []
    }]
}

def build_sarif(ioc_matches: list[dict], all_domains: list[str], run_url: str) -> dict:
    sarif = json.loads(json.dumps(SARIF_TEMPLATE))
    run = sarif["runs"][0]

    rules_seen: set[str] = set()

    for match in ioc_matches:
        rule_id = f"ACTIONLOGGR-IOC/{match['ioc']}"
        if rule_id not in rules_seen:
            rules_seen.add(rule_id)
            run["tool"]["driver"]["rules"].append({
                "id": rule_id,
                "name": "IoC_Match",
                "shortDescription": {"text": f"Egress traffic matched IoC: {match['ioc']}"},
                "fullDescription": {"text": (
                    f"Outbound network traffic matched the known Indicator of Compromise "
                    f"'{match['ioc']}'. This may indicate a supply chain compromise."
                )},
                "defaultConfiguration": {"level": "error"},
                "helpUri": "https://github.com/drewklauser/ActionLoggR",
                "properties": {"tags": ["supply-chain", "network-egress"]},
            })

        run["results"].append({
            "ruleId": rule_id,
            "level": "error",
            "message": {
                "text": (
                    f"IoC match: {match['match_type']} '{match['observed_value']}' "
                    f"→ '{match['ioc']}' (port {match.get('dst_port', '?')}, "
                    f"via {match['source']})"
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": run_url or "github-actions://runner"},
                    "region": {"startLine": 1}
                }
            }],
            "properties": match,
        })

    return sarif


# ─────────────────────────────────────────────────────────────────────────────
# GitHub Actions OIDC token
# ─────────────────────────────────────────────────────────────────────────────

def get_oidc_token(audience: str = "actionloggr") -> Optional[str]:
    request_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not request_url or not request_token:
        return None
    try:
        url = f"{request_url}&audience={audience}"
        req = urllib.request.Request(url, headers={"Authorization": f"bearer {request_token}"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
            return body.get("value")
    except Exception as exc:
        print(f"[actionloggr] Warning: could not obtain OIDC token: {exc}", file=sys.stderr)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Webhook delivery
# ─────────────────────────────────────────────────────────────────────────────

def post_to_webhook(webhook_url: str, report: dict, oidc_token: Optional[str]) -> None:
    payload = json.dumps(report).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "ActionLoggR/1.0",
    }
    if oidc_token:
        headers["Authorization"] = f"Bearer {oidc_token}"

    try:
        req = urllib.request.Request(webhook_url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = resp.status
        print(f"[actionloggr] Webhook delivery status: {status}", file=sys.stderr)
    except Exception as exc:
        print(f"[actionloggr] Warning: webhook delivery failed: {exc}", file=sys.stderr)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="ActionLoggR report generator")
    parser.add_argument("--output-dir", default="/tmp/actionloggr")
    parser.add_argument("--ioc-list", default="")
    parser.add_argument("--webhook", default="")
    parser.add_argument("--report-all", default="true")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    report_all = args.report_all.lower() not in ("false", "0", "no")

    run_id        = os.environ.get("GITHUB_RUN_ID", "")
    run_url       = os.environ.get("GITHUB_SERVER_URL", "https://github.com") + \
                    "/" + os.environ.get("GITHUB_REPOSITORY", "") + \
                    "/actions/runs/" + run_id
    repository    = os.environ.get("GITHUB_REPOSITORY", "")
    workflow      = os.environ.get("GITHUB_WORKFLOW", "")

    errors: list[str] = []

    # ── gather events ──────────────────────────────────────────────────────
    events: list[NetworkEvent] = []

    pcap_path = output_dir / "capture.pcap"
    if pcap_path.exists() and pcap_path.stat().st_size > 0:
        if SCAPY_AVAILABLE:
            events += extract_sni_scapy(pcap_path)
            events += extract_dns_from_pcap_scapy(pcap_path)
        else:
            events += extract_sni_raw(pcap_path)

    events += extract_dns_from_log(output_dir / "dns.log")
    events += extract_conntrack(output_dir / "conntrack.log")
    events += extract_iptables(output_dir / "iptables.log")

    # ── deduplicate domains and IPs ────────────────────────────────────────
    all_domains: list[str] = sorted({ev.domain for ev in events if ev.domain})
    ip_set: set[str] = set()
    for ev in events:
        if ev.dst_ip:
            try:
                parsed = ipaddress.ip_address(ev.dst_ip)
                if not parsed.is_private and not parsed.is_loopback:
                    ip_set.add(ev.dst_ip)
            except ValueError:
                pass

    # ── reverse DNS for IPs not already associated with a domain ──────────
    known_ips = {ev.dst_ip for ev in events if ev.domain}
    for ip in ip_set - known_ips:
        rdns = reverse_dns(ip)
        if rdns:
            all_domains.append(rdns)

    all_domains = sorted(set(all_domains))
    all_ips     = sorted(ip_set)

    # ── IoC matching ───────────────────────────────────────────────────────
    iocs = load_ioc_list(args.ioc_list)
    ioc_matches = match_iocs(events, iocs)

    if ioc_matches:
        print(f"[actionloggr] !! {len(ioc_matches)} IoC match(es) found !!", file=sys.stderr)
        for m in ioc_matches:
            print(f"[actionloggr]   {m['match_type']} | {m['observed_value']} → {m['ioc']}", file=sys.stderr)

    # ── build report ───────────────────────────────────────────────────────
    report = Report(
        generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        run_id=run_id,
        run_url=run_url,
        repository=repository,
        workflow=workflow,
        all_domains=all_domains if report_all else [],
        all_ips=all_ips if report_all else [],
        ioc_matches=ioc_matches,
        events=[asdict(ev) for ev in events] if report_all else [],
        errors=errors,
    )

    report_dict = asdict(report)

    # write JSON
    report_path = output_dir / "report.json"
    report_path.write_text(json.dumps(report_dict, indent=2))
    print(f"[actionloggr] JSON report: {report_path}", file=sys.stderr)

    # write SARIF
    sarif = build_sarif(ioc_matches, all_domains, run_url)
    sarif_path = output_dir / "results.sarif"
    sarif_path.write_text(json.dumps(sarif, indent=2))
    print(f"[actionloggr] SARIF report: {sarif_path}", file=sys.stderr)

    # emit GitHub Actions annotations for matches
    for m in ioc_matches:
        print(
            f"::warning title=ActionLoggR IoC Match::"
            f"{m['match_type']} match on '{m['observed_value']}' "
            f"(IoC: {m['ioc']}, port: {m.get('dst_port','?')}, source: {m['source']})"
        )

    # ── webhook delivery ────────────────────────────────────────────────────
    if args.webhook:
        oidc_token = get_oidc_token()
        post_to_webhook(args.webhook, report_dict, oidc_token)

    print(f"[actionloggr] Total domains observed: {len(all_domains)}", file=sys.stderr)
    print(f"[actionloggr] Total IPs observed: {len(all_ips)}", file=sys.stderr)
    print(f"[actionloggr] IoC matches: {len(ioc_matches)}", file=sys.stderr)


if __name__ == "__main__":
    main()
