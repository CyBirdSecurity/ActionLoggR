#!/usr/bin/env bash
# monitor-start.sh — starts tcpdump, iptables connection logging, and conntrack event capture
set -euo pipefail

OUTPUT_DIR="${ACTIONLOGGR_OUTPUT_DIR:-/tmp/actionloggr}"
CAPTURE_FILTER="${ACTIONLOGGR_CAPTURE_FILTER:-}"
PCAP_FILE="${OUTPUT_DIR}/capture.pcap"
DNS_LOG="${OUTPUT_DIR}/dns.log"
CONNTRACK_LOG="${OUTPUT_DIR}/conntrack.log"
IPTABLES_LOG="${OUTPUT_DIR}/iptables.log"
PID_FILE="${OUTPUT_DIR}/monitor.pids"

mkdir -p "${OUTPUT_DIR}"

# Detect outbound interface (typically eth0 on GitHub-hosted runners)
IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
IFACE="${IFACE:-eth0}"
echo "[actionloggr] Interface: ${IFACE}" >&2

# ── tcpdump ──────────────────────────────────────────────────────────────────
# Capture all traffic; SNI extraction happens offline in the reporter.
TCPDUMP_FILTER="not port 22"
if [ -n "${CAPTURE_FILTER}" ]; then
  TCPDUMP_FILTER="${CAPTURE_FILTER}"
fi

sudo tcpdump \
  -i "${IFACE}" \
  -w "${PCAP_FILE}" \
  -s 0 \
  --immediate-mode \
  -q \
  "${TCPDUMP_FILTER}" \
  &>/dev/null &
TCPDUMP_PID=$!
echo "[actionloggr] tcpdump PID: ${TCPDUMP_PID}" >&2

# ── DNS query capture via tcpdump (text log for quick offline parsing) ────────
# The brace group + </dev/null 2>/dev/null ensures none of the pipeline stages
# hold open the parent's stdin/stderr pipes (which would cause exec.exec in
# the Node.js action to hang waiting for those pipes to close).
{ sudo tcpdump \
    -i "${IFACE}" \
    -l \
    -n \
    'udp port 53 or tcp port 53' \
    2>/dev/null \
  | awk '
      /A\?|AAAA\?|CNAME\?|TXT\?/ {
        ts = $1
        for (i=1; i<=NF; i++) {
          if ($i ~ /\?$/) {
            gsub(/\?$/, "", $i)
            print ts, $i
            next
          }
        }
      }
    ' >> "${DNS_LOG}" 2>/dev/null
} </dev/null 2>/dev/null &
DNS_PID=$!
echo "[actionloggr] DNS capture PID: ${DNS_PID}" >&2

# ── conntrack event logging ───────────────────────────────────────────────────
# conntrack may not be loaded; fall back gracefully.
if command -v conntrack &>/dev/null; then
  { sudo conntrack -E -e NEW -o timestamp \
      2>/dev/null \
    | grep --line-buffered -v '127\.0\.0\.' \
      >> "${CONNTRACK_LOG}" 2>/dev/null
  } </dev/null 2>/dev/null &
  CONNTRACK_PID=$!
  echo "[actionloggr] conntrack PID: ${CONNTRACK_PID}" >&2
else
  CONNTRACK_PID=""
  echo "[actionloggr] conntrack not available, skipping" >&2
fi

# ── iptables connection logging ───────────────────────────────────────────────
# Log new outbound connections to kernel log, then tail into file.
if sudo iptables -L OUTPUT &>/dev/null 2>&1; then
  sudo iptables -I OUTPUT 1 \
    -m state --state NEW \
    ! -d 127.0.0.0/8 \
    -j LOG \
    --log-prefix "ACTIONLOGGR_OUT: " \
    --log-level 4 \
    2>/dev/null || true

  { sudo dmesg -w 2>/dev/null \
    | grep --line-buffered "ACTIONLOGGR_OUT:" \
      >> "${IPTABLES_LOG}" 2>/dev/null
  } </dev/null 2>/dev/null &
  DMESG_PID=$!
  echo "[actionloggr] dmesg tail PID: ${DMESG_PID}" >&2
else
  DMESG_PID=""
  echo "[actionloggr] iptables unavailable, skipping kernel log" >&2
fi

# ── persist PIDs for monitor-stop.sh ─────────────────────────────────────────
{
  echo "TCPDUMP_PID=${TCPDUMP_PID}"
  echo "DNS_PID=${DNS_PID}"
  echo "CONNTRACK_PID=${CONNTRACK_PID:-}"
  echo "DMESG_PID=${DMESG_PID:-}"
  echo "IFACE=${IFACE}"
} > "${PID_FILE}"

echo "[actionloggr] Monitor started. Output dir: ${OUTPUT_DIR}" >&2

# Give tcpdump a moment to initialise before the real job steps run
sleep 1
