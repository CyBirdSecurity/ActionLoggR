#!/usr/bin/env bash
# monitor-stop.sh — stops capture processes and invokes the Python reporter
set -euo pipefail

OUTPUT_DIR="${ACTIONLOGGR_OUTPUT_DIR:-/tmp/actionloggr}"
PID_FILE="${OUTPUT_DIR}/monitor.pids"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[actionloggr] Stopping network monitor…" >&2

# ── load PIDs ────────────────────────────────────────────────────────────────
if [ -f "${PID_FILE}" ]; then
  # shellcheck source=/dev/null
  source "${PID_FILE}"
else
  echo "[actionloggr] Warning: PID file not found at ${PID_FILE}" >&2
fi

kill_if_running() {
  local pid="${1:-}"
  local name="${2:-process}"
  if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
    sudo kill -TERM "${pid}" 2>/dev/null || true
    # give it 2 s to flush buffers, then SIGKILL
    sleep 2
    kill -0 "${pid}" 2>/dev/null && sudo kill -KILL "${pid}" 2>/dev/null || true
    echo "[actionloggr] Stopped ${name} (PID ${pid})" >&2
  fi
}

kill_if_running "${TCPDUMP_PID:-}" "tcpdump"
kill_if_running "${DNS_PID:-}" "DNS capture"
kill_if_running "${CONNTRACK_PID:-}" "conntrack"
kill_if_running "${DMESG_PID:-}" "dmesg tail"

# ── remove iptables rule ──────────────────────────────────────────────────────
sudo iptables -D OUTPUT \
  -m state --state NEW \
  ! -d 127.0.0.0/8 \
  -j LOG \
  --log-prefix "ACTIONLOGGR_OUT: " \
  --log-level 4 \
  2>/dev/null || true

# Allow kernel to finish writing
sleep 1

# ── invoke reporter ───────────────────────────────────────────────────────────
echo "[actionloggr] Generating report…" >&2

python3 "${SCRIPT_DIR}/report.py" \
  --output-dir "${OUTPUT_DIR}" \
  --ioc-list   "${ACTIONLOGGR_IOC_LIST:-}" \
  --webhook    "${ACTIONLOGGR_WEBHOOK_URL:-}" \
  --report-all "${ACTIONLOGGR_REPORT_ALL:-true}"

echo "[actionloggr] Done. Report at ${OUTPUT_DIR}/report.json" >&2
