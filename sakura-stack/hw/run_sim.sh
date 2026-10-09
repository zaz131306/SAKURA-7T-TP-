#!/usr/bin/env bash
# hw/run_sim.sh — прогон RTL-тестбенчей (iverilog/vvp).
# Программа испытаний SIL/HIL (§15.2): RTL-модули ТП §22.10/22.11/22.13/27.10.
set -u
cd "$(dirname "$0")"
mkdir -p sim
cd sim

# образ boot ROM (заглушка §27.10)
cat > boot_rom.hex <<'EOF'
DEADBEEF
CAFEBABE
5A5AA5A5
0000000D
FFFFFFFF
00000000
00000000
00000000
00000000
00000000
00000000
00000000
00000000
00000000
00000000
00000000
EOF

RC=0
for tb in window_wdt cdc_sync dma_ring boot_rom; do
  echo "=== $tb ==="
  if ! command -v iverilog >/dev/null 2>&1; then
    echo "SKIP: iverilog не установлен (apt-get install iverilog)"; continue
  fi
  iverilog -g2005 -o "$tb.vvp" ../rtl/*.v ../tb/tb_"$tb".v 2>iverilog_"$tb".log
  if [ $? -ne 0 ]; then
    echo "FAIL: $tb compile"; cat iverilog_"$tb".log; RC=1; continue
  fi
  out=$(vvp "$tb.vvp" 2>&1)
  echo "$out" | grep -E "PASS|FAIL|:" | head -5
  if echo "$out" | grep -q "PASS: tb_$tb"; then
    :
  else
    echo "FAIL: $tb runtime"; RC=1
  fi
done
exit $RC
