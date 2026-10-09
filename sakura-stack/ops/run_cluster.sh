#!/usr/bin/env bash
# SAKURA STACK — запуск демонстрационного кластера (ops/deployment).
# Полный цикл: сборка → ceremony provisioning (CA) → 4 узла → операторы.
#
# Использование:
#   ops/run_cluster.sh provision   # собрать + провижининг в run-data/
#   ops/run_cluster.sh start       # запустить 4 узла (фон)
#   ops/run_cluster.sh stop        # штатная остановка (STOP-файлы)
#   ops/run_cluster.sh kill        # принудительно
#   ops/run_cluster.sh status      # HTTP-статусы узлов
#   ops/run_cluster.sh workload    # E2E: kv/submit/attest/audit (см. ниже)
#   ops/run_cluster.sh demo        # provision + start + workload + stop
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$ROOT"
BIN="$ROOT/target/debug"
DATA="$ROOT/run-data"
CA="$DATA/ca"
N_NODES=4
BASE_PORT=9301
BASE_HTTP=9401

stop_nodes() {
  for i in $(seq 0 $((N_NODES-1))); do
    touch "$DATA/node$i/STOP" 2>/dev/null || true
  done
  sleep 2
}

kill_nodes() {
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    [ "$pid" = "$$" ] && continue
    [ "$pid" = "$PPID" ] && continue
    if grep -qa "sakura-[n]ode" "$p/cmdline" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  done
  sleep 1
}

provision() {
  cargo build -p sakura-ca -p sakura-node -p sakura-cli
  kill_nodes
  rm -rf "$DATA"
  mkdir -p "$DATA"
  "$BIN/sakura-ca" init --dir "$CA" --cluster-n $N_NODES
  for i in $(seq 0 $((N_NODES-1))); do
    "$BIN/sakura-ca" gen-node --dir "$CA" --out "$DATA/node$i" --idx "$i" \
      --host 127.0.0.1 --port $((BASE_PORT+i)) --http-port $((BASE_HTTP+i)) --hw-rev 1
  done
  "$BIN/sakura-ca" gen-operator --dir "$CA" --out "$DATA/op_admin"  --role ADMIN
  "$BIN/sakura-ca" gen-operator --dir "$CA" --out "$DATA/op_op"     --role OPERATOR
  "$BIN/sakura-ca" gen-operator --dir "$CA" --out "$DATA/op_aud"    --role AUDITOR
  "$BIN/sakura-ca" gen-operator --dir "$CA" --out "$DATA/op_safety" --role SAFETY_OFFICER
  for i in $(seq 0 $((N_NODES-1))); do
    "$BIN/sakura-ca" deploy-bundle --dir "$CA" --node "$DATA/node$i"
  done
  echo "provisioning OK: $DATA"
}

start_nodes() {
  for i in $(seq 0 $((N_NODES-1))); do
    rm -f "$DATA/node$i/STOP"
    (setsid "$BIN/sakura-node" --config "$DATA/node$i/config.ini" \
      > "$DATA/node$i/log.txt" 2>&1 < /dev/null &)
  done
  # ожидание RUNTIME_READY всех узлов (boot-цепочка ~2–6 с)
  for try in $(seq 1 30); do
    ok=0
    for i in $(seq 0 $((N_NODES-1))); do
      if python3 - "$((BASE_HTTP+i))" <<'EOF' 2>/dev/null
import sys, urllib.request
r = urllib.request.urlopen(f'http://127.0.0.1:{sys.argv[1]}/health', timeout=2)
sys.exit(0 if b'RUNTIME_READY' in r.read() else 1)
EOF
      then ok=$((ok+1)); fi
    done
    [ "$ok" = "$N_NODES" ] && { echo "все узлы RUNTIME_READY (${try}0 c)"; return 0; }
    sleep 1
  done
  echo "ВНИМАНИЕ: не все узлы готовы" >&2
  return 1
}

status_nodes() {
  python3 - "$N_NODES" "$BASE_HTTP" <<'EOF'
import sys, json, urllib.request
n, base = int(sys.argv[1]), int(sys.argv[2])
for i in range(n):
    try:
        d = json.loads(urllib.request.urlopen(f'http://127.0.0.1:{base+i}/status', timeout=3).read())
        peers = ','.join(f"{p['idx']}:{'UP' if p['alive'] else 'down'}" for p in d['peers'])
        print(f"node{d['node_idx']}: phase={d['phase']} mode={d['mode']} h={d['consensus_height']} v={d['consensus_view']} "
              f"time={d['time_quality']} audit={d['audit_len']} peers[{peers}] fw={d['fw_versions'].get('kernel')}")
    except Exception as e:
        print(f"node{i}: ERR {e}")
EOF
}

workload() {
  local CLI="$BIN/sakura-cli --node 127.0.0.1:$BASE_PORT --bundle $CA/bundle.cbor"
  echo "== 1. статус узла (management/control)"
  $CLI --op "$DATA/op_admin" status
  echo "== 2. KV_PUT через BFT-консенсус"
  $CLI --op "$DATA/op_op" kv put sensor.temp 21.5
  $CLI --op "$DATA/op_op" kv put config.mode production
  echo "== 3. KV_INCR (G-counter CRDT)"
  $CLI --op "$DATA/op_op" kv incr requests.total 5
  $CLI --op "$DATA/op_op" kv get requests.total
  echo "== 4. чтение реплицированного состояния"
  $CLI --op "$DATA/op_op" kv get sensor.temp
  echo "== 5. произвольная команда (RBAC)"
  $CLI --op "$DATA/op_op" submit --type SENSOR_CALIBRATE --target node-2
  echo "== 6. отказ этики (hard constraint §24.6)"
  $CLI --op "$DATA/op_op" submit --type LETHAL_STRIKE --target x || true
  echo "== 7. удалённая аттестация + верификация (BC-19)"
  $CLI --op "$DATA/op_aud" attest --verify --out "$DATA/attestation.cbor"
  echo "== 8. экспорт аудита + внешняя верификация (AUD-010)"
  $CLI --op "$DATA/op_aud" audit export --out "$DATA/audit_chunk.cbor" --from 1 --max 1000
  $CLI --op "$DATA/op_aud" audit verify --file "$DATA/audit_chunk.cbor"
  echo "== 9. HTTP management plane"
  python3 - "$BASE_HTTP" <<'EOF'
import sys, urllib.request
print(urllib.request.urlopen(f'http://127.0.0.1:{sys.argv[1]}/metrics', timeout=3).read().decode().strip())
EOF
}

ota_demo() {
  local CLI="$BIN/sakura-cli --node 127.0.0.1:$BASE_PORT --bundle $CA/bundle.cbor"
  echo "== OTA: сборка kernel v2, пакет, push на node0, reboot, commit counter (BC-24)"
  PH=$("$BIN/sakura-ca" policy-hash)
  echo "SAKURA-KERNEL-V2 payload $(date +%s)" > /tmp/sakura_kernel_v2.bin
  "$BIN/sakura-ca" sign-image --dir "$CA" --payload /tmp/sakura_kernel_v2.bin \
      --type kernel --version 2 --rollback 1 --out /tmp/sakura_kernel_v2.img
  "$BIN/sakura-ca" ota-package --dir "$CA" --image /tmp/sakura_kernel_v2.img \
      --type kernel --version 2 --rollback 1 --policy-hash "$PH" --out /tmp/sakura_update_v2.pkg
  echo yes | $CLI --op "$DATA/op_admin" update push --pkg /tmp/sakura_update_v2.pkg
  sleep 2
  echo "== перезапуск node0 (Update FSM: REBOOT → SELF_TEST → COMMIT)"
  rm -f "$DATA/node0/STOP"
  (setsid "$BIN/sakura-node" --config "$DATA/node0/config.ini" > "$DATA/node0/log.txt" 2>&1 < /dev/null &)
  sleep 6
  python3 - "$BASE_HTTP" <<'EOF'
import sys, json, urllib.request
d = json.loads(urllib.request.urlopen(f'http://127.0.0.1:{sys.argv[1]}/status', timeout=3).read())
print("node0 fw:", d['fw_versions'], "rollback:", d['rollback_active'])
assert d['fw_versions']['kernel'] == '2', "kernel v2 не загружен"
assert d['rollback_active']['kernel'] == 1, "rollback counter не закоммичен (BC-24)"
print("OTA SUCCESS PATH: OK (commit после successful boot — BC-24)")
EOF
}

case "${1:-demo}" in
  provision) provision ;;
  start) start_nodes ;;
  stop) stop_nodes ;;
  kill) kill_nodes ;;
  status) status_nodes ;;
  workload) workload ;;
  ota) ota_demo ;;
  demo)
    provision
    start_nodes
    sleep 3
    status_nodes
    workload
    ota_demo
    echo "== остановка кластера"
    stop_nodes
    status_nodes || true
    ;;
  *) echo "usage: $0 {provision|start|stop|kill|status|workload|ota|demo}"; exit 1 ;;
esac
