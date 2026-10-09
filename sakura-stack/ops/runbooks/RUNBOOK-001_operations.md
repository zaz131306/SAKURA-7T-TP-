# RUNBOOK-001: Эксплуатация кластера Sakura Stack (SIL-контур)

## 1. Запуск / останов

```bash
./ops/run_cluster.sh provision   # ceremony + provisioning (run-data/)
./ops/run_cluster.sh start       # запуск 4 узлов (ждёт RUNTIME_READY)
./ops/run_cluster.sh status      # состояние (фаза/режим/высота/время/пиры)
./ops/run_cluster.sh stop        # штатная остановка (STOP-файлы, §22.8:
                                 #   flush logs → save state → close sessions)
./ops/run_cluster.sh kill        # аварийное завершение (имитация отказа питания)
```

Коды выхода узла: `0` — штатно, `85` — SECURE_BOOT_FAILED (recovery),
`87` — REBOOT после OTA (§13.16.2).

## 2. Обновление прошивки (OTA, §22.23)

```bash
BIN=target/debug
PH=$($BIN/sakura-ca policy-hash)                      # policy binding
echo "new kernel" > /tmp/k.bin
$BIN/sakura-ca sign-image   --dir run-data/ca --payload /tmp/k.bin \
    --type kernel --version 2 --rollback 1 --out /tmp/k.img
$BIN/sakura-ca ota-package  --dir run-data/ca --image /tmp/k.img \
    --type kernel --version 2 --rollback 1 --policy-hash $PH --out /tmp/k.pkg
$BIN/sakura-cli --node 127.0.0.1:9301 --bundle run-data/ca/bundle.cbor \
    --op run-data/op_admin update push --pkg /tmp/k.pkg   # confirm: yes
# узел перезапускается (exit 87) — ops-процесс/система перезапускает процесс:
(setsid $BIN/sakura-node --config run-data/node0/config.ini > log 2>&1 &)
```

Поведение (BC-24):
- успех: active rollback counter коммитится ПОСЛЕ successful boot + self-test;
- неудача: MARK_FAILED → RESTORE_PREVIOUS_SLOT, active counter НЕ изменяется;
- 3+ неудач подряд: boot_fail_count → recovery/lockdown по политике.

Откат запрещён: пакет с rollback_counter < active → ROLLBACK_DETECTED (0x000C).

## 3. Аварийная остановка (two-person, §13.19.2)

```bash
$BIN/sakura-cli --node 127.0.0.1:9301 --bundle run-data/ca/bundle.cbor \
  --op run-data/op_safety emergency --reason 42 --op2 run-data/op_admin --confirm
```

Требования: два РАЗНЫХ оператора SAFETY_OFFICER/ADMIN, обе гибридные подписи
валидны. Режим EMERGENCY_STOP реплицируется консенсусом; выход — только
RECOVERY (команда RECOVERY_ENTER роли SAFETY_OFFICER/ADMIN).

## 4. Аудит и расследование (§25.3)

```bash
$CLI --op run-data/op_aud audit export --out chunk.cbor --from 1 --max 1000
$CLI --op run-data/op_aud audit verify --file chunk.cbor
```

Верификация: chunk_hash, подпись узла, подписи записей, hash-цепочка,
монотонность seq. Экспорт идемпотентен по request_id (AUD-010).

## 5. Резервное копирование / DR (§25.4/25.5)

Резервируются каталоги узлов: `flash/` (слоты A/B + rollback.bin + slots.meta),
`audit/` (WORM-копия), `identity/keystore.bin`, `trust_bundle.cbor`,
`crdt.snapshot`, `idem.snapshot`, `time.state`.
Восстановление: развернуть каталог → старт узла; целостность подтверждается
boot-цепочкой (hash/signature), MAC rollback-хранилища и audit verify_all.
Метрика BC-30 (restore ≤ N мин) фиксируется в акте DR-drill.

## 6. Инциденты

| Симптом | Реакция (§13.8) |
|---|---|
| QUORUM_LOST (0x000A) | узлы → ISOLATED, local autonomy; после heal — SYNC/RECOVERY автоматически |
| TIME_SYNC_LOST (0x0009) | HOLDOVER ≤30 с (модель OCXO ≤5 мкс/24ч), далее FREE — аудит |
| TAMPER_DETECTED (0x0003) | LOCKDOWN + zeroization (SoftHsm::trigger_tamper); снятие — ceremony_reset |
| ROLLBACK_DETECTED (0x000C) | CRITICAL: блокировка обновления, аудит, расследование |
| WATCHDOG | safe state (DegradedCompute), аудит, reset окна |
| SECURE_BOOT_FAILED (0x000D) | exit 85 → recovery-процедура (двойная авторизация, §22.15) |

## 7. Ключевые церемонии (§23.9, КР-3)

Production: root-ключ — offline HSM, n=5/k=3 split knowledge, dual control.
SIL: `sakura-ca init` эмулирует ceremony с документированным risk acceptance;
форматы артефактов (ключи/сертификаты/CRL/протокол) соответствуют КР-2/КР-3.
