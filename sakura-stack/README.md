# SAKURA STACK — рабочая реализация платформы

**Шифр ТП:** SAKURA-7T-TP · **Редакция спецификации:** 2.3 (Gate 2 / CDR) · **Версия ПО:** 2.3.0

Программно-аппаратная платформа распределённых вычислений, криптостойкого
управления и нейро-символической обработки — **полностью работоспособная
реализация** программного контура (L0–L8) по детальному техническому проекту,
включая RTL-модули с тестбенчами.

## Быстрый старт

```bash
# зависимости: Rust (pinned 1.83.0 — rust-toolchain.toml), gcc, python3,
#              iverilog (для RTL-симуляции)
cargo build --workspace --release      # сборка
cargo test  --workspace                # все испытания (unit + integration)
./hw/run_sim.sh                        # RTL-тестбенчи (iverilog)

# Демонстрационный кластер (4 узла, полный цикл):
./ops/run_cluster.sh demo              # provisioning → старт → workload → OTA → стоп
```

`run_cluster.sh demo` выполняет: key ceremony (CA) → provisioning 4 узлов и
4 операторов → загрузку узлов (secure boot) → установление NPP-сессий →
BFT-консенсус → KV-операции через консенсус → отказ этики (§24.6) →
удалённую аттестацию с верификацией → экспорт аудита с внешней проверкой →
OTA-обновление с reboot и коммитом rollback-счётчика (BC-24) → штатный останов.

Отдельные команды: `provision | start | stop | status | workload | ota`.
Ручное управление оператором: `target/debug/sakura-cli` (см. ниже).

## Что реально работает

| Подсистема | Реализация | Подтверждение |
|---|---|---|
| **L0 Trust Anchor** | secure boot: образы `SAKU` (C-08), цепочка сертификатов + CRL + время (C-02), гибрид-подпись ГОСТ+ML-DSA, PCR 0–15 (§22.16), Boot FSM (§13.16.1): 3 отказа → RECOVERY, tamper → LOCKDOWN | `cargo test -p sakura-boot` (23) |
| **L2 Crypto Core** | ГОСТ Р 34.10-2012 paramSetA (собственная реализация, **KAT байт-в-байт против независимой gostcrypto**), Стрибог-256/512, HMAC/HKDF/KDF/KDF_TREE (KAT RFC 7836 B.1/B.2/B.9/B.10), ГОСТ 28147-89 ECB+IMIT+key wrap (KAT RFC 7836 B.11), VKO (RFC 7836 §4.3.1) | `cargo test -p sakura-gost` (20) |
| **PQ-гибрид** | ML-DSA-65 (FIPS 204), ML-KEM-1024 (FIPS 203), гибридная подпись 64+3309=3373 Б (§23.3.3), KEM-combiner — точный код ТП §23.3.2, Кузнечик-MGM AEAD (BC-21: тег 128 бит, IV 128 бит, no IV reuse) | `cargo test -p sakura-pq -p sakura-hybrid` (11) |
| **HSM-agent** | slice-based `HsmBackend` (BC-18: no_std, no heap в API, BufferTooSmall, без `HsmError::Ok`), SoftHsm: PIN-сессии ≤1 ч, rate limit 10k ops/с и 1k сессий/с (§13.6), power-on self-test KAT, tamper→zeroization, wrap/unwrap, персистенция keystore | `cargo test -p sakura-hsm` (9) |
| **L6 Consensus** | SakuraBFT: референсный узел C-01 (кворум 2f+1, HashSet-голоса, view в hash блока, DoubleFinalization невозможен), двухфазный PREPARE/COMMIT, FSM BC-23 (BACKUP…QUARANTINE/EVIDENCE_LOG), equivocation→карантин+evidence, CFT-режим, state transfer (SYNC/RECOVERY), CONS-005 cleanup | `cargo test -p sakura-consensus` (16) |
| **L6 CRDT** | vector clocks (канонический happens-before C-06), LWW tie-break timestamp→node_id→value_hash (BC-34), G-counter, детерминированная конвергенция (property-тест перестановок), аудит merge (CRDT-REG-001) | `cargo test -p sakura-crdt` (7) |
| **NPP-транспорт** | кадр §13.3 (preamble/SFD/header 15B CRC8/payload/padding/**FEC RS(544,514) GF(2¹⁰)** t=15/CRC32 IEEE), BC-26 выравнивание и padding, fail-secure детекция версии (BC-1), fragmentation, anti-replay окно (§13.17) | `cargo test -p sakura-npp` (32) |
| **L4 Policy & Ethics** | RBAC/ABAC, Ethics Governor 3 уровня (ETH-002), **hard constraints не переопределяются** (ETH-003): `LETHAL_*`/`WEAPON_*` → ETHICS_REJECTED даже для ADMIN (§24.6), автономность ≤L3 (ETH-004), two-person rule, decommission 3-из-5 (LIFE-005), lifecycle phases ↔ operating modes (BC-22) | `cargo test -p sakura-policy` (9) |
| **L7 Audit** | AuditRecord 12 полей DM-1 (canonical CBOR — контрольный пример §13.18.3 в KAT), формулы §4.12 (MAC/chain/checkpoint), append-only, checkpoints каждые 512 (AUD-004), ротация ключей ≤24ч/10⁶ (AUD-006), tamper-detection всех 5 классов (AUD-008), signed export + идемпотентность (AUD-010) | `cargo test -p sakura-audit` (6) |
| **L8 Lifecycle / OTA** | update agent §22.23: манифест+подпись, policy binding, `attest(sid,nonce)` (C-04), A/B slots, **pending rollback counter отдельно от active; commit ТОЛЬКО после successful boot; при неудаче — RESTORE_PREVIOUS_SLOT без коммита** (BC-24) | `cargo test -p sakura-update` (3) + E2E в `run_cluster.sh` |
| **Attestation** | отчёт §13.7 (13 полей), canonical CBOR + COSE_Sign1 (RFC 8152), подпись переменной длины 3373 Б (BC-19: фиксированные 96 Б запрещены), verifier: alg/цепочка/nonce/PCR/policy hash/expiry≤60с/revocation | `cargo test -p sakura-attestation` (3) |
| **Узел (sakura-node)** | демон: boot-цепочка PBL→SBL→KERNEL(A/B), HSM+key release policy (§13.7), TCP-mesh NPP-кадрами, рукопожатие HELLO→AUTH→SESSION (гибридный KEM: VKO+ML-KEM, channel binding = хэш транскрипта), MGM-шифрование трафика (IV=direction‖seq), heartbeats + window watchdog (§22.11), PTP-подобная синхронизация времени + holdover-модель OCXO ≤5 мкс/24ч (§12.2, LOCKED/HOLDOVER/FREE), control API (SubmitCommand: сертификат+подпись+RBAC+seq-replay+идемпотентность→консенсус), EmergencyStop two-person, HTTP management plane (read-only) | `ops/run_cluster.sh demo`, `tests/integration` (6) |
| **Инструменты** | `sakura-ca` (ceremony: root→platform→firmware/update CA, provisioning узлов — ключи генерируются внутри HSM-образа, no key export; sign-image, ota-package, CRL), `sakura-cli` (status/kv/submit/attest/audit/update/emergency/watch) | E2E-сценарии demo |
| **HW RTL** | `cdc_sync.v` (§22.10), `window_wdt.v` (§22.11, C-05: sticky-timeout, перезапуск окна), `dma_ring.v` (§22.13), `boot_rom.v` (§27.10) + self-checking тестбенчи | `./hw/run_sim.sh` — 4/4 PASS (iverilog 11) |

## Архитектура (слои ТП §5.1)

```
L8 Lifecycle      sw/policy_engine (phases/modes), firmware/update_agent (OTA A/B)
L7 Observability  sw/audit_service (hash-chain, checkpoints, export)
L6 Consensus+Dist sw/consensus (SakuraBFT), sw/crdt, sw/npp (транспорт)
L5 Isolation      (SIL: процессы/потоки; production: RTOS/MPU — ПО-1)
L4 Policy&Ethics  sw/policy_engine (RBAC, Ethics Governor, hard constraints)
L3 Cognitive T8   интерфейс Plan* в NPP §13.3 (внешняя зона, BC-17 — вне узла доверия)
L2 Crypto Core    crypto/gost, crypto/pq, crypto/hybrid
L1 Compute        apps/node (runtime), hw/rtl (FPGA-модули)
L0 Trust Anchor   firmware/boot (secure/measured boot), firmware/hsm_agent
```

Монорепозиторий — структура CM-1 §21.2: `crypto/ firmware/ sw/ apps/ hw/ tests/
ops/ schemas/ build/ docs/ tools/`.

## Криптографический профиль (КР-1)

| Профиль | Алгоритм | Статус |
|---|---|---|
| P-GOST-SIGN | ГОСТ Р 34.10-2012, 256 бит, paramSetA (RFC 7836) | реализован, KAT gostcrypto |
| P-GOST-HASH-256/512 | Стрибог (RustCrypto `streebog`, KAT) | реализован |
| P-GOST-CIPHER / P-GOST-MGM | Кузнечик + MGM, тег 128, IV 128 (BC-21) | реализован (`mgm`/`kuznyechik`) |
| P-GOST-KDF / P-GOST-HMAC | HKDF-Стрибог-256 (C-09), KDF/KDF_TREE (RFC 7836) | реализован, KAT B.9/B.10 |
| P-GOST-WRAP | RFC 7836 §4.6 (28147-89 ECB+IMIT, KDF, seed) | реализован, KAT B.11¹ |
| P-GOST-ECDH | VKO_GOSTR3410_2012_256 (RFC 7836 §4.3.1) | реализован |
| PQ-подпись | ML-DSA-65 (FIPS 204, crate `fips204`) | реализован |
| PQ-KEM | ML-KEM-1024 (FIPS 203, crate `ml-kem`) | реализован |
| Гибрид | sign = GOST(64)‖ML-DSA(3309); KEM = HKDF(VKO‖ML-KEM) (§23.3) | реализован |

¹ Байтовая конвенция 28147-89 (слова little-endian, блоки reversed) сверена с
вектором RFC 7836 B.11 байт-в-байт. Порядок байт r‖s подписи 34.10 — big-endian
(внутренний профиль, сверен с gostcrypto); интероперабельность с RFC 4491
требует reversal — фиксируется в КР-2 при интеграции с внешними PKI.

**Interim baseline (§23.3.1):** PQ-алгоритмы — открытые реализации (fips204,
ml-kem — RustCrypto/integritychain), binary foreign dependencies отсутствуют,
algorithm agility обеспечена идентификаторами алгоритмов в заголовках/отчётах.
Production: сертифицированный ФСБ криптопровайдер и HSM класса КС3 (BC-16, КР-4).

## Испытания

```bash
cargo test --workspace          # ~140 тестов: unit + property + KAT + integration
./hw/run_sim.sh                 # RTL: 4 тестбенча (iverilog)
./ops/run_cluster.sh demo       # системный E2E (процессы, сеть, OTA)
```

Интеграционные сценарии (`tests/integration`, §15.4): финализация через реальные
NPP-кадры с FEC; коррекция битовых ошибок канала (RS t=15); отказ proposer'а →
VIEW_CHANGE → failover; партиция → ISOLATED/DEGRADED → heal → SYNC →
конвергенция CRDT; equivocation → QUARANTINE+EVIDENCE; отсутствие двойной
финализации (FV-003/CONS-006).

## CLI оператора

```bash
CLI="target/debug/sakura-cli --node 127.0.0.1:9301 --bundle run-data/ca/bundle.cbor"
$CLI --op run-data/op_op   kv put sensor.temp 21.5   # через BFT-консенсус
$CLI --op run-data/op_op   kv get sensor.temp
$CLI --op run-data/op_aud  attest --verify            # COSE_Sign1 + verifier ATT-001
$CLI --op run-data/op_aud  audit export --out a.cbor && $CLI --op run-data/op_aud audit verify --file a.cbor
$CLI --op run-data/op_admin update push --pkg upd.pkg  # OTA (confirm-запрос, §25.2)
$CLI --op run-data/op_safety emergency --reason 1 --op2 run-data/op_admin --confirm
```

## Отклонения и решения по [TBD] (регистрируются в change board, §21.5)

1. **L3 Cognitive Core / L5 RTOS / физический HSM и FPGA** — вне SIL-контура:
   интерфейсы присутствуют (NPP Plan* §13.3, HsmBackend, RTL-модули), исполнение
   на хост-платформе эмулируется (SoftHsm, процессы). Production — по ПО-1/КР-4.
2. **Кодирование r‖s и проводная конвенция 28147-89** — big-endian/LE-профиль
   (см. сноску КР-1 выше), сверено KAT.
3. **Padding/FEC-выравнивание NPP [TBD §13.3]** — принято: pattern 0x00, регион
   кратен 1285 Б (2 кодовых слова RS(544,514)), интерливинг отсутствует,
   max frame 2733 Б (ICD-аддендум).
4. **Типы сообщений 0x70–0x73** (consensus/crdt/control-api/time-sync) —
   аддендум ICD-1 к таблице §13.3.
5. **CBC-режим и ключевой wrap «Кузнечик KWP»** — P-GOST-WRAP реализован по
   RFC 7836 §4.6 (28147-89); KWP по ГОСТ 34.13-2015 — опция миграции (§23.23).
6. **Инструменты pinned 1.83.0 (BC-9)** — зависимости зафиксированы на
   поколениях, совместимых с rustc 1.83 (digest 0.10 / cipher 0.3); миграция на
   edition 2024 — отдельным изменением после аудита toolchain ≥1.85.
7. **SIGTERM** — штатный останов через STOP-файл в data_dir (ops/runbooks);
   обработчик сигналов без unsafe-зависимостей не вводится.

Полная матрица «требование → реализация → испытание» — `docs/TRACEABILITY.md`.

## Состав workspace

```
sw/common          sakura-common      canonical CBOR (RFC 8949), коды §13.8, UUIDv7
crypto/gost        sakura-gost        34.10-2012, Стрибог, HMAC/HKDF/KDF, 28147-89
crypto/pq          sakura-pq          ML-DSA-65, ML-KEM-1024
crypto/hybrid      sakura-hybrid      гибрид-подпись/KEM, MGM AEAD
crypto/kdf         (в sakura-gost)    KDF-модули (CM-1: crypto/kdf → gost/src/kdf.rs)
firmware/boot      sakura-boot        secure/measured boot, PCR, rollback, bundle
firmware/hsm_agent sakura-hsm         HsmBackend (BC-18) + SoftHsm
firmware/attestation_agent sakura-attestation  §13.7 + COSE_Sign1
firmware/update_agent      sakura-update       OTA A/B (BC-24)
sw/consensus       sakura-consensus   SakuraBFT (C-01 + BC-23)
sw/crdt            sakura-crdt        C-06 + BC-34
sw/npp             sakura-npp         кадры §13.3, RS(544,514), API-1 payload
sw/policy_engine   sakura-policy      L4 + lifecycle
sw/audit_service   sakura-audit       DM-1 + AUD-001..012
sw/lifecycle_service (в policy/node)  фазы/режимы (BC-22)
apps/node          sakura-node        демон узла
apps/ca            sakura-ca          PKI/ceremony инструмент
apps/cli           sakura-cli         операторский CLI
tests/integration  sakura-integration кластерные испытания в процессе
hw/rtl, hw/tb      —                  Verilog + тестбенчи (iverilog)
```

## Лицензии зависимостей

Apache-2.0/MIT/BSD (§21.8 §5): RustCrypto (streebog, hmac, digest, kuznyechik,
mgm, ml-kem, zeroize), integritychain fips204, getrandom/rand_core. GPL/AGPL
отсутствуют. SBOM: `build/sbom/gen_sbom.py` (SPDX из Cargo.lock).
