# SAKURA STACK — план сборки рабочего проекта (по ТП SAKURA-7T-TP v2.3)

Цель: полностью работоспособный программный комплекс платформы (Rust workspace)
по спецификации + RTL (Verilog) с тестбенчами (iverilog) + E2E-кластер.

## Этапы

- [x] 0. Окружение: Rust 1.83.0 (pinned per 21.2), gcc, iverilog, wget
- [x] 1. KAT-материалы: RFC 7836 (HMAC/KDF/KDF_TREE/VKO/wrap/S-box Z, B.11 — порядок
       байт: rev_words(key)+rev_block), gostcrypto-векторы GOST 34.10-2012 paramSetA
- [x] 2. Каркас: workspace sakura-stack/ по структуре CM-1 §21.2, rust-toolchain.toml, git
- [x] 3. sakura-common (sw/common): canonical CBOR (RFC 8949 §4.2.1), коды ошибок 13.8,
       UUIDv7, hex, ini-config, wall-time
- [x] 4. sakura-gost (crypto/gost): Streebog-256/512 (KAT RFC 6986), HMAC (KAT RFC 7836 B.1),
       HKDF (C-09), KDF_3411_2012_256 + KDF_TREE (KAT B.9/B.10), U256-арифметика,
       GOST 34.10-2012 paramSetA sign/verify (KAT gostcrypto), VKO (B.7 конструкция),
       GOST 28147-89 ECB+IMIT param-Z (KAT B.11), key wrap/unwrap §4.6
- [x] 5. sakura-pq (crypto/pq): ML-DSA-65 (fips204), ML-KEM-1024 (ml-kem)
- [x] 6. sakura-hybrid (crypto/hybrid): hybrid sign/verify (GOST||ML-DSA 3373 B),
       hybrid_kem_combine (код из ТП 23.3.2), Kuznyechik-MGM AEAD (BC-21: IV 128, tag 128)
- [x] 7. sakura-hsm (firmware/hsm_agent): HsmBackend trait (BC-18, no_std, slice-based,
       BufferTooSmall, без HsmError::Ok), SoftHsm: сессии по PIN, rate limit ≤10k ops/s,
       generate/sign/verify/encrypt/decrypt/wrap/unwrap/attest/zeroize, self-test KAT
- [x] 8. sakura-boot (firmware/boot): ImageHeader C-08, TrustAnchor C-02 (chain, CRL,
       time_valid, hybrid sig), PCR-банк (22.16), rollback counters active/pending (BC-24),
       Boot FSM 13.16.1 (3 fail → RECOVERY, tamper → LOCKDOWN+ZEROIZE)
- [x] 9. sakura-attestation (firmware/attestation_agent): отчёт 13.7/27.8, canonical CBOR,
       COSE_Sign1, var-length sig (BC-19), verifier (nonce/PCR/policy/expiry/CRL)
- [x] 10. sakura-update (firmware/update_agent): UpdateAgent 22.23 (attest(sid,nonce),
       pending rollback counter, commit только после successful boot), A/B slots
- [x] 11. sakura-consensus (sw/consensus): BftNode C-01 (quorum 2f+1, HashSet votes,
       view в hash, DoubleFinalization), FSM BC-23 (BACKUP/PREPARE/COMMIT/FINALIZED/
       VIEW_CHANGE/NEW_VIEW/DEGRADED/ISOLATED/SYNC/RECOVERY/QUARANTINE/EVIDENCE_LOG),
       equivocation detection, CFT-режим
- [x] 12. sakura-crdt (sw/crdt): VectorClock (каноничный happens-before C-06), LWW
       tie-break (timestamp, node_id, value_hash) BC-34, G-counter, deterministic merge,
       audit-event hook (CRDT-REG-001), CBOR-коды операций
- [x] 13. sakura-npp (sw/npp): кадр 13.3 (preamble/SFD/header 15B CRC8/payload/padding/
       FEC RS(544,514)/CRC32), BC-26 padding+FEC alignment, fail-secure format detect,
       типы сообщений, anti-replay window (13.17)
- [x] 14. sakura-policy (sw/policy_engine): L4 policy+ethics (25.1 приоритеты, 24.6 запрет
       летальных автономных действий), RBAC/ABAC команд, key-release policy (13.7),
       lifecycle LIFE-001/BC-22, decommission 3-of-5 (LIFE-005), model allowlist (BC-35)
- [x] 15. sakura-audit (sw/audit_service): AuditRecord DM-1 13.18 (12 полей, canonical CBOR,
       hash-chain Streebog256, seq monotonic, HMAC key_epoch, hybrid sig по пустому
       signature-полю), verify/export chunks (подписанные, идемпотентные)
- [x] 16. sakura-node (apps/node): демон узла — boot-последовательность, HSM, TCP-mesh
       NPP-кадрами, сессии (HELLO/AUTH/SESSION + hybrid KEM + channel binding + MGM),
       heartbeat+watchdog (22.11 окно 50–200мс), consensus-драйвер, CRDT-репликация,
       SubmitCommand (идемпотентность IDEMP-001, replay REPLAY-001), GetStatus,
       RequestAttestation (nonce одноразовый ≤60с), EmergencyStop (two-person),
       UpdateCommit, HTTP management plane (read-only), holdover-модель времени (12.2)
- [x] 17. sakura-ca (apps/ca): key ceremony tool — root/intermediate/device/operator keys,
       сертификаты, CRL, подписание firmware-образов и OTA-манифестов
- [x] 18. sakura-cli (apps/cli): operator tool — status/kv put,get/incr/submit/attest/
       verify/audit export+verify/update create+push/emergency-stop
- [x] 19. hw/rtl: cdc_sync.v, window_wdt.v, dma_ring.v, boot_rom.v (из ТП 22.10/22.11/
       22.13/27.10) + тестбенчи + iverilog-прогон
- [x] 20. Интеграция: tests/integration — кластер 4 узла in-process: consensus finalization,
       leader down → view change, partition → DEGRADED/ISOLATED → heal → CRDT converge,
       idempotent replay, OTA success/fail rollback counter, audit chain verify, attestation
- [x] 21. ops/run_cluster.sh (4 узла + CLI workload E2E), README.md, docs/TRACEABILITY.md,
       schemas/machine_readable/requirements.json (MR-1), build/sbom (SPDX из Cargo.lock)
- [x] 22. Финал: cargo build --release, cargo test --workspace (все зелёные), E2E-прогон,
       iverilog-прогон, git commit, отчёт пользователю
