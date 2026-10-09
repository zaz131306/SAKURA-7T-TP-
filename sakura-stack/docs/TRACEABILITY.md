# МАТРИЦА ТРАССИРУЕМОСТИ (Requirements Traceability, §21.7: 100%)

Шифр ТП: SAKURA-7T-TP ред. 2.3. Формат: требование → реализация → испытание.
Идентификаторы — по §21.3 (SAKURA.REQ/ICD/CRYPTO/TEST/BC).

## Breaking changes v2.3 (BC-16…BC-36) — статус закрытия в ПО

| BC | Требование | Реализация | Испытание |
|---|---|---|---|
| BC-16 | HSM КС3, FIPS 140-3 reference | `sakura-hsm` (HsmBackend; SoftHsm — SIL-эмуляция, production КР-4) | `sakura-hsm::*` (9) |
| BC-17 | L3 — домен T8, вне узла доверия | NPP Plan* типы §13.3 (`sw/npp/src/msg.rs`); L3 не входит в boot-измерения узла | `msg::tests` |
| BC-18 | HSM-agent slice-based, no heap, BufferTooSmall | `firmware/hsm_agent/src/lib.rs` (trait точной формы §22.5.1) | `soft::tests::sign_verify_flow_and_buffer_too_small` |
| BC-19 | attestation var-length signature, 96 Б запрещены | `sakura-attestation` (COSE_Sign1, sig 3373 Б) | `attestation_full_cycle`, `buffer_too_small_bc18` |
| BC-21 | MGM: тег 128, IV 128 baseline, AAD, no IV reuse | `crypto/hybrid/src/aead_mgm.rs` (IV=dir‖seq — уникальность на сессию) | `mgm_roundtrip_and_tamper`, `mgm_rejects_msb_iv` |
| BC-22 | lifecycle phases ↔ operating modes | `sakura-policy` (OperatingMode::lifecycle_phase, таблица 1.6.2) | `lifecycle_mode_mapping_bc22` |
| BC-23 | Consensus FSM в BFT-терминах | `sw/consensus/src/engine.rs` (FsmState: BACKUP…EVIDENCE_LOG) | `engine_cluster.rs` (9 сценариев) |
| BC-24 | pending/active rollback counters, commit после successful boot | `sakura-boot::rollback`, `sakura-update`, boot-последовательность узла | `bc24_commit_semantics`, `success_path_commits_counter`, `failed_boot_does_not_commit`, E2E `run_cluster.sh`/`ota` |
| BC-25 | Power sequencing 5V | RTL-контур вне SIL (hw/schematic — ПО-1); в ПО: порядок shutdown (§22.8) в `NodeApp::shutdown` | code review |
| BC-26 | NPP padding/FEC alignment | `sw/npp/src/frame.rs` (pattern 0x00, регион кратен 1285 Б, padding в CRC32) | `frame_roundtrip_with_fec`, `fec_corrects_*` |
| BC-27 | idempotency/replay/backward compatibility | `apps/node/src/control.rs` (IdemStore), seq-окна NPP, nonce-реестр | `idem_*`, `principal_seq_replay`, `nonce_one_time`, E2E IDEMPOTENT_REPLAY |
| BC-28 | вибрация 2 Grms | HW-требование (§10.1) — вне SIL-контура | отчёты лаборатории (СОИС-Г) |
| BC-29 | HSM Tj ≤ 75 °C | HW-требование (§6.2) — вне SIL-контура | thermal-отчёт |
| BC-30 | backup restore metric | `ops/backup_dr` (runbook), audit BACKUP_RESTORE | drill по runbook |
| BC-31 | WCET margin ≥20% | методика §21.5 (HIL/SIL); в SIL — watchdog-окно 50–200 мс (§22.11) | `watchdog::tests` |
| BC-33 | Authority Kernel veto — определённые объекты | `sakura-policy`: HARD_FORBIDDEN_PREFIXES не переопределяются ролью/политикой | `hard_constraints_never_overridable` |
| BC-34 | CRDT concurrent tie-break | `sakura-crdt` (timestamp→node_id→value_hash) | `tie_break_order_bc34`, `concurrent_sets_converge_deterministically`, `permutation_convergence_property` |
| BC-35 | ONNX custom operators / allowlist | `KeyReleasePolicy.model_allowlist`, `PolicyEngine::model_allowed`, attestation model_hashes | `model_allowlist_bc35`, verifier `ModelNotAllowed` |
| BC-36 | FL secure aggregation — draft | вне baseline v2.3 (draft) | — |

## Исправления референсного кода (C-01…C-10)

| ID | Требование | Реализация | Испытание |
|---|---|---|---|
| C-01 | консенсус: трейт, HashSet-голоса, view в hash | `sw/consensus/src/node.rs` (код §27.1 дословно) | `node::tests` (7) |
| C-02 | secure boot: root key, цепочка, CRL до подписи | `sakura-boot::anchor` (порядок проверок §27.2) | `revoked_cert_rejected_before_signature` |
| C-03 | HsmError::Ok удалён | `sakura-hsm::HsmError` (успех = Ok(())) | compile-time |
| C-04 | attest(sid, nonce) с явной сессией | `sakura-update::apply`, attestation-agent | `policy_and_signature_gates`, `attestation_full_cycle` |
| C-05 | window_wdt: sticky, перезапуск окна | `hw/rtl/window_wdt.v` | `tb_window_wdt` (iverilog PASS) |
| C-06 | canonical happens_before по объединению ключей | `sakura-crdt::VectorClock` | `happens_before_canonical_c06` |
| C-07 | attestation: детерминированный CBOR, SessionId-параметр | `sakura-attestation` | `attestation_full_cycle` |
| C-08 | ImageHeader — парсер по смещениям | `sakura-boot::image` (offsets §22.1.3) | `parse_roundtrip`, `parse_errors` |
| C-09 | HKDF: HmacStreebog256 | `sakura-gost::kdf::hkdf_streebog256` (код §23.2.3 дословно) | `hkdf_properties` + KAT HMAC |
| C-10 | SBOM: реальные зависимости | `build/sbom/gen_sbom.py` (SPDX из Cargo.lock) | артефакт sbom.spdx.json |

## Тактико-технические требования (§4) и интерфейсы (§13)

| Требование | Реализация | Испытание |
|---|---|---|
| CONS-001/002 BFT f=3/N=10, кворум 2f+1 | `BftNode` (n=3f+1 любое; demo n=4, f=1) | `quorum_and_leader`, integration |
| CONS-003/004 latency ≤20 мс / view change ≤2 с | round_ms=250, proposer_timeout=2000 (config) | E2E timing (demo) |
| CONS-005 MAX_ROUNDS_TO_KEEP=100 | `engine::trim_rounds` | code (константа) |
| CONS-006 double finalization = 0 | `BftNode::finalize` + `import_finalized` | `double_finalization_impossible`, `no_double_finalization_cluster_wide` |
| REL: partition safe mode | DEGRADED/ISOLATED + local autonomy | `partition_isolated_and_state_sync`, E2E kill-сценарий |
| AUD-001..012 | `sakura-audit` (формулы §4.12 дословно) | `append_and_verify`, `tamper_detection_all_classes`, `checkpoints_every_512`, `key_rotation_epochs`, `export_chunks_idempotent`, `persistence_roundtrip` |
| DM-1 §13.18 (12 полей, canonical CBOR) | `AuditRecord::canonical` | KAT §13.18.3 (`audit_record_example_13_18_3`) |
| API-1 §13.19 (SubmitCommand/GetStatus/RequestAttestation/EmergencyStop/UpdateCommit, result/request_seq/audit_ref) | `sw/npp/src/payload.rs`, `apps/node` control | `api_request_roundtrip`, E2E workload |
| ICD §13.3 NPP-кадр | `sw/npp/src/frame.rs` | 32 теста NPP (CRC KAT, FEC, fail-secure) |
| ICD §13.7 attestation schema | `sakura-attestation` | `attestation_full_cycle` + CLI `attest --verify` |
| ICD §13.8 error codes | `sakura-common::error` | `codes_match_icd_13_8` |
| §13.16 FSM (Boot/Update/Attestation/Consensus/Lockdown/Decommission) | boot/update/attestation/consensus FSM; lockdown — `SoftHsm::trigger_tamper`+policy modes; decommission — `verify_decommission_quorum` | соответствующие тесты модулей |
| §13.17 security bindings (channel binding, nonce, seq+ts+nonce, policy binding) | `net.rs` (cb=хэш транскрипта), idem nonce-реестр, `ReplayWindow`, OTA policy_hash | integration + E2E |
| §13.20 IDEMP-001/REPLAY-001/COMPAT-001 | `IdemStore`, replay-окна, версии API (`control.v1` в заголовке пакета) | `control.rs` тесты |
| LIFE-001/002/005 | `sakura-policy` (phases, decommission 3-из-5) | `decommission_3_of_5` |
| ETH-001..009 | Ethics Governor 3 уровня, hard constraints | `hard_constraints_never_overridable`, `anomaly_detection_level3`, E2E `LETHAL_STRIKE → ETHICS_REJECTED` |
| §23.2 профили КР-1 | `crypto/*` (таблица README) | KAT-тесты gost/pq/hybrid |
| §23.6 key hierarchy L0–L9 | классы ключей HSM, уровни в сертификатах/rota | `sakura-hsm`, CA-инструмент |
| §22.16 PCR allocation | `sakura-boot::pcr` (константы PCR0–15) | `pcr::tests`, boot-измерения E2E |
| §22.11 watchdog hierarchy | `apps/node/src/watchdog.rs` (core window 50–200 мс) + RTL | `watchdog::tests`, `tb_window_wdt` |
| §22.13 DMA/CDC RTL | `hw/rtl/dma_ring.v`, `cdc_sync.v` | `tb_dma_ring`, `tb_cdc_sync` |
| §12 GNSS/PTP/holdover ≤5 мкс/24ч | `apps/node/src/time.rs` (LOCKED/HOLDOVER/FREE, drift-модель) | `time::tests` (в т.ч. `holdover_drift_bounded`) |
| §21.2 toolchain pinned 1.83.0, edition 2021 | `rust-toolchain.toml`, все Cargo.toml | `cargo build` на pinned toolchain |
| §25.2 HMI (confirm для критических) | CLI `--confirm`/yes-подтверждение, two-person | E2E emergency сценарий |
| §25.3 журналирование (события + BC-22/BC-27) | `sakura_audit::events` (включая LIFECYCLE_TRANSITION, IDEMPOTENT_REPLAY, CRDT_MERGE) | E2E audit export/verify |

## MR-1 machine-readable

Фрагмент реестра требований — `schemas/machine_readable/requirements.json`
(формат §26.6). SBOM — `build/sbom/gen_sbom.py` → SPDX JSON.
