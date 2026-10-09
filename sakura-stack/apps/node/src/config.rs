//! Конфигурация узла (INI, §25.6 управление конфигурацией).

use sakura_common::config::Ini;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub idx: u32,
    pub node_id_hex: String,
    pub hw_rev: u16,
    pub listen: String,
    pub http_listen: String,
    pub data_dir: PathBuf,
    pub hsm_pin: String,
    pub cluster_n: u32,
    pub consensus_mode: String, // bft | cft
    pub round_ms: u64,
    pub heartbeat_ms: u64,
    pub proposer_timeout_ms: u64,
    pub peer_timeout_ms: u64,
    pub wd_min_ms: u64,
    pub wd_max_ms: u64,
    pub time_sync_interval_ms: u64,
    pub drift_ppb_x1000: i64, // holdover drift, ppb×1000 (§12.2: OCXO ≤5 мкс/24ч ≈ 58 ppb×1000?)
    pub sign_audit_records: bool,
}

impl NodeConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let ini = Ini::load(path).map_err(|e| format!("config read: {e}"))?;
        let data_dir = PathBuf::from(ini.get_or("node", "data_dir", "run-data/node"));
        let hsm_pin = if let Some(pf) = ini.get("hsm", "pin_file") {
            std::fs::read_to_string(pf)
                .map_err(|e| format!("pin file: {e}"))?
                .trim()
                .to_owned()
        } else {
            ini.get_or("hsm", "pin", "change-me")
        };
        Ok(NodeConfig {
            idx: ini.get_u64("node", "idx", 0) as u32,
            node_id_hex: ini.get_or("node", "id", ""),
            hw_rev: ini.get_u16("node", "hw_rev", 1),
            listen: ini.get_or("node", "listen", "127.0.0.1:9100"),
            http_listen: ini.get_or("node", "http", "127.0.0.1:9200"),
            data_dir,
            hsm_pin,
            cluster_n: ini.get_u64("cluster", "n", 4) as u32,
            consensus_mode: ini.get_or("cluster", "mode", "bft"),
            round_ms: ini.get_u64("consensus", "round_ms", 250),
            heartbeat_ms: ini.get_u64("consensus", "heartbeat_ms", 500),
            proposer_timeout_ms: ini.get_u64("consensus", "proposer_timeout_ms", 2000),
            peer_timeout_ms: ini.get_u64("consensus", "peer_timeout_ms", 3000),
            wd_min_ms: ini.get_u64("watchdog", "min_ms", 50),
            wd_max_ms: ini.get_u64("watchdog", "max_ms", 200),
            time_sync_interval_ms: ini.get_u64("time", "sync_interval_ms", 1000),
            // OCXO holdover ≤5 мкс/24 ч (§12.1, BC-2) = 5e-6/86400 ≈ 0.058 ppb
            drift_ppb_x1000: ini.get("time", "drift_ppb_x1000").and_then(|v| v.parse().ok()).unwrap_or(58),
            sign_audit_records: ini.get_bool("audit", "sign_records", true),
        })
    }

    pub fn flash_dir(&self) -> PathBuf {
        self.data_dir.join("flash")
    }
    pub fn keystore_path(&self) -> PathBuf {
        self.data_dir.join("identity").join("keystore.bin")
    }
    pub fn rollback_path(&self) -> PathBuf {
        self.data_dir.join("flash").join("rollback.bin")
    }
    pub fn audit_path(&self) -> PathBuf {
        self.data_dir.join("audit").join("audit.log")
    }
    pub fn crdt_snapshot_path(&self) -> PathBuf {
        self.data_dir.join("crdt.snapshot")
    }
    pub fn idem_path(&self) -> PathBuf {
        self.data_dir.join("idem.snapshot")
    }
    pub fn bundle_path(&self) -> PathBuf {
        self.data_dir.join("trust_bundle.cbor")
    }
    pub fn time_state_path(&self) -> PathBuf {
        self.data_dir.join("time.state")
    }
}
