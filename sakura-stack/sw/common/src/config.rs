//! Минимальный INI-парсер конфигурации узлов (без внешних зависимостей).
//! Секции: [node], [cluster], [hsm], [policy], [update], [http].

use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Debug, Default)]
pub struct Ini {
    pub sections: BTreeMap<String, BTreeMap<String, String>>,
}

impl Ini {
    pub fn parse(text: &str) -> Self {
        let mut ini = Ini::default();
        let mut cur = String::from("default");
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                cur = line[1..line.len() - 1].trim().to_owned();
                ini.sections.entry(cur.clone()).or_default();
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                ini.sections
                    .entry(cur.clone())
                    .or_default()
                    .insert(k.trim().to_owned(), v.trim().to_owned());
            }
        }
        ini
    }

    pub fn load(path: impl AsRef<Path>) -> std::io::Result<Self> {
        Ok(Self::parse(&std::fs::read_to_string(path)?))
    }

    pub fn get(&self, sec: &str, key: &str) -> Option<&str> {
        self.sections.get(sec)?.get(key).map(|s| s.as_str())
    }

    pub fn get_or(&self, sec: &str, key: &str, def: &str) -> String {
        self.get(sec, key).unwrap_or(def).to_owned()
    }

    pub fn get_u64(&self, sec: &str, key: &str, def: u64) -> u64 {
        self.get(sec, key).and_then(|v| v.parse().ok()).unwrap_or(def)
    }

    pub fn get_u32(&self, sec: &str, key: &str, def: u32) -> u32 {
        self.get(sec, key).and_then(|v| v.parse().ok()).unwrap_or(def)
    }

    pub fn get_u16(&self, sec: &str, key: &str, def: u16) -> u16 {
        self.get(sec, key).and_then(|v| v.parse().ok()).unwrap_or(def)
    }

    pub fn get_bool(&self, sec: &str, key: &str, def: bool) -> bool {
        self.get(sec, key)
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(def)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ini_parse() {
        let ini = Ini::parse(
            "\
[node]
id = 3
listen = 127.0.0.1:9103
debug = true
# comment
[cluster]
members = 4
",
        );
        assert_eq!(ini.get_u64("node", "id", 0), 3);
        assert_eq!(ini.get_or("node", "listen", ""), "127.0.0.1:9103");
        assert!(ini.get_bool("node", "debug", false));
        assert_eq!(ini.get_u64("cluster", "members", 0), 4);
        assert_eq!(ini.get_or("node", "missing", "def"), "def");
        assert!(!ini.get_bool("node", "missing", false));
    }
}
