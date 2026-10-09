//! sakura-node — библиотека подсистем узла (транспорт/сессии NPP,
//! конфигурация, control-хранилища, HTTP management, время, watchdog).
//! Исполняемая среда узла — в bin sakura-node (main.rs).
#![forbid(unsafe_code)]

pub mod config;
pub mod control;
pub mod http;
pub mod net;
pub mod time;
pub mod watchdog;
