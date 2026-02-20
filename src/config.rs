use std::env;
use std::time::Duration;

use thiserror::Error;
use tracing::Level;

#[derive(Debug, Clone)]
pub(crate) struct SocksConfig {
    pub(crate) connect_timeout: Duration,
    pub(crate) read_timeout: Duration,
    pub(crate) write_timeout: Duration,
}

#[derive(Debug, Clone)]
pub(crate) struct AppConfig {
    pub(crate) listen_addr: String,
    pub(crate) shutdown_timeout: Duration,
    pub(crate) log_level: Level,
    pub(crate) socks: SocksConfig,
}

#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    #[error("invalid value for {var}: {value}")]
    InvalidEnv { var: &'static str, value: String },
}

impl AppConfig {
    pub(crate) fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            listen_addr: env::var("TP_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:7878".to_string()),
            shutdown_timeout: duration_from_env("TP_SHUTDOWN_TIMEOUT_SECS", 20)?,
            log_level: log_level_from_env("TP_LOG_LEVEL", Level::INFO)?,
            socks: SocksConfig {
                connect_timeout: duration_from_env("TP_CONNECT_TIMEOUT_SECS", 10)?,
                read_timeout: duration_from_env("TP_READ_TIMEOUT_SECS", 5)?,
                write_timeout: duration_from_env("TP_WRITE_TIMEOUT_SECS", 5)?,
            },
        })
    }
}

fn duration_from_env(var: &'static str, default_secs: u64) -> Result<Duration, ConfigError> {
    match env::var(var) {
        Ok(raw) => match raw.parse::<u64>() {
            Ok(secs) => Ok(Duration::from_secs(secs)),
            Err(_) => Err(ConfigError::InvalidEnv { var, value: raw }),
        },
        Err(_) => Ok(Duration::from_secs(default_secs)),
    }
}

fn log_level_from_env(var: &'static str, default: Level) -> Result<Level, ConfigError> {
    match env::var(var) {
        Ok(raw) => match raw.to_ascii_lowercase().as_str() {
            "trace" => Ok(Level::TRACE),
            "debug" => Ok(Level::DEBUG),
            "info" => Ok(Level::INFO),
            "warn" => Ok(Level::WARN),
            "error" => Ok(Level::ERROR),
            _ => Err(ConfigError::InvalidEnv { var, value: raw }),
        },
        Err(_) => Ok(default),
    }
}
