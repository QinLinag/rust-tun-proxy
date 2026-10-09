use serde::Deserialize;
use std::{fs, path::Path};

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub tun: TunConfig,
    pub fake_ip: FakeIpConfig,
    pub proxy: ProxyConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TunConfig {
    pub address: String,
    pub destination: String,
    pub netmask: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FakeIpConfig {
    pub start: String,
    pub netmask:String,
    pub expire_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ProxyConfig {
    Socks5 {
        address: String,
    },

    Shadowsocks {
        address: String,
        method: String,
        password: String,
    },
}

impl AppConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config = toml::from_str(&content)?;
        Ok(config)
    }
}