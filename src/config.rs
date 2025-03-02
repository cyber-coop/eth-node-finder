use serde::Deserialize;
use std::fs::File;
use std::io::prelude::*;
use toml;

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub user: String,
    pub password: String,
    pub dbname: String,
}

#[derive(Debug, Deserialize)]
pub struct PingConfig {
    pub batch_size: i64,
    pub permits: usize,
    pub timeout: u64,
    pub interval: u64,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub database: DatabaseConfig,
    pub ping: PingConfig,
}

pub fn read_config() -> Config {
    let mut file = File::open("config.toml").expect("config.toml file required");
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    let config: Config = toml::from_str(&contents).unwrap();

    return config;
}
