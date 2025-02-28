use core::time::Duration;
use log::{error, info};
use postgres::{Client, NoTls};
use std::net::TcpStream;

use void::config;

fn main() {
    // init logger
    env_logger::init();

    info!("Starting ping");

    let cfg = config::read_config();

    // Connect to postgres
    let database_params = format!(
        "host={} user={} password={} dbname={}",
        cfg.database.host, cfg.database.user, cfg.database.password, cfg.database.dbname,
    );

    let mut client = Client::connect(&database_params, NoTls).expect("Connection error");

    let timeout_duration = Duration::from_millis(3000);

    for row in client.query("SELECT * FROM discv4.nodes WHERE last_ping_timestamp IS NULL OR (last_ping_timestamp < NOW() - INTERVAL '5 minutes')", &[]).unwrap() {
        let address: String = row.get(0);
        let tcp_port: i32 = row.get(1);
        let _udp_port: i32 = row.get(2);
        let _node_id: Vec<u8> = row.get(3);

        let socket_address = format!("{}:{}", address, tcp_port).parse().unwrap();

        match TcpStream::connect_timeout(&socket_address, timeout_duration) {
            Ok(_) => {
                info!("{} on port {} is working", address, tcp_port);
                if let Err(err) = client.execute(
                    "UPDATE discv4.nodes SET last_ping_timestamp = NOW() WHERE address = $1 AND tcp_port = $2",
                    &[&address, &tcp_port],
                ) {
                    error!("Failed to update row: {}", err);
                }
            }
            Err(_) => {
                error!(
                    "{} on port {} is NOT WORKING...",
                    address, tcp_port
                );
            }
        }
    }
}
