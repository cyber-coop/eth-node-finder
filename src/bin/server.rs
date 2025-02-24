use log::{error, warn, info};
use std::net::TcpListener;
use std::net::TcpStream;
use std::error::Error;
use secp256k1::SecretKey;
use rand::RngCore;
use sha3::{Digest, Keccak256};
use discv4::Node;
use tokio_postgres::NoTls;

static SERVER_ADDRESS: &str = "0.0.0.0";
static SERVER_PORT: u16 = 50505;

use void::utils;
use void::message;
use void::networks;
use void::config;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // init logger
    env_logger::init();
    // tracing_subscriber::fmt::init();

    info!("Starting server");

    let cfg = config::read_config();
    // Connect to postgres
    let database_params = format!(
        "host={} user={} password={} dbname={}",
        cfg.database.host, cfg.database.user, cfg.database.password, cfg.database.dbname,
    );
    let (postgres_client, connection) = tokio_postgres::connect(&database_params, NoTls)
        .await
        .unwrap();
    info!("Connection to the database created");
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            error!("connection error: {}", e);
        }
    });

    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
    let secp = secp256k1::Secp256k1::new();

    let id = secp256k1::PublicKey::from_secret_key(&secp, &private_key).serialize_uncompressed()[1..].to_vec();

    let _node = Node::new(
        format!("0.0.0.0:{}", SERVER_PORT).parse().unwrap(),
        private_key,
        networks::BOOTSTRAP_NODES.iter().map(|v| v.parse().unwrap()).collect(),
        None,
        true,
        SERVER_PORT,
    )
    .await
    .unwrap();

    info!("Remote id {}", hex::encode(id));

    let private_key = private_key.secret_bytes();

    let listener = TcpListener::bind(format!("{SERVER_ADDRESS}:{SERVER_PORT}")).unwrap();
    info!("Server started on {SERVER_ADDRESS}:{SERVER_PORT}");
    
    loop {
        let (mut socket, addr) = listener.accept().unwrap();
        info!("New connection: {:?}", addr);

        tokio::spawn(async move {
            if let Err(err) = handle_connection(&mut socket, &private_key.to_vec(), networks::Network::ETHEREUM_MAINNET).await {
                error!("Failed to handle connection request : {}", err.to_string());
            };
        });
    }
}

async fn handle_connection(stream: &mut TcpStream, private_key: &Vec<u8>, network: networks::Network) -> Result<(), Box<dyn Error>> {

    let mut nonce = vec![0; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ephemeral_privkey = SecretKey::new(&mut secp256k1::rand::thread_rng())
        .secret_bytes()
        .to_vec();
    let pad = vec![0; 100]; // should be generated randomly but we don't really care

    // Handle auth eip8 message
    let (payload, shared_mac_data) = utils::read_auth_eip8(stream).unwrap();
    let (remote_id, remote_nonce, ephemeral_shared_secret) = utils::verify_auth_eip8(&payload, &shared_mac_data, private_key, &ephemeral_privkey);

    // Send Ack message
    let init_msg = utils::create_ack(&remote_id, &nonce, &ephemeral_privkey, &pad);
    utils::send_ack_message(&init_msg, stream)?;


    // Setup Frame
    // IMPORTANT!!! When receiving connection we reverse nonce order (see https://github.com/paradigmxyz/reth/blob/main/crates/net/ecies/src/algorithm.rs#L584C31-L584C39)
    let nonce_material = [nonce.clone(), remote_nonce.clone()].concat();
    let mut hasher = Keccak256::new();
    hasher.update(&nonce_material);
    let h_nonce = hasher.finalize().to_vec();
    let remote_data = [shared_mac_data, payload].concat();
    let (mut ingress_aes, mut ingress_mac, mut egress_aes, mut egress_mac) = utils::setup_frame(
        remote_nonce,
        nonce,
        ephemeral_shared_secret,
        remote_data,
        init_msg,
        h_nonce
    );

    info!("Sending HELLO message");
    // Create Hello
    let secp = secp256k1::Secp256k1::new();
    let private_key = secp256k1::SecretKey::from_slice(&private_key).unwrap();
    let hello = message::HelloMessage {
        protocol_version: message::BASE_PROTOCOL_VERSION,
        client: String::from("deadbrain corp."),
        capabilities: vec![("eth".into(), 67), ("eth".into(), 68)],
        port: 0,
        id: secp256k1::PublicKey::from_secret_key(&secp, &private_key).serialize_uncompressed()[1..].to_vec(),
    };
    
    let hello = message::create_hello_message(hello);
    utils::send_message(hello, stream, &mut egress_mac, &mut egress_aes);

    // Handle HELLO
    let uncrypted_body = match utils::read_message(stream, &mut ingress_mac, &mut ingress_aes) {
        Ok(ub) => ub,
        Err(err) => { return Err(format!("{:?}", err).into()); }
    };

    if uncrypted_body[0] == 0x01 {
        // we have a disconnect message unfortunately
        error!("Disconnect {}",
            hex::encode(uncrypted_body[1..].to_vec())
        );
        return Err("Received disconnect message".into());
    }

    // Should be HELLO
    assert_eq!(0x80, uncrypted_body[0]);
    let hello_message = message::parse_hello_message(uncrypted_body[1..].to_vec());
    info!("{:?}", &hello_message);

    // We need to find the highest eth version it supports
    let mut version = 0;
    for capability in &hello_message.capabilities {
        if capability.0.to_string() == "eth" {
            if capability.1 > version {
                version = capability.1;
            }
        }
    }
    
    info!("Handling STATUS message");
    let uncrypted_body = utils::read_message(stream, &mut ingress_mac, &mut ingress_aes).unwrap();
    if uncrypted_body[0] == 0x01 {
        warn!("Disconnect message : {}", hex::encode(&uncrypted_body));

        return Err("Disconnected peer".into());
    }
    let status = message::parse_status_message(uncrypted_body[1..].to_vec()).unwrap();

    info!("Found status {:?}", &status);

    info!("Sending STATUS message");
    let status = message::Status {
        version,
        network_id: network.network_id, // TODO: allow to do random networks
        td: network.head_td.to_be_bytes().to_vec(),
        blockhash: network.genesis_hash.to_vec(),
        genesis: network.genesis_hash.to_vec(),
        fork_id: (network.fork_id[0].to_be_bytes().to_vec(), network.fork_id[1].into()),
    };

    let status = message::create_status_message(status);
    utils::send_message(status, stream, &mut egress_mac, &mut egress_aes);

    Ok(())
}