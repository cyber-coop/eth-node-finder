use secp256k1::rand::RngCore;
use secp256k1::SecretKey;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::time::Duration;

use crate::utils;
use crate::types;
use crate::message;

// We return the capabilities the nework id and the agent string. If something fails we return an arror message.
pub async fn connect(address: IpAddr, tcp_port: u16, remote_id: Vec<u8>) -> (Option<Vec<types::CapabilityMessage>>, Option<i64>, Option<String>) {
    // connect to node
    let addr: SocketAddr = format!("{}:{}", address, tcp_port).parse().expect("To be able to parse address");

    let target = format!("{}@{}", hex::encode(&remote_id), addr);

    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(1)) {
        Ok(s) => s,
        Err(_) => {
            warn!(target: &target, "Couldn't reach node");
            return (None, None, None);
        }
    };

    // Set read timeout
    stream
        .set_read_timeout(Some(Duration::from_millis(5000)))
        .unwrap();

    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng())
        .secret_bytes()
        .to_vec();
    let mut nonce = vec![0; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ephemeral_privkey = SecretKey::new(&mut secp256k1::rand::thread_rng())
        .secret_bytes()
        .to_vec();
    let pad = vec![0; 100]; // should be generated randomly but we don't really care

    info!(target: &target, "Creating EIP8 Auth message");
    let init_msg =
        utils::create_auth_eip8(&remote_id, &private_key, &nonce, &ephemeral_privkey, &pad);

    // send the message
    info!(target: &target, "Sending EIP8 Auth message");
    if let Err(_) = utils::send_eip8_auth_message(&init_msg, &mut stream) {
        return (None, None, None);
    };

    // Handle Ack
    let (payload, shared_mac_data) = match utils::read_ack_message(&mut stream) {
        Ok((payload, shared_mac_data)) => (payload, shared_mac_data),
        Err(_) => {
            return (None, None, None);
        }
    };

    if payload[0] != 0x04 {
        return (None, None, None);
    }

    let (_remote_public_key, remote_nonce, ephemeral_shared_secret) =
        utils::handle_ack_message(&payload, &shared_mac_data, &private_key, &ephemeral_privkey);

    // Setup Frame
    let remote_data = [shared_mac_data, payload].concat();
    let (mut ingress_aes, mut ingress_mac, mut egress_aes, mut egress_mac) = utils::setup_frame(
        remote_nonce,
        nonce,
        ephemeral_shared_secret,
        remote_data,
        init_msg,
    );

    info!(target: &target, "Received Ack, waiting for Hello");

    // Handle HELLO
    let uncrypted_body = utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes);

    if uncrypted_body.is_err() {
        warn!(target: &target, "Time out");
        return (None, None, None);
    }
    let uncrypted_body = uncrypted_body.unwrap();

    if uncrypted_body[0] == 0x01 {
        // we have a disconnect message unfortunately
        warn!(target: &target,
            "Disconnect {}",
            hex::encode(uncrypted_body[1..].to_vec())
        );
        return (None, None, None);
    }

    // Should be HELLO
    assert_eq!(0x80, uncrypted_body[0]);
    let payload = rlp::decode::<types::HelloMessage>(&uncrypted_body[1..]);

    if payload.is_err() {
        warn!(target: &target,
            "Couldn't read payload",
        );
        return (None, None, None);
    }

    let hello_message = payload.unwrap();
    info!("{:?}", &hello_message);

    // We need to find the highest eth version it supports
    let mut version = 0;
    for capability in &hello_message.capabilities {
        if capability.name.0.to_string() == "eth" {
            if capability.version > version {
                version = capability.version;
            }
        }
    }

    info!(target: &target,
        "Sending HELLO message",
    );
    // Create Hello
    let hello = message::create_hello_message(&private_key);
    utils::send_message(hello, &mut stream, &mut egress_mac, &mut egress_aes);

    info!(target: &target,
        "Sending STATUS message",
    );

    let genesis_hash = [
        212, 229, 103, 64, 248, 118, 174, 248, 192, 16, 184, 106, 64, 213, 245, 103, 69, 161, 24,
        208, 144, 106, 52, 230, 154, 236, 140, 13, 177, 203, 143, 163,
    ]
    .to_vec();
    let head_td = 0;
    let fork_id = [0x9f3d2254, 0].to_vec();
    let network_id = 1;

    // Send STATUS message
    let status = message::create_status_message(
        &version,
        &genesis_hash,
        &genesis_hash,
        &head_td,
        &fork_id,
        &network_id,
    );
    utils::send_message(status, &mut stream, &mut egress_mac, &mut egress_aes);

    info!(target: &target,
        "Handling STATUS message",
    );
    // Handle STATUS message
    let uncrypted_body = utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes);
    if uncrypted_body.is_err() {
        warn!(target: &target,
            "Time out",
        );
        return (Some(hello_message.capabilities), None, Some(hello_message.client_version));
    }
    let uncrypted_body = uncrypted_body.unwrap();
    if uncrypted_body[0] == 0x01 {
        // let mut dec = snap::raw::Decoder::new();
        // let message = dec.decompress_vec(&uncrypted_body[1..].to_vec()).unwrap();
        // we have a disconnect message unfortunately
        warn!(target: &target,
            "Disconnect {}",
            hex::encode(&uncrypted_body)
        );
        return (Some(hello_message.capabilities), None, Some(hello_message.client_version));
    }
    let network_id = message::parse_status_message(uncrypted_body[1..].to_vec());

    info!(target: &target,
        "networkid = {}",
        &network_id
    );

    return (Some(hello_message.capabilities), Some(network_id as i64), Some(hello_message.client_version));
}
