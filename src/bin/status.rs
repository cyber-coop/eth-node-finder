use byteorder::{BigEndian, ReadBytesExt};
use log::{error, info};
use secp256k1::rand::RngCore;
use secp256k1::{rand, SecretKey};
use sha3::{Digest, Keccak256};
use std::io::prelude::*;
use std::net::SocketAddr;
use std::{net::TcpStream, time::Duration};
use tokio_postgres::NoTls;

use void::config;
use void::message;
use void::utils;

#[tokio::main]
async fn main() {
    // init logger
    env_logger::init();

    info!("Start getting status from nodes");
    let cfg = config::read_config();

    // Connect to postgres
    let database_params = format!(
        "host={} user={} password={} dbname={}",
        cfg.database.host, cfg.database.user, cfg.database.password, cfg.database.dbname,
    );

    let (postgres_client, connection) = tokio_postgres::connect(&database_params, NoTls)
        .await
        .unwrap();

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            error!("connection error: {}", e);
        }
    });

    let records = postgres_client
        .query("SELECT * FROM discv4.nodes ORDER BY RANDOM();", &[])
        .await
        .unwrap();
    let update_statement = postgres_client.prepare("UPDATE discv4.nodes SET network_id = $1, capabilities = $2, client = $3 WHERE id = $4;").await.unwrap();

    // TODO: don't delete but have a flag to say not active
    let delete_statement = postgres_client
        .prepare("DELETE FROM discv4.nodes WHERE id = $1;")
        .await
        .unwrap();

    let _ = futures::future::join_all(records.iter().map(|record| async {
        let ip: String = record.get(0);
        let port: i32 = record.get(1);
        let remote_id: Vec<u8> = record.get(3);

        // Connect to node
        let addr: SocketAddr = format!("{}:{}", ip, port).parse().unwrap();
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10));

        if stream.is_err() {
            error!(
                "[{}@{}:{}] Couldn't reach node",
                hex::encode(&remote_id),
                ip,
                port
            );
            let _result = postgres_client
                .execute(&delete_statement, &[&remote_id])
                .await
                .unwrap();
            return;
        }

        let mut stream = stream.unwrap();
        // Set read timeout
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let private_key = SecretKey::new(&mut rand::thread_rng())
            .secret_bytes()
            .to_vec();
        let mut nonce = vec![0; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ephemeral_privkey = SecretKey::new(&mut rand::thread_rng())
            .secret_bytes()
            .to_vec();
        let pad = vec![0; 100]; // should be generated randomly but we don't really care

        /******************
         *
         *  Create Auth message (EIP8 supported)
         *
         ******************/
        println!(
            "[{}@{}:{}] Creating EIP8 Auth message",
            hex::encode(&remote_id),
            ip,
            port
        );
        let init_msg =
            utils::create_auth_eip8(&remote_id, &private_key, &nonce, &ephemeral_privkey, &pad);

        // send the message
        println!(
            "[{}@{}:{}] Sending EIP8 Auth message",
            hex::encode(&remote_id),
            ip,
            port
        );
        stream.write(&init_msg).unwrap();
        stream.flush().unwrap();

        println!(
            "[{}@{}:{}] waiting for answer...",
            hex::encode(&remote_id),
            ip,
            port
        );

        /******************
         *
         *  Read Ack
         *
         ******************/

        let mut buf = [0u8; 2];
        let _size = stream.read(&mut buf);

        let size_expected = buf.as_slice().read_u16::<BigEndian>().unwrap() as usize;
        let shared_mac_data = &buf[0..2];

        if size_expected == 0 {
            // Probably doesn't support EIP8
            // ACTUALLY... no it just have the discovery but no node (maybe someone doing like us)
            println!(
                "[{}@{}:{}] Size expected is 0. Something is wrong.",
                hex::encode(&remote_id),
                ip,
                port
            );
            println!("[{}@{}:{}] EIP8 error", hex::encode(&remote_id), ip, port);

            let _result = postgres_client
                .execute(&delete_statement, &[&remote_id])
                .await
                .unwrap();
            return;
        }

        let mut payload = vec![0u8; size_expected.into()];
        let result = stream.read_exact(&mut payload);

        if result.is_err() {
            // TODO: actually show error
            error!(
                "[{}@{}:{}] Unknown error",
                hex::encode(&remote_id),
                ip,
                port
            );
            let _result = postgres_client
                .execute(&delete_statement, &[&remote_id])
                .await
                .unwrap();
            return;
        }

        /******************
         *
         *  Handle Ack
         *
         ******************/

        info!(
            "[{}@{}:{}] ACK message received",
            hex::encode(&remote_id),
            ip,
            port
        );
        let decrypted =
            utils::decrypt_message(&payload.to_vec(), &shared_mac_data.to_vec(), &private_key);

        // decode RPL data
        let rlp = rlp::Rlp::new(&decrypted);
        let mut rlp = rlp.into_iter();

        // id to pubkey
        let remote_public_key: Vec<u8> =
            [vec![0x04], rlp.next().unwrap().as_val().unwrap()].concat();
        let remote_nonce: Vec<u8> = rlp.next().unwrap().as_val().unwrap();

        let ephemeral_shared_secret = utils::ecdh_x(&remote_public_key, &ephemeral_privkey);

        /******************
         *
         *  Setup Frame
         *
         ******************/

        let nonce_material = [remote_nonce.clone(), nonce.clone()].concat();
        let mut hasher = Keccak256::new();
        hasher.update(&nonce_material);
        let h_nonce = hasher.finalize().to_vec();
        let remote_data = [shared_mac_data, &payload].concat();
        let (mut ingress_aes, mut ingress_mac, mut egress_aes, mut egress_mac) = utils::setup_frame(
            remote_nonce,
            nonce,
            ephemeral_shared_secret,
            remote_data,
            init_msg,
            h_nonce,
        );

        info!(
            "[{}@{}:{}] Frame setup done !",
            hex::encode(&remote_id),
            ip,
            port
        );

        info!(
            "[{}@{}:{}] Received Ack, waiting for Header",
            hex::encode(&remote_id),
            ip,
            port
        );

        /******************
         *
         *  Handle HELLO
         *
         ******************/

        let uncrypted_body = utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes);

        if uncrypted_body.is_err() {
            error!("[{}@{}:{}] Time out", hex::encode(&remote_id), ip, port);
            return;
        }
        let uncrypted_body = uncrypted_body.unwrap();

        if uncrypted_body[0] == 0x01 {
            // we have a disconnect message unfortunately
            error!(
                "[{}@{}:{}] Disconnect {}",
                hex::encode(&remote_id),
                ip,
                port,
                hex::encode(uncrypted_body[1..].to_vec())
            );
            return;
        }

        // Should be HELLO
        assert_eq!(0x80, uncrypted_body[0]);
        let hello_message = message::parse_hello_message(uncrypted_body[1..].to_vec());

        let capabilities = serde_json::to_string(&hello_message.capabilities).unwrap();

        // We need to find the highest eth version it supports
        let mut version = 0;
        for capability in &hello_message.capabilities {
            if capability.0.to_string() == "eth" {
                if capability.1 > version {
                    version = capability.1;
                }
            }
        }

        /******************
         *
         *  Create Hello
         *
         ******************/

        info!(
            "[{}@{}:{}] Sending HELLO message",
            hex::encode(&remote_id),
            ip,
            port
        );
        // Create Hello
        let secp = secp256k1::Secp256k1::new();
        let private_key = secp256k1::SecretKey::from_slice(&private_key).unwrap();
        let hello = message::HelloMessage {
            protocol_version: message::BASE_PROTOCOL_VERSION,
            client: String::from("deadbrain corp."),
            capabilities: vec![
                ("eth".into(), 64),
                ("eth".into(), 65),
                ("eth".into(), 66),
                ("eth".into(), 67),
                ("eth".into(), 68),
            ],
            port: 0,
            id: secp256k1::PublicKey::from_secret_key(&secp, &private_key).serialize_uncompressed()
                [1..]
                .to_vec(),
        };

        let payload = message::create_hello_message(hello);
        utils::send_message(payload, &mut stream, &mut egress_mac, &mut egress_aes);

        /******************
         *
         *  Send STATUS message
         *
         ******************/

        info!(
            "[{}@{}:{}] Sending STATUS message",
            hex::encode(&remote_id),
            ip,
            port
        );

        let genesis_hash = [
            212, 229, 103, 64, 248, 118, 174, 248, 192, 16, 184, 106, 64, 213, 245, 103, 69, 161,
            24, 208, 144, 106, 52, 230, 154, 236, 140, 13, 177, 203, 143, 163,
        ];

        let status = message::Status {
            version,
            network_id: 1, // TODO: allow to do random networks
            td: vec![0],
            blockhash: genesis_hash.to_vec(),
            genesis: genesis_hash.to_vec(),
            fork_id: (vec![159, 61, 34, 84], 0),
        };

        // Send STATUS message
        let status = message::create_status_message(status);
        utils::send_message(status, &mut stream, &mut egress_mac, &mut egress_aes);

        /******************
         *
         *  Handle STATUS message
         *
         ******************/

        info!(
            "[{}@{}:{}] Handling STATUS message",
            hex::encode(&remote_id),
            ip,
            port
        );
        let uncrypted_body = utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes);
        if uncrypted_body.is_err() {
            error!("[{}@{}:{}] Time out", hex::encode(&remote_id), ip, port);
            return;
        }
        let uncrypted_body = uncrypted_body.unwrap();

        if uncrypted_body[0] == 0x01 {
            // we have a disconnect message unfortunately
            error!(
                "[{}@{}:{}] Disconnect {}",
                hex::encode(&remote_id),
                ip,
                port,
                hex::encode(uncrypted_body[1..].to_vec())
            );
            return;
        }
        let status = message::parse_status_message(uncrypted_body[1..].to_vec()).unwrap();

        info!(
            "[{}@{}:{}] network_id = {:?}",
            hex::encode(&remote_id),
            ip,
            port,
            &status.network_id
        );

        let cap: Vec<(String, u32)> = serde_json::from_str(&capabilities).unwrap();
        let _result = postgres_client
            .execute(
                &update_statement,
                &[
                    &(status.network_id as i64),
                    &serde_json::to_value(&cap).unwrap(),
                    &hello_message.client,
                    &remote_id,
                ],
            )
            .await
            .unwrap();
    }))
    .await;

    info!("Contacted all the nodes");
}
