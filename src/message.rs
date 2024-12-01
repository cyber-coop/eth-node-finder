use crate::types::{HelloMessage, CapabilityMessage, CapabilityName};

const BASE_PROTOCOL_OFFSET: u8 = 16;
const BASE_PROTOCOL_VERSION: usize = 5;

pub fn create_ping_message() -> Vec<u8> {
    let payload = rlp::encode_list(&[0_u8; 0]);
    let code: Vec<u8> = vec![0x02];

    let mut enc = snap::raw::Encoder::new();
    let payload_compressed = enc.compress_vec(&payload).unwrap();

    return [code.to_vec(), payload_compressed].concat();
}

pub fn create_pong_message() -> Vec<u8> {
    let payload = rlp::encode_list(&[0_u8; 0]);
    let code: Vec<u8> = vec![0x03];

    let mut enc = snap::raw::Encoder::new();
    let payload_compressed = enc.compress_vec(&payload).unwrap();

    return [code.to_vec(), payload_compressed].concat();
}

// Create status message following the ETH protocol
pub fn create_status_message(version: &u32, genesis_hash: &Vec<u8>, head_hash: &Vec<u8>, head_td: &u64, fork_id: &Vec<u32>, network_id: &u32) -> Vec<u8> {
    let mut s = rlp::RlpStream::new();
    s.begin_unbounded_list();
    // Protocol version
    s.append(version);
    // network Id
    s.append(network_id);
    // head Td
    s.append(head_td);
    // head Hash
    s.append(head_hash);
    // genesis Hash
    s.append(genesis_hash);
    // fork ID
    s.begin_list(2);
    s.append(&fork_id[0]);
    s.append(&fork_id[1]);

    s.finalize_unbounded_list();

    let payload = s.as_raw();
    let code: Vec<u8> = vec![0x00 + BASE_PROTOCOL_OFFSET];

    let mut enc = snap::raw::Encoder::new();
    let payload_compressed = enc.compress_vec(&payload).unwrap();

    return [code.to_vec(), payload_compressed].concat();
}

pub fn parse_status_message(payload: Vec<u8>) -> u64 {
    let mut dec = snap::raw::Decoder::new();
    let message = dec.decompress_vec(&payload).unwrap();

    let r = rlp::Rlp::new(&message);
    assert!(r.is_list());

    if r.is_empty() {
        return 0;
    }

    // let version: u16 = r.at(0).unwrap().as_val().unwrap();
    let network_id: u64  = r.at(1).unwrap().as_val().unwrap();
    // let td: u16 = r.at(2).unwrap().as_val().unwrap();
    // let blockhash: Vec<u8> = r.at(3).unwrap().as_val().unwrap();
    // let genesis: Vec<u8> = r.at(4).unwrap().as_val().unwrap();

    // get forkid info
    let forkidrlp = r.at(5).unwrap();
    assert!(forkidrlp.is_list());
    let fork_hash: Vec<u8> = forkidrlp.at(0).unwrap().as_val().unwrap();
    let fork_next: u64 = forkidrlp.at(1).unwrap().as_val().unwrap();

    return network_id;
}

pub fn create_hello_message(private_key: &Vec<u8>) -> Vec<u8> {
    let secp = secp256k1::Secp256k1::new();
    let private_key = secp256k1::SecretKey::from_slice(&private_key).unwrap();
    let hello = HelloMessage {
        protocol_version: BASE_PROTOCOL_VERSION,
        client_version: String::from("deadbrain corp."),
        capabilities: vec![
            CapabilityMessage {
                name: CapabilityName("eth".into()),
                version: 67,
            },
            CapabilityMessage {
                name: CapabilityName("eth".into()),
                version: 68,
            },
        ],
        port: 0,
        id: secp256k1::PublicKey::from_secret_key(&secp, &private_key).serialize_uncompressed()[1..].to_vec(),
    };

    let payload = rlp::encode(&hello);
    let code: Vec<u8> = vec![0x80];
    // Add HELLO code in front
    let message = [code.to_vec(), payload.to_vec()].concat();

    return message;
}
