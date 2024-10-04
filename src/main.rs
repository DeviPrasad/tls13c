mod ccs;
mod cert;
mod cfg;
mod ch;
mod cipher;
mod client;
mod def;
mod deser;
mod ecdhe;
mod enc_ext;
mod err;
mod ext;
mod fin;
mod logger;
mod rand;
mod rec;
mod session;
mod sh;
mod stream;
mod types;

fn main() {
    logger::init_logger(true);

    if let Err(e) = client::client_main() {
        log::error!("{e:#?}");
    }
}

#[cfg(test)]
mod tls_cl_tests {
    use crate::cfg::PeerSessionConfig;
    use crate::ch::ClientHelloMsg;
    use crate::deser::DeSer;
    use crate::ecdhe::X25519KeyPair;
    use crate::ext::{ClientExtensions, ServerSessionPublicKey};
    use crate::rand;
    use crate::sh::ServerHelloMsg;
    use crate::stream::{Stream, TlsConnection};

    // Section 4.1.4 Hello Retry Request, pages 33 and 34.
    // Checks for Hello Retry response in the ServerHello.
    // spacex TLS looks for a P256 key share while we supply a x25519 key share in ClientHello.
    // Therefore, the server asks client to retry with a fresh ClientHello.
    // In addition, the key value will be empty on the key share extension in ServerHello.
    #[test]
    fn spacex_hello_retry() {
        let peer = PeerSessionConfig::spacex();
        if let Ok(session) = TlsConnection::with_peer(&peer) {
            let mut serv_stream = session.stream;

            let random: Vec<u8> = rand::CryptoRandom::<32>::bytes().to_vec();
            let x25519_key_pair = X25519KeyPair::default();
            let x25519_key_share = ServerSessionPublicKey::x25519(x25519_key_pair.public_bytes());

            let extensions_data = ClientExtensions::try_from((
                peer.id.as_str(),
                peer.sig_algs.as_slice(),
                peer.dh_groups.as_slice(),
                [x25519_key_share].as_slice(),
            ))
            .unwrap();

            let ch = ClientHelloMsg::try_from(
                random.try_into().unwrap(),
                peer.cipher_suites,
                extensions_data,
            )
            .unwrap();

            let mut ch_msg_buf = vec![0u8; ch.size()];
            let res = ch.serialize(ch_msg_buf.as_mut_slice());
            assert!(res.is_ok());

            let mut buf = Vec::new();
            serv_stream.write(&ch_msg_buf).expect("write");
            let res = serv_stream.read(1024, &mut buf);
            let copied = res.unwrap();
            let mut deser = DeSer::new(&buf[0..copied]);
            let (sh, _) = ServerHelloMsg::deserialize(&mut deser).unwrap();
            assert!(sh.is_server_retry());
        } else {
            eprintln!("Error - connect attempt failed for {}", peer.id);
            panic!();
        }
    }
}
