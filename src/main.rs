use std::cmp::min;
use std::io::Write;
use chrono::Local;
use env_logger::Builder;
use log::LevelFilter;

use crate::cfg::PeerSessionConfig;
use crate::ch::ClientHelloMsg;
use crate::crypto::{P256KeyPair, X25519KeyPair};
use crate::ext::{ClientExtensions, KeyShare};
use crate::session::EarlySession;
use crate::sh::ServerHelloMsg;
use crate::sock::Stream;

mod sock;
mod err;
mod def;
mod cfg;
mod session;
mod protocol;
mod cipher;
mod ecdhe;
mod ext;
mod ch;
mod crypto;
mod sh;

pub fn init_logger(allow_test: bool) {
    let _ = Builder::new()
        .format(|buf, record| {
            writeln!(buf,
                     "{} [{}] - {}",
                     Local::now().format("%Y-%m-%dT%H:%M:%S"),
                     record.level(),
                     record.args()
            )
        })
        .filter(None, LevelFilter::Info)
        .is_test(!allow_test)
        .format_timestamp_secs()
        .try_init();
}

#[tokio::main]
async fn main() {
    let peer = PeerSessionConfig::ebay();

    init_logger(true);
    if let Ok(session) = EarlySession::with_peer(&peer).await {
        log::info!("server_stream: {} - {}", peer.id, peer.tls_addr);
        let serv_stream = session.stream;

        let random: Vec<u8> = crypto::CryptoRandom::<32>::bytes().to_vec();
        let x25519_key_pair = X25519KeyPair::default();
        let _x25519_key_share = KeyShare::x25519(x25519_key_pair.public_bytes());

        let p256_key_pair = P256KeyPair::default();
        let p256_key_share = KeyShare::secp256r1(p256_key_pair.public_bytes().as_bytes());

        let extensions = ClientExtensions::try_from(
            (
                peer.id.as_str(),
                peer.sig_algs.as_slice(),
                peer.dh_groups.as_slice(),
                [p256_key_share].as_slice()
                // [x25519_key_share].as_slice()
                // [p256_key_share, x25519_key_share].as_slice()
            )
        ).unwrap();
        let ch = ClientHelloMsg::try_from(
            random.try_into().unwrap(),
            peer.cipher_suites,
            extensions
        ).unwrap();
        log::info!("ClientHelloMsg: {ch:?}");
        let ch_msg_buf: &mut [u8] = &mut [0u8; 1024];
        assert!(matches!(ch.serialize(ch_msg_buf), Ok(_)));
        log::info!("ClientHelloMsg: {:?}", &ch_msg_buf[0..ch.size()]);

        let mut buf = [0u8; 1024 * 8];
        serv_stream.write(ch_msg_buf).await.expect("write");
        let res = serv_stream.read(1024, &mut buf).await;
        let copied = res.unwrap();
        println!("copied {copied} bytes of server's response {:?}", &buf[0..min(7, copied)]);

        log::info!("{:?}", ServerHelloMsg::deserialize(&buf[0..copied]));
    } else {
        log::error!("Error - connect attempt failed for {}", peer.id);
    }
}

#[cfg(test)]
mod tls_cl_tests {
    use crate::{crypto, init_logger};
    use crate::cfg::PeerSessionConfig;
    use crate::ch::ClientHelloMsg;
    use crate::crypto::X25519KeyPair;
    use crate::ext::{ClientExtensions, KeyShare};
    use crate::session::EarlySession;
    use crate::sh::ServerHelloMsg;
    use crate::sock::Stream;

    // Section 4.1.4 Hello Retry Request, pages 33 and 34.
    // Checks for Hello Retry response in the ServerHello.
    // spacex TLS looks for a P256 key share while we supply a x25519 key share in ClientHello.
    // Therefore, the server asks client to retry with a fresh ClientHello.
    // In addition, the key value will be empty on the key share extension in ServerHello.
    #[tokio::test(flavor = "multi_thread")]
    async fn spacex_hello_retry() {
        init_logger(true);
        let peer = PeerSessionConfig::spacex();
        if let Ok(session) = EarlySession::with_peer(&peer).await {
            // log::info!("server_stream: {} - {}", peer.id, peer.tls_addr);
            let serv_stream = session.stream;

            let random: Vec<u8> = crypto::CryptoRandom::<32>::bytes().to_vec();
            let x25519_key_pair = X25519KeyPair::default();
            let x25519_key_share = KeyShare::x25519(x25519_key_pair.public_bytes());

            let extensions = ClientExtensions::try_from(
                (
                    peer.id.as_str(),
                    peer.sig_algs.as_slice(),
                    peer.dh_groups.as_slice(),
                    [x25519_key_share].as_slice()
                )
            ).unwrap();
            let ch = ClientHelloMsg::try_from(
                random.try_into().unwrap(),
                peer.cipher_suites,
                extensions
            ).unwrap();
            let ch_msg_buf: &mut [u8] = &mut [0u8; 1024];
            assert!(matches!(ch.serialize(ch_msg_buf), Ok(_)));

            let mut buf = [0u8; 1024 * 8];
            serv_stream.write(ch_msg_buf).await.expect("write");
            let res = serv_stream.read(1024, &mut buf).await;
            let copied = res.unwrap();
            let sh = ServerHelloMsg::deserialize(&buf[0..copied]);
            assert!(sh.unwrap().is_server_retry());
        } else {
            log::error!("Error - connect attempt failed for {}", peer.id);
            assert!(false);
        }
    }
}
