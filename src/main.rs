use std::io::Write;

use chrono::Local;
use env_logger::Builder;
use log::LevelFilter;

use crate::cfg::PeerSessionConfig;
use crate::ch::ClientHelloMsg;
use crate::crypto::X25519KeyPair;
use crate::def::CipherSuite;
use crate::ext::{ClientExtensions, KeyShare};
use crate::session::EarlySession;
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
    let peer = PeerSessionConfig::your_dot_net();

    init_logger(true);
    if let Ok(session) = EarlySession::with_peer(&peer).await {
        println!("server_stream: {:#?}", session);
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
            vec![CipherSuite::TlsAes128GcmSha256],
            extensions
        ).unwrap();
        // log::info!("ClientHelloMsg: {ch:?}");
        let ch_msg_buf: &mut [u8] = &mut [0u8; 1024];
        assert!(matches!(ch.serialize(ch_msg_buf), Ok(_)));
        // log::info!("ClientHelloMsg: {:?}", &ch_msg_buf[0..ch.size() + 8]);

        let mut buf = [0u8; 1024 * 8];
        serv_stream.write(ch_msg_buf).await.expect("write");
        let res = serv_stream.read(7, &mut buf).await;
        let copied = res.unwrap();
        println!("copied {copied} bytes of server's response.");
        // println!("read msg: {:?}", &buf[0..copied]);
    } else {
        log::error!("Error - connect attempt failed for {}", peer.id);
    }
}

#[cfg(test)]
mod tls_cl_tests {
    #[test]
    fn ch_msg_size() {}
}
