use std::io::Write;
use std::time::UNIX_EPOCH;

use env_logger::Builder;
use log::LevelFilter;

use crate::cfg::PeerSessionConfig;
use crate::ch::ClientHelloMsg;
use crate::crypto::{P256KeyPair, X25519KeyPair};
use crate::def::{SupportedGroup, to_u16};
use crate::deser::DeSer;
use crate::ext::{ClientExtensions, KeyShare};
use crate::protocol::ChangeCipherSpecMsg;
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
mod deser;
mod cert;
mod enc_ext;
mod key_sched;
mod fin;

fn duration_min_sec() -> String {
    let now = std::time::SystemTime::now();
    let dur = now.duration_since(UNIX_EPOCH).unwrap();
    let sec = dur.as_secs();
    let min = sec / 60;
    format!("{:02}:{:02}", min % 60, sec % 60)
}

pub fn init_logger(allow_test: bool) {
    let _ = Builder::new()
        .format(|buf, record| {
            writeln!(buf,
                     "{:?} [{}] - {}",
                     duration_min_sec(),
                     record.level(),
                     record.args()
            )
        })
        .filter(None, LevelFilter::Info)
        .is_test(!allow_test)
        .format_timestamp_secs()
        .try_init();
}

fn main() {
    let peer = PeerSessionConfig::microsoft();

    init_logger(true);
    if let Ok(session) = EarlySession::with_peer(&peer) {
        log::info!("server_stream: {} - {}", peer.id, peer.tls_addr);
        let mut serv_stream = session.stream;

        let random: Vec<u8> = crypto::CryptoRandom::<32>::bytes().to_vec();
        let x25519_key_pair = X25519KeyPair::default();
        let x25519_key_share = KeyShare::x25519(x25519_key_pair.public_bytes());

        let p256_key_pair = P256KeyPair::default();
        let p256_key_share = KeyShare::secp256r1(p256_key_pair.public_bytes().as_bytes());

        let mut msg_ctx: Vec<u8> = Vec::new();

        let ch = {
            let extensions_data = ClientExtensions::try_from(
                (
                    peer.id.as_str(),
                    peer.sig_algs.as_slice(),
                    peer.dh_groups.as_slice(),
                    // [p256_key_share].as_slice()
                    // [x25519_key_share].as_slice()
                    // [p256_key_share, x25519_key_share].as_slice()
                    [x25519_key_share, p256_key_share].as_slice()
                )
            ).unwrap();
            let ch = ClientHelloMsg::try_from(
                random.try_into().unwrap(),
                peer.cipher_suites,
                extensions_data.clone()
            ).unwrap();
            log::info!("ClientHelloMsg: {ch:?}");
            ch
        };
        {
            let mut ch_data_buf = [0u8; 1024];
            {
                let ch_buf_start = 0;
                assert!(matches!(ch.serialize(&mut ch_data_buf), Ok(_)));
                // log::info!("ClientHelloMsg: {:?}", &ch_data_buf[ch_buf_start + 5..ch_buf_start + ch.size()]);

                let n = serv_stream.write(&ch_data_buf[ch_buf_start..ch_buf_start + ch.size()])
                    //.await
                                   .expect("ClientHello message");
                assert_eq!(n, ch.size());
            };
            msg_ctx.extend_from_slice(&ch_data_buf[5..ch.size()]);
        }

        {
            let mut handshake_data = Vec::with_capacity(2 * 1024);
            let copied_size = serv_stream.read(1024, &mut handshake_data)
                                         .expect("ServerHello message");
            let (sh, sh_msg_end) = {
                //log::info!("read {copied_size} bytes from server: {:?}", &handshake_data[0..min(14, copied_size)]);
                log::info!("read {copied_size} bytes from server: {}", session.peer.id);
                let sh_data_buf_start = 0;
                let mut sh_deser = &mut DeSer::new(&handshake_data[sh_data_buf_start..sh_data_buf_start + copied_size]);
                let (sh, sh_msg_start_offset) = ServerHelloMsg::deserialize(&mut sh_deser).unwrap();
                assert_eq!(sh_msg_start_offset, 5);
                let sh_msg_start = sh_data_buf_start + sh_msg_start_offset;
                let sh_msg_end = sh_msg_start + sh.fragment_len as usize;
                log::info!("{:?}", sh);
                // log::info!("ServerHelloMsg buf size {:?}", &handshake_data[sh_msg_start..sh_msg_end].len());
                //log::info!("ServerHelloMsg buf {:?}", &handshake_data[sh_msg_start..sh_msg_end]);

                msg_ctx.extend_from_slice(&handshake_data[sh_msg_start..sh_msg_end]);
                (sh, sh_msg_end)
            };

            let enc_data_start = {
                let mut cipher_change_deser = &mut DeSer::new(&handshake_data[sh_msg_end..sh_msg_end + 6]);
                let change_cipher_spec = ChangeCipherSpecMsg::deserialize(&mut cipher_change_deser).unwrap();
                sh_msg_end + change_cipher_spec.map_or(0, |(_, size)| size)
            };

            let mut cipher = {
                // time to derive a few cryptographic secrets for handshake authentication,
                // first, compute DH shared secret
                let server_key_share = sh.extensions.0;

                let mut public_key: Option<Vec<u8>> = None;
                for client_key_share in ch.key_shares().extensions() {
                    if client_key_share.group == server_key_share.group {
                        if client_key_share.group == SupportedGroup::X25519 {
                            public_key = Some(server_key_share.public_key);
                            break;
                        } else if client_key_share.group == SupportedGroup::Secp256r1 {
                            public_key = Some(server_key_share.public_key);
                            break;
                        }
                    }
                };

                let dh_shared_secret: Vec<u8> =
                    public_key.map_or(vec![], |pk| {
                        if server_key_share.group == SupportedGroup::X25519 {
                            let dh_res = x25519_key_pair.dh(pk.try_into().unwrap());
                            dh_res.to_bytes().as_slice().to_vec()
                        } else if server_key_share.group == SupportedGroup::Secp256r1 {
                            let dh_res = p256_key_pair.dh(&pk).unwrap();
                            dh_res.raw_secret_bytes().as_slice().to_vec()
                        } else {
                            vec![]
                        }
                    });
                assert!(!dh_shared_secret.is_empty());

                // time to create a key schedule before we go and grab encrypted extensions
                let key_sched = cipher::tls_cipher_suite_try_from(sh.cipher_suite).unwrap();
                let (key, nonce) =
                    key_sched.derive_server_handshake_authn_secrets(
                        &dh_shared_secret,
                        &msg_ctx);
                let cipher = key_sched.server_authn_cipher(key, nonce);
                log::info!("key schedule created!");
                cipher
            };

            // pass 1 - receive records arriving in a sequence of flights.
            let mut enc_msg_start = enc_data_start;
            while enc_msg_start < handshake_data.len() {
                let enc_msg_len = to_u16(handshake_data[enc_msg_start + 3],
                                         handshake_data[enc_msg_start + 4]) as usize;
                let enc_msg_end = enc_msg_start + 5 + enc_msg_len;
                // log::info!("current capacity: {}, enc_msg_start = {enc_msg_start}, enc_msg_len = {enc_msg_len}, enc_msg_end = {enc_msg_end}", handshake_data.len());
                if enc_msg_end > handshake_data.len() {
                    log::info!("\nRefilling at least {} bytes\n", enc_msg_end - handshake_data.len());
                    serv_stream.read(enc_msg_end - handshake_data.len(), &mut handshake_data)
                        //.await
                               .expect("ServerHello message");
                    log::info!("refilled. enc_msg_end = {enc_msg_end}, enc_msg_len = {enc_msg_len},  {}", handshake_data.len());
                }
                enc_msg_start = enc_msg_end;
            }

            // pass 2 - decrypt records and collect the data in a fresh buffer for processing.
            let mut enc_msg_start = enc_data_start;
            while enc_msg_start < handshake_data.len() {
                let ad = handshake_data[enc_msg_start..enc_msg_start + 5].to_vec();
                log::info!("enc msg aad {:?}", &ad);
                let enc_msg_len = to_u16(handshake_data[enc_msg_start + 3],
                                         handshake_data[enc_msg_start + 4]) as usize;
                let enc_msg_end = enc_msg_start + 5 + enc_msg_len;
                let mut dec_data_buf = (&handshake_data[enc_msg_start + 5..enc_msg_end]).to_vec();
                cipher.decrypt_next(&ad, &mut dec_data_buf).expect("decrypt extensions");
                log::info!("decrypted data {:?}", &dec_data_buf[0..7]);
                enc_msg_start = enc_msg_end;
            }
        }

        log::info!("Done! Shutting down the connection....");
        serv_stream.shutdown()
            //.await
                   .expect("server shutdown");
    }
}

#[cfg(test)]
mod tls_cl_tests {
    use crate::{crypto, init_logger};
    use crate::cfg::PeerSessionConfig;
    use crate::ch::ClientHelloMsg;
    use crate::crypto::X25519KeyPair;
    use crate::deser::DeSer;
    use crate::ext::{ClientExtensions, KeyShare};
    use crate::session::EarlySession;
    use crate::sh::ServerHelloMsg;
    use crate::sock::Stream;

    // Section 4.1.4 Hello Retry Request, pages 33 and 34.
    // Checks for Hello Retry response in the ServerHello.
    // spacex TLS looks for a P256 key share while we supply a x25519 key share in ClientHello.
    // Therefore, the server asks client to retry with a fresh ClientHello.
    // In addition, the key value will be empty on the key share extension in ServerHello.
    #[test]
    fn spacex_hello_retry() {
        init_logger(true);
        let peer = PeerSessionConfig::spacex();
        if let Ok(session) = EarlySession::with_peer(&peer) {
            let mut serv_stream = session.stream;

            let random: Vec<u8> = crypto::CryptoRandom::<32>::bytes().to_vec();
            let x25519_key_pair = X25519KeyPair::default();
            let x25519_key_share = KeyShare::x25519(x25519_key_pair.public_bytes());

            let extensions_data = ClientExtensions::try_from(
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
                extensions_data
            ).unwrap();
            let mut ch_msg_buf = vec![0u8; ch.size()];
            assert!(matches!(ch.serialize(ch_msg_buf.as_mut_slice()), Ok(_)));

            let mut buf = Vec::with_capacity(2048);
            serv_stream.write(&ch_msg_buf)
                       .expect("write");
            let res = serv_stream.read(1024, &mut buf); //.await;
            let copied = res.unwrap();
            let mut deser = DeSer::new(&buf[0..copied]);
            let (sh, _) = ServerHelloMsg::deserialize(&mut deser).unwrap();
            assert!(sh.is_server_retry());
        } else {
            log::error!("Error - connect attempt failed for {}", peer.id);
            assert!(false);
        }
    }
}
