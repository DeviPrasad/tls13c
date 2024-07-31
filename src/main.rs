use std::io::Write;
use std::time::UNIX_EPOCH;

use env_logger::Builder;
use log::LevelFilter;

use crate::ccs::ChangeCipherSpecMsg;
use crate::cfg::PeerSessionConfig;
use crate::ch::ClientHelloMsg;
use crate::crypto::{P256KeyPair, X25519KeyPair};
use crate::def::{HandshakeType, RecordContentType, SupportedGroup};
use crate::deser::DeSer;
use crate::err::Mutter;
use crate::ext::{ClientExtensions, KeyShare};
use crate::fin::FinishedMsg;
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
mod ccs;

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
        .try_init()
        .expect("init_logger");
}

fn main() {
    init_logger(true);

    let peer = PeerSessionConfig::facebook();

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
                                   .expect("ClientHello message");
                assert_eq!(n, ch.size());
            };
            msg_ctx.extend_from_slice(&ch_data_buf[5..ch.size()]);
        }

        {
            let mut handshake_data = Vec::new();
            let copied_size = serv_stream.read(750, &mut handshake_data).expect("ServerHello message");

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

                msg_ctx.extend_from_slice(&handshake_data[sh_msg_start..sh_msg_end]);
                (sh, sh_msg_end)
            };

            let enc_data_start = {
                let mut cipher_change_deser = &mut DeSer::new(&handshake_data[sh_msg_end..sh_msg_end + 6]);
                let change_cipher_spec = ChangeCipherSpecMsg::deserialize(&mut cipher_change_deser).unwrap();
                sh_msg_end + change_cipher_spec.map_or(0, |(_, size)| size)
            };

            let ((mut serv_cipher_suite, mut serv_cipher, serv_master_hs_secret, serv_hs_secret, _serv_hs_key, _serv_hs_iv),
                (mut cl_cipher_suite, mut cl_cipher, cl_master_hs_secret, cl_hs_secret, _cl_hs_key, _cl_hs_iv)) = {
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
                let mut server_cipher_suite = cipher::tls_cipher_suite_try_from(sh.cipher_suite).unwrap();
                let (serv_master_hs_secret, serv_hs_secret, serv_key, serv_nonce) =
                    server_cipher_suite.derive_server_handshake_secrets(
                        &dh_shared_secret,
                        &msg_ctx);
                let serv_cipher = server_cipher_suite.cipher(serv_key.clone(), serv_nonce.clone());

                let mut cl_cipher_suite = cipher::tls_cipher_suite_try_from(sh.cipher_suite).unwrap();
                let (cl_master_hs_secret, cl_hs_secret, cl_key, cl_nonce) =
                    cl_cipher_suite.derive_client_handshake_secrets(
                        &dh_shared_secret,
                        &msg_ctx);
                let cl_cipher = cl_cipher_suite.cipher(cl_key.clone(), cl_nonce.clone());

                ((server_cipher_suite, serv_cipher, serv_master_hs_secret, serv_hs_secret, serv_key, serv_nonce), (cl_cipher_suite, cl_cipher, cl_master_hs_secret, cl_hs_secret, cl_key, cl_nonce))
            };

            // pass 1 - receive records arriving in a sequence of flights.
            let mut enc_msg_start = enc_data_start;
            while enc_msg_start < handshake_data.len() {
                let enc_msg_len = def::to_u16(handshake_data[enc_msg_start + 3],
                                              handshake_data[enc_msg_start + 4]) as usize;
                let enc_msg_end = enc_msg_start + 5 + enc_msg_len;
                if enc_msg_end > handshake_data.len() {
                    log::info!("\nRefilling at least {} bytes\n", enc_msg_end - handshake_data.len());
                    serv_stream.read(enc_msg_end - handshake_data.len(), &mut handshake_data)
                               .expect("ServerHello message");
                    log::info!("refilled. enc_msg_end = {enc_msg_end}, enc_msg_len = {enc_msg_len},  {}", handshake_data.len());
                }
                enc_msg_start = enc_msg_end;
            }

            // pass 2 - decrypt records and collect the data in a fresh buffer for processing.
            let mut enc_msg_start = enc_data_start;
            let mut dec_msg_buf = Vec::<u8>::new();
            while enc_msg_start < handshake_data.len() {
                let ad = handshake_data[enc_msg_start..enc_msg_start + 5].to_vec();
                // log::info!("enc msg aad {:?}", &ad);
                let enc_msg_len = def::to_u16(handshake_data[enc_msg_start + 3],
                                              handshake_data[enc_msg_start + 4]) as usize;
                let enc_msg_end = enc_msg_start + 5 + enc_msg_len;
                let mut dec_data_buf = (&handshake_data[enc_msg_start + 5..enc_msg_end]).to_vec();
                serv_cipher.decrypt_next(&ad, &mut dec_data_buf).expect("decrypted handshake data");
                // log::info!("decrypted data {:?}", &dec_data_buf[0..7]);
                assert!(dec_data_buf.len() < handshake_data[enc_msg_start + 5..enc_msg_end].len());
                dec_msg_buf.extend(dec_data_buf);
                enc_msg_start = enc_msg_end;
            }
            assert!(dec_msg_buf.len() < enc_msg_start - enc_data_start);
            assert!(!msg_ctx.is_empty());

            // pass 3 - deserialize the decrypted data to correct types
            {
                // encrypted extensions
                let mut s = 0;
                let mut deser = DeSer::new(&dec_msg_buf[s..]);
                {
                    assert_eq!(HandshakeType::EncryptedExtensions, deser.ru8().into());
                    let len = deser.ru24() as usize;
                    let k = 0;
                    s += 4 + len;
                    deser.slice(len);
                    msg_ctx.extend_from_slice(&dec_msg_buf[k..s]);
                    if deser.peek_u8() == RecordContentType::Handshake as u8 {
                        deser.ru8();
                        s += 1;
                        log::info!("EncryptedExtensions - ContentType = HANDSHAKE");
                    }
                    log::info!("EncryptedExtensions");
                }

                let _cert_ok = {
                    // server's certificate
                    assert_eq!(HandshakeType::Certificate, deser.ru8().into());
                    let len = deser.ru24() as usize;
                    let k = s;
                    s += 4 + len;
                    deser.slice(len);
                    msg_ctx.extend_from_slice(&dec_msg_buf[k..s]);
                    if deser.peek_u8() == RecordContentType::Handshake as u8 {
                        deser.ru8();
                        s += 1;
                        log::info!("Certificate - ContentType = HANDSHAKE");
                    }
                    // meta, whatsapp, and facebook, for example, encode zero-length something...
                    if deser.peek_u8() == 0 && deser.peek_u16() == 0 {
                        deser.ru16();
                        s += 2;
                        log::warn!("Certificate - stray bytes? The Finished message MAC will be invalid!");
                        false
                    } else {
                        log::info!("Certificate");
                        true
                    }
                };
                {
                    // certificate verify
                    assert_eq!(HandshakeType::CertificateVerify, deser.ru8().into());
                    let len = deser.ru24() as usize;
                    let k = s;
                    s += 4 + len;
                    deser.slice(len);
                    msg_ctx.extend_from_slice(&dec_msg_buf[k..s]);
                    if deser.peek_u8() == RecordContentType::Handshake as u8 {
                        deser.ru8();
                        s += 1;
                        log::info!("CertificateVerify - ContentType = HANDSHAKE");
                    }
                    log::info!("CertificateVerify");

                    assert_eq!(s, deser.cursor());
                }
                {
                    // server finished
                    let _res: Result<(), Mutter> =
                        FinishedMsg::deserialize(&mut deser)
                            .and_then(|(serv_fin_msg, _)| {
                                // verify the MAC in the Server Finished message
                                serv_cipher_suite
                                    .derive_finished_mac(&serv_hs_secret, &msg_ctx)
                                    .and_then(|expected_tag| serv_fin_msg.check_mac(expected_tag))
                                    .map_err(|e| {
                                        log::info!("ServerFinished - Invalid Tag!");
                                        e
                                    })
                                    .and_then(|_| {
                                        if deser.peek_u8() == RecordContentType::Handshake as u8 {
                                            deser.ru8();
                                            Ok(())
                                        } else {
                                            Mutter::MissingInnerPlaintextContentType.into()
                                        }
                                    })
                                    .and_then(|_| {
                                        // include server finished message in the msg_ctx
                                        Ok(msg_ctx.extend_from_slice(&serv_fin_msg.to_vec()))
                                    })
                                    .and_then(|_tags_match_| Ok(log::info!("ServerFinished - Verified!")))
                            });
                }
            };

            // send client Finish message
            {
                // opaque verify data
                let verify_data = cl_cipher_suite.derive_finished_mac(&cl_hs_secret, &msg_ctx).expect("");
                assert_eq!(verify_data.len(), cl_cipher_suite.digest_size());

                let mut fin_inner_plaintext = vec![0u8; 4 + verify_data.len() + 1];
                fin_inner_plaintext[0] = HandshakeType::Finished as u8;
                (fin_inner_plaintext[1], fin_inner_plaintext[2], fin_inner_plaintext[3]) =
                    def::u24_to_u8_triple(verify_data.len() as u32);
                let _ = &fin_inner_plaintext[4..4 + verify_data.len()].copy_from_slice(&verify_data);
                fin_inner_plaintext[4 + verify_data.len()] = RecordContentType::Handshake as u8;
                assert_eq!(fin_inner_plaintext.len(), cl_cipher_suite.digest_size() + 4 + 1);
                // log::info!("\n\nfin_inner_plaintext: {} {:?}", fin_inner_plaintext.len(), &fin_inner_plaintext);

                //assert_eq!(cipher_text_out.len(), verify_data.len() + 4 + 1 + 16);
                let mut tls_cipher_text = vec![0; 5 + fin_inner_plaintext.len() + 16];
                tls_cipher_text[0] = RecordContentType::ApplicationData as u8;
                (tls_cipher_text[1], tls_cipher_text[2]) = (0x03, 0x03);
                (tls_cipher_text[3], tls_cipher_text[4]) = def::u16_to_u8_pair(verify_data.len() as u16 + 4 + 1 + 16);
                let ad = tls_cipher_text[0..5].to_vec();
                cl_cipher.encrypt_next(&ad, &mut fin_inner_plaintext).expect("Finished ciphertext");
                tls_cipher_text[5..].copy_from_slice(&fin_inner_plaintext);
                // log::info!("\n\nfin_ciphertext: {} {:?}", tls_cipher_text.len(), &tls_cipher_text);
                // log::info!("\n\nad: {} {:?}", ad.len(), &ad);
                assert_eq!(fin_inner_plaintext.len(), verify_data.len() + 4 + 1 + 16);

                let w = serv_stream.write(&tls_cipher_text)
                                   .expect("ClientFinished message");
                assert_eq!(w, tls_cipher_text.len());
                // log::info!("\nClient Finished sent: {w:} bytes");
            }
            // send http get request
            {
                let (key, iv) = cl_cipher_suite.derive_client_app_traffic_secrets(cl_master_hs_secret, &msg_ctx);
                let mut cl_cipher = cl_cipher_suite.cipher(key, iv);
                let http_req_plaintext = format!("GET /{} HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\nUser-Agent: curl/8.6.0\r\n\r\n", peer.path, peer.id).as_bytes().to_vec();
                // log::info!("HTTP request: {}", format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", peer.id));
                // log::info!("HTTP request len: {}", http_req_plaintext.len());
                let mut tls_cipher_text = vec![0; 5];
                tls_cipher_text[0] = RecordContentType::ApplicationData as u8;
                (tls_cipher_text[1], tls_cipher_text[2]) = (0x03, 0x03);
                (tls_cipher_text[3], tls_cipher_text[4]) = def::u16_to_u8_pair(http_req_plaintext.len() as u16 + 16 + 1);
                let mut enc_http_req = http_req_plaintext.to_vec();
                enc_http_req.extend_from_slice(&[23]);
                assert_eq!(enc_http_req.len(), http_req_plaintext.len() + 1);
                cl_cipher.encrypt_next(&tls_cipher_text[0..5].to_vec(),
                                       &mut enc_http_req).expect("Finished ciphertext");
                assert_eq!(enc_http_req.len(), http_req_plaintext.len() + 16 + 1);
                tls_cipher_text.extend(enc_http_req);
                assert_eq!(tls_cipher_text.len(), http_req_plaintext.len() + 16 + 5 + 1);
                // log::info!("Record of HTTP request: {:?}", &tls_cipher_text);
                let w = serv_stream.write(&tls_cipher_text).expect("ClientFinished message");
                assert_eq!(w, tls_cipher_text.len());
                // log::info!("\nSent http req: {w:} bytes");
            }

            let (key, iv) = serv_cipher_suite.derive_server_app_traffic_secrets(serv_master_hs_secret, &msg_ctx);
            let mut serv_cipher = serv_cipher_suite.cipher(key, iv);
            let mut start = 0;
            let mut response = Vec::new();
            loop {
                let n = serv_stream.read(16, &mut response).unwrap();
                if n > 0 && response.len() > 0 {
                    while start < response.len() {
                        let len = def::to_u16(response[start + 3], response[start + 4]) as usize;
                        if start + 5 + len <= response.len() {
                            let ad = response[start..start + 5].to_vec();
                            let mut decrypted = response[start + 5..start + 5 + len].to_vec();
                            serv_cipher.decrypt_next(&ad, &mut decrypted).unwrap();
                            log::info!("{}", String::from_utf8_lossy(&decrypted));
                            start += len + 5;
                        } else {
                            break;
                        }
                    }
                } else {
                    break
                }
            }
            log::info!("Done! Shutting down the connection....");
            serv_stream.shutdown()
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
                let res = ch.serialize(ch_msg_buf.as_mut_slice());
                assert!(matches!(res, Ok(_)));

                let mut buf = Vec::with_capacity(2048);
                serv_stream.write(&ch_msg_buf)
                           .expect("write");
                let res = serv_stream.read(1024, &mut buf);
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
}