use std::io::Write;
use std::time::UNIX_EPOCH;

use env_logger::Builder;
use log::LevelFilter;

use crate::cert::{CertificateMsg, CertificateVerifyMsg};
use crate::cfg::PeerSessionConfig;
use crate::ch::ClientHelloMsg;
use crate::def::{HandshakeType, RecordContentType};
use crate::deser::DeSer;
use crate::enc_ext::EncryptedExtensionsMsg;
use crate::err::Mutter;
use crate::ext::ClientExtensions;
use crate::fin::FinishedMsg;
use crate::protocol::{DHSession, KeyExchangeSession};
use crate::session::TlsConnection;

pub fn view_main() {
    init_logger(true);

    let peer = PeerSessionConfig::dicp();
    init(peer)
}

pub fn init(peer: PeerSessionConfig) {
    if let Ok(tls_conn) = TlsConnection::with_peer(&peer) {
        log::info!("TLS 1.3 peer: ({})", peer.tls_addr);

        let mut key_exchange_session = KeyExchangeSession::new(tls_conn.stream);
        let mut dh = DHSession::new();

        let ch = {
            let extensions_data = ClientExtensions::try_from((
                peer.id.as_str(),
                peer.sig_algs.as_slice(),
                peer.dh_groups.as_slice(),
                // [p256_key_share].as_slice()
                // [x25519_key_share].as_slice()
                // [p256_key_share, x25519_key_share].as_slice()
                [dh.x25519_key_share(), dh.p256_key_share()].as_slice(),
            ))
                .unwrap();
            let ch = ClientHelloMsg::try_from(
                key_exchange_session.random(),
                peer.cipher_suites,
                extensions_data.clone(),
            )
                .unwrap();
            log::info!("ClientHello sent");
            ch
        };

        let _ = key_exchange_session
            .client_hello(&ch)
            .expect("client hello on the first flight");
        let sh = key_exchange_session
            .read_server_hello()
            .expect("server hello on the first flight");

        key_exchange_session
            .read_change_cipher_spec()
            .expect("optional change cipher spec");

        let serv_key_share = sh.key_share(&ch.key_shares()).expect("public key for DH");
        let mut auth_session = key_exchange_session
            .authentication_session(sh.cipher_suite_id, serv_key_share, dh)
            .expect("handshake secrets");

        {
            let msg_type_proc = [
                HandshakeType::EncryptedExtensions,
                HandshakeType::Certificate,
                HandshakeType::CertificateVerify,
                HandshakeType::Finished,
            ];

            let mut next_mtp = 0;
            while next_mtp < msg_type_proc.len() {
                // read the next TlsCiphertext record.
                let ciphertext_rec = auth_session
                    .read_ciphertext_record()
                    .expect("handshake message ciphertext");
                // decrypt and cache TlsInnerPlaintext records
                let mut dec_msg_buf = Vec::<u8>::new();
                let ad = ciphertext_rec[0..5].to_vec();
                let mut dec_data_buf = (&ciphertext_rec[5..]).to_vec();
                auth_session
                    .decrypt_next(&ad, &mut dec_data_buf)
                    .expect("decrypted handshake data");
                assert!(dec_data_buf.len() < ciphertext_rec.len() - 5);

                // iterate and process each inner_plaintext_rec in the cache
                let mut deser = DeSer::new(&dec_data_buf);
                // deserialize the decrypted data to correct message types
                while deser.available() > 0 && next_mtp < msg_type_proc.len() {
                    let expected_msg_type = msg_type_proc[next_mtp];
                    next_mtp += 1;
                    match expected_msg_type {
                        HandshakeType::EncryptedExtensions => {
                            // encrypted extensions
                            let _enc_ext_msg = EncryptedExtensionsMsg::deserialize(&mut deser)
                                .map_err(|e| {
                                    log::info!(
                                            "EncryptedExtensions - deserialization error {:#?}",
                                            e
                                        );
                                    e
                                })
                                .and_then(|(enc_ext_msg, msg_slice)| {
                                    if deser.peek_u8() == RecordContentType::Handshake as u8 {
                                        deser.ru8();
                                        log::info!(
                                                "EncryptedExtensions - ContentType = HANDSHAKE"
                                            );
                                    }
                                    Ok((enc_ext_msg, msg_slice))
                                })
                                .and_then(|(enc_ext_msg, msg_slice)| {
                                    log::info!("EncryptedExtensions");
                                    Ok((enc_ext_msg, msg_slice))
                                })
                                .and_then(|(enc_ext_msg, msg_slice)| {
                                    auth_session.update_msg_ctx(msg_slice);
                                    Ok(enc_ext_msg)
                                });
                        }
                        HandshakeType::Certificate => {
                            // server's certificate
                            let _cert_msg = CertificateMsg::deserialize(&mut deser)
                                .map_err(|e| {
                                    log::info!("Certificate - deserialization error {:#?}", e);
                                    panic!("Certificate - deserialization error");
                                })
                                .and_then(|(cert_msg, msg_slice)| {
                                    if deser.peek_u8() == RecordContentType::Handshake as u8 {
                                        deser.ru8();
                                        log::info!("Certificate - ContentType = HANDSHAKE");
                                    }
                                    Ok((cert_msg, msg_slice))
                                })
                                .and_then(|(cert_msg, msg_slice)| {
                                    log::info!("Certificate ({} bytes)", msg_slice.len());
                                    Ok((cert_msg, msg_slice))
                                })
                                .and_then(|(cert_msg, msg_slice)| {
                                    auth_session.update_msg_ctx(msg_slice);
                                    Ok(cert_msg)
                                });
                        }
                        HandshakeType::CertificateVerify => {
                            // certificate verify
                            let _cert_verify_msg =
                                CertificateVerifyMsg::deserialize(&mut deser)
                                    .map_err(|e| {
                                        log::info!(
                                                "CertificateVerify - deserialization error {:#?}",
                                                e
                                            );
                                        panic!("CertificateVerify - deserialization error");
                                    })
                                    .and_then(|(cert_verify_msg, _)| {
                                        if deser.peek_u8() == RecordContentType::Handshake as u8
                                        {
                                            deser.ru8();
                                            log::info!(
                                                    "CertificateVerify - ContentType = HANDSHAKE"
                                                );
                                        }
                                        Ok(cert_verify_msg)
                                    })
                                    .and_then(|cert_verify_msg| {
                                        Ok(auth_session
                                            .update_msg_ctx(cert_verify_msg.to_vec()))
                                    })
                                    .and_then(|_| Ok(log::info!("CertificateVerify")));
                        }
                        HandshakeType::Finished => {
                            // server finished
                            let _fin_msg = FinishedMsg::deserialize(&mut deser).and_then(
                                |(serv_fin_msg, _)| {
                                    // verify the MAC in the Server Finished message
                                    auth_session
                                        .server_finished_mac()
                                        .and_then(|expected_tag| {
                                            serv_fin_msg.check_mac(expected_tag)
                                        })
                                        .map_err(|e| {
                                            log::info!("ServerFinished - Invalid Tag!");
                                            e
                                        })
                                        .and_then(|_| {
                                            if deser.peek_u8()
                                                == RecordContentType::Handshake as u8
                                            {
                                                deser.ru8();
                                                Ok(())
                                            } else {
                                                Mutter::MissingInnerPlaintextContentType.into()
                                            }
                                        })
                                        .map_err(|e| {
                                            log::info!("ServerFinished - error {:#?}", e);
                                            panic!("ServerFinished - error");
                                        })
                                        .and_then(|_| {
                                            // include server finished message in the msg_ctx
                                            Ok(auth_session
                                                .update_msg_ctx(serv_fin_msg.to_vec()))
                                        })
                                        .and_then(|_tags_match_| {
                                            Ok(log::info!("ServerFinished - Verified!"))
                                        })
                                },
                            );
                            assert!(matches!(_fin_msg, Ok(_)));
                        }
                        _ => panic!("Internal Error while processing cipher text"),
                    }
                }
                // log::info!("done deserializing a set of messages. deser available = {}", deser.available());
                dec_msg_buf.extend(dec_data_buf);
            }
        }

        // send client Finish message
        auth_session.send_client_finished_method().expect("client finished message");

        // send http get request
        let mut app_session = auth_session.app_session().expect("app session");
        let http_req_plaintext = format!(
            "GET /{} HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\nUser-Agent: curl/8.6.0\r\n\r\n",
            peer.path, peer.id
        );
        app_session.send(http_req_plaintext.as_bytes()).expect("http get request");

        // read the server response
        loop {
            let mut response = Vec::new();
            if let Ok(n) = app_session.read(&mut response) {
                if n > 0 {
                    eprint!("{:#}", String::from_utf8_lossy(&response));
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        log::info!("Done! Shutting down the connection....");
        let _ = app_session.shutdown();
    }
}

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
            writeln!(
                buf,
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
