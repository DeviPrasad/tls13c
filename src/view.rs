use std::io::Write;
use std::time::UNIX_EPOCH;

use env_logger::Builder;
use log::LevelFilter;

use crate::cert::{CertificateMsg, CertificateVerifyMsg};
use crate::cfg::PeerSessionConfig;
use crate::ch::ClientHelloMsg;
use crate::def;
use crate::def::{HandshakeType, RecordContentType};
use crate::deser::DeSer;
use crate::enc_ext::EncryptedExtensionsMsg;
use crate::err::Mutter;
use crate::ext::ClientExtensions;
use crate::fin::FinishedMsg;
use crate::protocol::{DHSession, KeyExchangeSession, Tls13Ciphertext};
use crate::session::TlsConnection;
use crate::sock::Stream;

pub fn view_main() {
    init_logger(true);

    let peer = PeerSessionConfig::google();
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
                {
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
            {
                // opaque verify data
                let verify_data = auth_session.client_finished_mac().expect("");
                assert_eq!(verify_data.len(), auth_session.digest_size());
                let mut cl_fin_msg = FinishedMsg::serialize(verify_data);
                // size + 16 bytes AEAD authentication tag
                let aad = Tls13Ciphertext::aad(cl_fin_msg.len() as u16 + 16);
                auth_session
                    .encrypt_next(&aad, &mut cl_fin_msg)
                    .expect("Finished ciphertext");
                let ct = Tls13Ciphertext::serialize(cl_fin_msg);
                let w = auth_session.send(&ct).expect("ClientFinished message");
                assert_eq!(w, ct.len());
                log::info!("Client Finished");
            }

            // send http get request
            let mut traffic_sec = auth_session
                .new_app_traffic_secrets()
                .expect("app traffic secrets");
            {
                let http_req_plaintext = format!(
                    "GET /{} HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\nUser-Agent: curl/8.6.0\r\n\r\n",
                    peer.path, peer.id
                )
                .as_bytes()
                .to_vec();
                let mut tls_cipher_text = vec![0; 5];
                tls_cipher_text[0] = RecordContentType::ApplicationData as u8;
                (tls_cipher_text[1], tls_cipher_text[2]) = (0x03, 0x03);
                (tls_cipher_text[3], tls_cipher_text[4]) =
                    def::u16_to_u8_pair(http_req_plaintext.len() as u16 + 16 + 1);
                let mut enc_http_req = http_req_plaintext.to_vec();
                enc_http_req.extend_from_slice(&[23]);
                assert_eq!(enc_http_req.len(), http_req_plaintext.len() + 1);
                traffic_sec
                    .encrypt_next(&tls_cipher_text[0..5].to_vec(), &mut enc_http_req)
                    .expect("Finished ciphertext");
                assert_eq!(enc_http_req.len(), http_req_plaintext.len() + 16 + 1);
                tls_cipher_text.extend(enc_http_req);
                assert_eq!(tls_cipher_text.len(), http_req_plaintext.len() + 16 + 5 + 1);
                let w = auth_session
                    .serv_stream
                    .write(&tls_cipher_text)
                    .expect("ClientFinished message");
                assert_eq!(w, tls_cipher_text.len());
            }

            let mut start = 0;
            let mut response = Vec::new();
            loop {
                let n = match auth_session.serv_stream.read(16, &mut response) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        log::error!("{:#?}", e);
                        break;
                    }
                };
                if n > 0 && response.len() > 0 {
                    while start + 5 < response.len() {
                        let len = def::to_u16(response[start + 3], response[start + 4]) as usize;
                        if start + 5 + len <= response.len() {
                            let ad = response[start..start + 5].to_vec();
                            let mut decrypted = response[start + 5..start + 5 + len].to_vec();
                            traffic_sec.decrypt_next(&ad, &mut decrypted).unwrap();
                            // eprint!("{:?}", String::from_utf8_lossy(&decrypted));
                            eprint!(".");
                            start += len + 5;
                        } else {
                            break;
                        }
                    }
                } else {
                    break;
                }
            }
            log::info!("Done! Shutting down the connection....");
            auth_session
                .serv_stream
                .shutdown()
                .expect("server shutdown");
        }
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
