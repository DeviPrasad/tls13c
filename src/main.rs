use std::io::Write;
use std::time::UNIX_EPOCH;

use env_logger::Builder;
use log::LevelFilter;

use crate::cert::{CertificateMsg, CertificateVerifyMsg};
use crate::cfg::PeerSessionConfig;
use crate::ch::ClientHelloMsg;
use crate::def::{HandshakeType, RecordContentType, SupportedGroup};
use crate::deser::DeSer;
use crate::enc_ext::EncryptedExtensionsMsg;
use crate::err::Mutter;
use crate::ext::ClientExtensions;
use crate::fin::FinishedMsg;
use crate::protocol::{DHSession, Tls13ProtocolSession};
use crate::session::TlsConnection;
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

    let peer = PeerSessionConfig::nsa();

    if let Ok(tls_conn) = TlsConnection::with_peer(&peer) {
        log::info!("TLS 1.3 peer: ({})", peer.tls_addr);

        let mut session = Tls13ProtocolSession::new(tls_conn.stream);
        let mut dh = DHSession::new();

        let ch = {
            let extensions_data = ClientExtensions::try_from(
                (
                    peer.id.as_str(),
                    peer.sig_algs.as_slice(),
                    peer.dh_groups.as_slice(),
                    // [p256_key_share].as_slice()
                    // [x25519_key_share].as_slice()
                    // [p256_key_share, x25519_key_share].as_slice()
                    [dh.x25519_key_share(), dh.p256_key_share()].as_slice()
                )
            ).unwrap();
            let ch = ClientHelloMsg::try_from(
                session.random(),
                peer.cipher_suites,
                extensions_data.clone()
            ).unwrap();
            log::info!("ClientHello sent");
            ch
        };

        let _ = session.client_hello(&ch).expect("client hello on the first flight");
        let sh = session.read_server_hello().expect("server hello on the first flight");
        session.read_change_cipher_spec().expect("optional change cipher spec");

        {
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
                            dh.x25519_dh(pk)
                        } else if server_key_share.group == SupportedGroup::Secp256r1 {
                            dh.p256_dh(pk)
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
                        &session.msg_ctx());
                let serv_cipher = server_cipher_suite.cipher(serv_key.clone(), serv_nonce.clone());

                let mut cl_cipher_suite = cipher::tls_cipher_suite_try_from(sh.cipher_suite).unwrap();
                let (cl_master_hs_secret, cl_hs_secret, cl_key, cl_nonce) =
                    cl_cipher_suite.derive_client_handshake_secrets(
                        &dh_shared_secret,
                        &session.msg_ctx());
                let cl_cipher = cl_cipher_suite.cipher(cl_key.clone(), cl_nonce.clone());

                ((server_cipher_suite, serv_cipher, serv_master_hs_secret, serv_hs_secret, serv_key, serv_nonce), (cl_cipher_suite, cl_cipher, cl_master_hs_secret, cl_hs_secret, cl_key, cl_nonce))
            };

            // pass 1 - receive records arriving in a sequence of flights.
            let msg_type_proc = [
                HandshakeType::EncryptedExtensions,
                HandshakeType::Certificate,
                HandshakeType::CertificateVerify,
                HandshakeType::Finished,
            ];

            let mut next_mtp = 0;
            while next_mtp < msg_type_proc.len() {
                // read the next TlsCiphertext record.
                let ciphertext_rec = session.read_ciphertext_record().expect("handshake message ciphertext");
                // pass 2 - decrypt and cache TlsInnerPlaintext records
                let mut dec_msg_buf = Vec::<u8>::new();
                let ad = ciphertext_rec[0..5].to_vec();
                let mut dec_data_buf = (&ciphertext_rec[5..]).to_vec();
                serv_cipher.decrypt_next(&ad, &mut dec_data_buf).expect("decrypted handshake data");
                assert!(dec_data_buf.len() < ciphertext_rec.len() - 5);
                {
                    // iterate and process each inner_plaintext_rec in the cache
                    let mut deser = DeSer::new(&dec_data_buf);
                    // pass 3 - deserialize the decrypted data to correct types
                    while deser.available() > 0 && next_mtp < msg_type_proc.len() {
                        let expected_msg_type = msg_type_proc[next_mtp];
                        // log::info!("Expecting: {:#?}", expected_msg_type);
                        // log::info!("available for deser: {:#?}", deser.available());
                        next_mtp += 1;
                        match expected_msg_type {
                            HandshakeType::EncryptedExtensions =>
                                {
                                    // encrypted extensions
                                    let _enc_ext_msg = EncryptedExtensionsMsg::deserialize(&mut deser)
                                        .map_err(|e| {
                                            log::info!("EncryptedExtensions - deserialization error {:#?}", e);
                                            panic!("EncryptedExtensions - deserialization error");
                                        })
                                        .and_then(|(enc_ext_msg, msg_slice)| {
                                            if deser.peek_u8() == RecordContentType::Handshake as u8 {
                                                deser.ru8();
                                                log::info!("EncryptedExtensions - ContentType = HANDSHAKE");
                                            }
                                            Ok((enc_ext_msg, msg_slice))
                                        })
                                        .and_then(|(enc_ext_msg, msg_slice)| {
                                            log::info!("EncryptedExtensions");
                                            Ok((enc_ext_msg, msg_slice))
                                        })
                                        .and_then(|(enc_ext_msg, msg_slice)| {
                                            session.update_msg_ctx(msg_slice);
                                            Ok(enc_ext_msg)
                                        });
                                }
                            HandshakeType::Certificate =>
                                {
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
                                            log::info!("Certificate");
                                            Ok((cert_msg, msg_slice))
                                        })
                                        .and_then(|(cert_msg, msg_slice)| {
                                            session.update_msg_ctx(msg_slice);
                                            Ok(cert_msg)
                                        });
                                }
                            HandshakeType::CertificateVerify =>
                                {
                                    // certificate verify
                                    let _cert_verify_msg = CertificateVerifyMsg::deserialize(&mut deser)
                                        .map_err(|e| {
                                            log::info!("CertificateVerify - deserialization error {:#?}", e);
                                            panic!("CertificateVerify - deserialization error");
                                        })
                                        .and_then(|(cert_verify_msg, _)| {
                                            if deser.peek_u8() == RecordContentType::Handshake as u8 {
                                                deser.ru8();
                                                log::info!("CertificateVerify - ContentType = HANDSHAKE");
                                            }
                                            Ok(cert_verify_msg)
                                        })
                                        .and_then(|cert_verify_msg| {
                                            Ok(session.update_msg_ctx(cert_verify_msg.to_vec()))
                                        })
                                        .and_then(|_| Ok(log::info!("CertificateVerify")));
                                }
                            HandshakeType::Finished =>
                                {
                                    // server finished
                                    let _fin_msg = FinishedMsg::deserialize(&mut deser)
                                        .and_then(|(serv_fin_msg, _)| {
                                            // verify the MAC in the Server Finished message
                                            serv_cipher_suite
                                                .derive_finished_mac(&serv_hs_secret, &session.msg_ctx())
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
                                                .map_err(|e| {
                                                    log::info!("ServerFinished - error {:#?}", e);
                                                    panic!("ServerFinished - error");
                                                })
                                                .and_then(|_| {
                                                    // include server finished message in the msg_ctx
                                                    Ok(session.update_msg_ctx(serv_fin_msg.to_vec()))
                                                })
                                                .and_then(|_tags_match_| Ok(log::info!("ServerFinished - Verified!")))
                                        });
                                    assert!(matches!(_fin_msg, Ok(_)));
                                }
                            _ => panic!("Internal Error while processing cipher text")
                        }
                    }
                    // log::info!("done deserializing a set of messages. deser available = {}", deser.available());
                    assert!(!session.msg_ctx().is_empty());
                    dec_msg_buf.extend(dec_data_buf);
                }
            }
            {
                // send client Finish message
                {
                    // opaque verify data
                    let verify_data = cl_cipher_suite.derive_finished_mac(&cl_hs_secret, &session.msg_ctx()).expect("");
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

                    let w = session.serv_stream.write(&tls_cipher_text)
                                   .expect("ClientFinished message");
                    assert_eq!(w, tls_cipher_text.len());
                    // log::info!("\nClient Finished sent: {w:} bytes");
                }
                // send http get request
                {
                    let (key, iv) = cl_cipher_suite.derive_client_app_traffic_secrets(cl_master_hs_secret, &session.msg_ctx());
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
                    let w = session.serv_stream.write(&tls_cipher_text).expect("ClientFinished message");
                    assert_eq!(w, tls_cipher_text.len());
                    // log::info!("\nSent http req: {w:} bytes");
                }

                let (key, iv) = serv_cipher_suite.derive_server_app_traffic_secrets(serv_master_hs_secret, &session.msg_ctx());
                let mut serv_cipher = serv_cipher_suite.cipher(key, iv);
                let mut start = 0;
                let mut response = Vec::new();
                loop {
                    let n =
                        match session.serv_stream.read(16, &mut response) {
                            Ok(0) => break,
                            Ok(n) => n,
                            Err(e) => {
                                log::error!("{:#?}", e);
                                break;
                            }
                        };
                    if n > 0 && response.len() > 0 {
                        while start < response.len() {
                            let len = def::to_u16(response[start + 3], response[start + 4]) as usize;
                            if start + 5 + len <= response.len() {
                                let ad = response[start..start + 5].to_vec();
                                let mut decrypted = response[start + 5..start + 5 + len].to_vec();
                                serv_cipher.decrypt_next(&ad, &mut decrypted).unwrap();
                                //eprint!("{}", String::from_utf8_lossy(&decrypted));
                                eprint!(".");
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
                session.serv_stream.shutdown()
                       .expect("server shutdown");
            }
        }
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
    use crate::session::TlsConnection;
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
        if let Ok(session) = TlsConnection::with_peer(&peer) {
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
