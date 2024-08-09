use crate::cfg::PeerSessionConfig;
use crate::ch::ClientHelloMsg;
use crate::ecdhe::DHSession;
use crate::err::Mutter;
use crate::ext::ClientExtensions;
use crate::logger;
use crate::session::{AppSession, KeyExchangeSession, MessageAuthenticator};
use crate::stream::TlsConnection;

pub fn client_main() -> Result<(), Mutter> {
    logger::init_logger(true);

    Ok(&PeerSessionConfig::dicp())
        .and_then(|peer| Ok((peer, tls_connect(&peer)?)))
        .and_then(|(peer, mut app_session)| {
            http_get(&peer.path, &peer.id, &mut app_session)?;
            Ok(app_session)
        })
        .and_then(|mut app_session| {
            read_http_response(&mut app_session);
            tls_shutdown(&mut app_session);
            Ok(())
        })
}

pub fn tls_connect(peer: &PeerSessionConfig) -> Result<AppSession, Mutter> {
    TlsConnection::with_peer(&peer).and_then(|tls_conn| {
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
                peer.cipher_suites.to_vec(),
                extensions_data.clone(),
            )
            .unwrap();
            log::info!("ClientHello sent");
            ch
        };

        let _ = key_exchange_session.client_hello(&ch)?;
        let sh = key_exchange_session.read_server_hello()?;

        key_exchange_session.read_change_cipher_spec()?;

        let serv_key_share = sh.key_share(&ch.key_shares()).expect("public key for DH");
        let mut auth_session =
            key_exchange_session.authentication_session(sh.cipher_suite_id, serv_key_share, dh)?;

        MessageAuthenticator::authenticate(&mut auth_session);

        // send client Finish message
        auth_session.send_client_finished()?;

        // send http get request
        auth_session.app_session()
    })
}

fn http_get(path: &str, host: &str, session: &mut AppSession) -> Result<usize, Mutter> {
    // send http get request
    let http_req_plaintext = format!(
        "GET /{} HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\nUser-Agent: curl/8.6.0\r\n\r\n",
        path, host
    );
    session.send(http_req_plaintext.as_bytes())
}

fn read_http_response(session: &mut AppSession) {
    // read the server response
    loop {
        let mut response = Vec::new();
        if let Ok(n) = session.read(&mut response) {
            if n > 0 {
                eprint!("{:#}", String::from_utf8_lossy(&response));
            } else {
                break;
            }
        } else {
            break;
        }
    }
}

fn tls_shutdown(session: &mut AppSession) {
    log::info!("Done! Shutting down the connection....");
    let _ = session.shutdown();
}
