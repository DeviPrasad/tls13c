use crate::cfg::PeerSessionConfig;
use crate::ch::ClientHelloMsg;
use crate::ecdhe::DHSession;
use crate::err::Mutter;
use crate::ext::ClientExtensions;
use crate::session::{AppSession, AuthenticationSession, KeyExchangeSession, MessageAuthenticator};
use crate::stream::TlsConnection;
use crate::{logger, rand};

pub fn client_main() -> Result<(), Mutter> {
    logger::init_logger(true);

    Ok(&PeerSessionConfig::spacex())
        .and_then(|peer| Ok((peer, TlsConnection::with_peer(peer)?)))
        .and_then(|(peer, tls_conn)| Ok((peer, exchange(peer, tls_conn)?)))
        .and_then(|(peer, auth_session)| Ok((peer, authenticate(auth_session)?)))
        .and_then(|(peer, mut app_session)| {
            run_http_client(&peer.path, &peer.id, &mut app_session)?;
            tls_shutdown(&mut app_session);
            Ok(())
        })
}

pub fn exchange(
    peer: &PeerSessionConfig,
    tls_conn: TlsConnection,
) -> Result<AuthenticationSession, Mutter> {
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
        ))?;
        let ch = ClientHelloMsg::try_from(
            rand::CryptoRandom::<32>::bytes(),
            peer.cipher_suites.to_vec(),
            extensions_data.clone(),
        )?;
        log::info!("ClientHello sent");
        ch
    };

    key_exchange_session.client_hello(&ch)?;
    let sh = key_exchange_session.read_server_hello()?;

    key_exchange_session.read_optional_change_cipher_spec()?;

    let serv_key_share = sh.key_share(ch.key_shares()).expect("public key for DH");

    key_exchange_session.authentication_session(sh.cipher_suite_id, serv_key_share, dh)
}

pub fn authenticate(mut auth_session: AuthenticationSession) -> Result<AppSession, Mutter> {
    MessageAuthenticator::authenticate(&mut auth_session)?;

    // send client Finish message
    auth_session.send_client_finished()?;

    // send http get request
    auth_session.app_session()
}

fn http_get(path: &str, host: &str, session: &mut AppSession) -> Result<usize, Mutter> {
    // send http get request
    let http_req_plaintext = format!(
        "GET /{} HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\nUser-Agent: curl/8.6.0\r\n\r\n",
        path, host
    );
    session.send(http_req_plaintext.as_bytes())
}

fn read_http_response(session: &mut AppSession, response: &mut Vec<u8>) -> Result<usize, Mutter> {
    session.read(response)
}

fn run_http_client(path: &str, host: &str, session: &mut AppSession) -> Result<(), Mutter> {
    http_get(path, host, session)?;
    let mut resp = vec![0; 4096];
    let mut i = 0;
    while i < 4 {
        if let Ok(n) = read_http_response(session, &mut resp) {
            if n > 0 {
                eprint!("{:#}", String::from_utf8_lossy(resp.as_slice()));
                i += 1;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    Ok(())
}

fn tls_shutdown(session: &mut AppSession) {
    log::info!("Done! Shutting down the connection....");
    let _ = session.shutdown();
}