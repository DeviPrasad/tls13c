use crate::cfg::PeerSessionConfig;
use crate::ch::ClientHelloMsg;
use crate::ecdhe::DHSession;
use crate::err::Mutter;
use crate::ext::ClientExtensions;
use crate::session::{AppSession, AuthenticationSession, KeyExchangeSession, MessageAuthenticator};
use crate::stream::TlsConnection;
use crate::{deser, logger, rand};

pub fn client_main() -> Result<(), Mutter> {
    logger::init_logger(true);

    Ok(&PeerSessionConfig::mitre())
        .and_then(|peer| Ok((peer, TlsConnection::with_peer(peer)?)))
        .and_then(|(peer, tls_conn)| Ok((peer, exchange(peer, tls_conn)?)))
        .and_then(|(peer, auth_session)| Ok((peer, authenticate(auth_session)?)))
        .and_then(|(peer, mut app_session)| {
            run_client(&peer.path, &peer.id, &mut app_session)?;
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

    key_exchange_session.authentication_session(
        sh.cipher_suite_id,
        serv_key_share,
        dh,
        peer.sig_algs.clone(),
    )
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

fn read_server_resp(session: &mut AppSession, response: &mut Vec<u8>) -> Result<usize, Mutter> {
    session.read(response)
}

fn run_client(path: &str, host: &str, session: &mut AppSession) -> Result<(), Mutter> {
    let mut resp = vec![];

    // Session tickets are optional. Not all servers offer them. For example, x.com doesn't.
    // We do not use them in any way.
    let mut ticket_last = 0;
    {
        let mut tc = 0; // ticket counts
        while !(resp.ends_with(&[1, 0, 21]) || resp.ends_with(&[2, 0, 21]))
            && session.read_ciphertext_record(&mut resp).is_ok()
        {
            let mut deser = deser::DeSer::new(&resp[ticket_last..]);
            while deser.have(5) && deser.peek_u8() == 4 {
                let len = deser.peek_u24_at(1) as usize;
                if deser.peek_u8_at(len + 4) == 22 {
                    log::info!("Got a session ticket {:?}", deser.slice(len + 5));
                    ticket_last += len + 5;
                    tc += 1;
                } else {
                    break;
                }
            }
            // Some servers (ex: 'www.mitre.org') send out a close_notify(0) alert.
            // alert level 1 is Warning and 2 is Fatal
            if resp.ends_with(&[1, 0, 21]) || resp.ends_with(&[2, 0, 21]) || tc == 0 {
                break;
            }

            log::info!("next record?");
        }

        // remove tickets from the buffer retaining alerts and rest of the response.
        if tc > 0 {
            let len = resp.len() - ticket_last;
            resp.copy_within(ticket_last.., 0);
            resp.truncate(len);
            eprintln!("\n");
            log::info!("Found {tc} session Ticket(s).");
        }
    }

    // HTTP GET
    http_get(path, host, session)?;

    // if the last message wasn't an alert message, read more till an alert
    // or the stream is empty (at least appears so).
    while !(resp.ends_with(&[1, 0, 21]) || resp.ends_with(&[2, 0, 21]))
        && read_server_resp(session, &mut resp).is_ok()
    {}

    eprintln!("\n");
    eprint!("{:#}", String::from_utf8_lossy(&resp[0..]));
    eprintln!("\n");
    Ok(())
}

fn tls_shutdown(session: &mut AppSession) {
    eprintln!("\n\n");
    log::info!("Done! Shutting down the connection....");
    let _ = session.shutdown();
}
