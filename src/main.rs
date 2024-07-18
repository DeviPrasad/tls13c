use std::io::Write;
use chrono::Local;
use env_logger::Builder;
use log::LevelFilter;
use crate::cfg::{PeerSessionConfig};
use crate::sock::{Stream};
use crate::session::EarlySession;

mod sock;
mod err;
mod def;
mod cfg;
mod session;
mod protocol;
mod cipher;
mod ecdhe;
mod ext;

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
    let peer = PeerSessionConfig::microsoft();

    init_logger(true);
    // if let Ok(session) = Session::<TlsAes128GcmSha256, GroupX25519>::with_peer(&peer).await {
    if let Ok(session) = EarlySession::with_peer(&peer).await {
        println!("server_stream: {:#?}", session);
        let serv_stream = session.stream;
        let mut buf = Vec::new();
        serv_stream.write("client_hello".as_bytes()).await.expect("write");
        let res = serv_stream.read(5, &mut buf).await;
        println!("read: {res:#?}");
    }
}
