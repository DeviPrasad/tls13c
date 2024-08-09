use std::io::Write;
use std::time::UNIX_EPOCH;

use env_logger::Builder;
use log::LevelFilter;

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
