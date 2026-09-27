//! VLYNESS консольный клиент: локальный SOCKS5-прокси через туннель.
//!
//! Вся сетевая логика — в библиотеке [`vlyness_cli::client`] (её же использует GUI).
//! Здесь только разбор окружения и запуск цикла с выводом лога в stderr.
//!
//! Два режима конфигурации:
//! - **пул**: `VLYNESS_PROFILES=<a.json,b.json,...>` — самодостаточные носители, ротация;
//! - **одиночный**: параметры из окружения (`VLYNESS_SERVER_ADDR` и т.д.), опционально
//!   `VLYNESS_PROFILE` задаёт форму.
//!
//! Окружение (одиночный режим): VLYNESS_SERVER_ADDR, VLYNESS_SNI, VLYNESS_CA,
//!   VLYNESS_PSK_B64, VLYNESS_SERVER_PUB_B64, VLYNESS_TUNNEL_PATH, VLYNESS_UA,
//!   VLYNESS_MODE (stream|segments|packet|datagram), VLYNESS_ECH / VLYNESS_ECH_CONFIG_B64.
//! Общее: VLYNESS_SOCKS_BIND, VLYNESS_REFERENCE (контрольный хост для blackhole).

use tokio::sync::watch;

use vlyness_cli::client::{load_profile, run, Reporter, Source};
use vlyness_cli::{env_opt, env_or};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxErr> {
    let socks_bind = env_or("VLYNESS_SOCKS_BIND", "127.0.0.1:1080");
    let reference = env_opt("VLYNESS_REFERENCE");

    // Пул носителей (если задан) — иначе одиночная конфигурация из окружения.
    let source = match env_opt("VLYNESS_PROFILES") {
        Some(list) => {
            let mut profiles = Vec::new();
            for path in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                profiles.push(load_profile(path)?);
            }
            Source::Pool(profiles)
        }
        None => Source::Env,
    };

    // Консоль: лог в stderr, остановки нет (Ctrl+C завершает процесс).
    let reporter = Reporter::new(true);
    let (_stop_tx, stop_rx) = watch::channel(false);
    run(source, socks_bind, reference, reporter, stop_rx).await
}
