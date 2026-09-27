//! `vlyness-setup` — генератор конфигурации для развёртывания: одной командой создаёт
//! серверный `server.toml` и клиентский профиль `client.json` со **всеми** секретами
//! (PSK + статическая пара сервера), устраняя копипаст ключей.
//!
//! Профиль — Direct (свой VPS со своим доменом), режим по умолчанию `datagram`
//! (HTTP/3 + WebTransport). Сертификат — настоящий (Let's Encrypt) либо самоподписанный.
//!
//! Использование:
//!   vlyness-setup --domain rtc.example.tld [опции]
//! Опции:
//!   --out-dir DIR        куда писать конфиги (по умолчанию ./vlyness-config)
//!   --tunnel-path PATH   путь туннеля (по умолчанию /v1/rtc)
//!   --port N             порт входа (по умолчанию 443)
//!   --mode M             datagram | stream | both (по умолчанию datagram)
//!   --self-signed        самоподписанный серт (иначе — пути Let's Encrypt)
//!   --cert-dir DIR       каталог сертификата (по умолчанию /etc/letsencrypt/live/<domain>)
//!   --client-ca PATH     куда клиент кладёт доверенный PEM при --self-signed

use std::collections::HashMap;

use vlyness_cli::config::ServerConfig;
use vlyness_cli::profilegen::build_client_profile;
use vlyness_cli::b64_encode;
use vlyness_core::noise::generate_keypair;
use vlyness_profile::{validate, Profile, TrafficMode};

type BoxErr = Box<dyn std::error::Error>;

struct Args {
    domain: String,
    out_dir: String,
    tunnel_path: String,
    port: u16,
    mode: String,
    self_signed: bool,
    cert_dir: Option<String>,
    client_ca: String,
}

fn parse_args() -> Result<Args, BoxErr> {
    let mut flags: HashMap<String, String> = HashMap::new();
    let mut self_signed = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--self-signed" => self_signed = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            k if k.starts_with("--") => {
                let v = it.next().ok_or_else(|| format!("{k} требует значение"))?;
                flags.insert(k[2..].to_string(), v);
            }
            other => return Err(format!("неизвестный аргумент: {other}").into()),
        }
    }
    let domain = flags
        .remove("domain")
        .ok_or("обязателен --domain <имя> (или --domain <ip> с --self-signed)")?;
    let out_dir = flags.remove("out-dir").unwrap_or_else(|| "./vlyness-config".to_string());
    Ok(Args {
        client_ca: flags
            .remove("client-ca")
            .unwrap_or_else(|| format!("{out_dir}/vlyness-cert.pem")),
        cert_dir: flags.remove("cert-dir"),
        tunnel_path: flags.remove("tunnel-path").unwrap_or_else(|| "/v1/rtc".to_string()),
        port: flags.remove("port").map(|s| s.parse()).transpose()?.unwrap_or(443),
        mode: flags.remove("mode").unwrap_or_else(|| "datagram".to_string()),
        self_signed,
        out_dir,
        domain,
    })
}

fn print_help() {
    eprintln!(
        "vlyness-setup --domain <имя> [--out-dir DIR] [--tunnel-path P] [--port N]\n\
         \x20             [--mode datagram|stream|both] [--self-signed] [--cert-dir DIR] [--client-ca PATH]"
    );
}

/// Собрать когерентный Direct-профиль под выбранный режим (валидируется перед записью).
fn write_profile(path: &str, p: &Profile) -> Result<(), BoxErr> {
    validate(p).map_err(|errs| {
        let codes: Vec<_> = errs.iter().map(|e| e.code).collect();
        format!("сгенерированный профиль '{}' некогерентен: {codes:?}", p.id)
    })?;
    std::fs::write(path, p.to_json())?;
    Ok(())
}

fn main() -> Result<(), BoxErr> {
    let args = parse_args()?;
    std::fs::create_dir_all(&args.out_dir)?;

    // Секреты.
    let mut psk = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut psk);
    let psk_b64 = b64_encode(&psk);
    let kp = generate_keypair()?;
    let server_priv_b64 = b64_encode(&kp.private);
    let server_pub_b64 = b64_encode(&kp.public);

    // Сертификат: пути Let's Encrypt или самоподпись.
    let (cert_pem, key_pem) = if args.self_signed {
        (None, None)
    } else {
        let dir = args
            .cert_dir
            .clone()
            .unwrap_or_else(|| format!("/etc/letsencrypt/live/{}", args.domain));
        (Some(format!("{dir}/fullchain.pem")), Some(format!("{dir}/privkey.pem")))
    };

    // Серверный конфиг: и TCP, и QUIC на одном порту (реальные H3 так и слушают).
    let bind = format!("0.0.0.0:{}", args.port);
    let server_cfg = ServerConfig {
        bind: bind.clone(),
        quic: Some(bind.clone()),
        domain: args.domain.clone(),
        tunnel_path: args.tunnel_path.clone(),
        psk_b64: psk_b64.clone(),
        server_priv_b64,
        server_pub_b64: server_pub_b64.clone(),
        cert_pem,
        key_pem,
        site_body_path: None,
        // Панель по умолчанию на loopback; доступ через SSH-туннель.
        admin_bind: Some("127.0.0.1:8088".to_string()),
    };
    let server_toml_path = format!("{}/server.toml", args.out_dir);
    std::fs::write(&server_toml_path, server_cfg.to_toml())?;

    // Клиент коннектится по домену:порту (при настоящем серте — системные корни).
    let server_addr = format!("{}:{}", args.domain, args.port);
    let client_ca = if args.self_signed { Some(args.client_ca.clone()) } else { None };

    let mut client_profiles: Vec<String> = Vec::new();
    let mk = |mode: TrafficMode, id: &str| {
        build_client_profile(
            mode, id, &args.domain, &args.tunnel_path, &server_addr, &psk_b64, &server_pub_b64,
            client_ca.clone(),
        )
    };
    match args.mode.as_str() {
        "datagram" => {
            let path = format!("{}/client.json", args.out_dir);
            write_profile(&path, &mk(TrafficMode::Datagram, "vps-datagram-h3"))?;
            client_profiles.push(path);
        }
        "stream" => {
            let path = format!("{}/client.json", args.out_dir);
            write_profile(&path, &mk(TrafficMode::Stream, "vps-stream-h2"))?;
            client_profiles.push(path);
        }
        "both" => {
            let d = format!("{}/client-datagram.json", args.out_dir);
            let s = format!("{}/client-stream.json", args.out_dir);
            write_profile(&d, &mk(TrafficMode::Datagram, "vps-datagram-h3"))?;
            write_profile(&s, &mk(TrafficMode::Stream, "vps-stream-h2"))?;
            client_profiles.push(d);
            client_profiles.push(s);
        }
        other => return Err(format!("неизвестный --mode: {other} (datagram|stream|both)").into()),
    }

    // Итог и следующие шаги.
    println!("Конфигурация записана в {}/", args.out_dir);
    println!("  сервер : {server_toml_path}");
    for p in &client_profiles {
        println!("  клиент : {p}");
    }
    println!();
    println!("СЕРВЕР (на VPS):");
    println!("  VLYNESS_CONFIG={server_toml_path} vlyness-server");
    if args.self_signed {
        println!("  (самоподпись: сервер запишет ./vlyness-cert.pem — скопируй его клиенту в {})", args.client_ca);
    } else {
        println!("  требуется сертификат Let's Encrypt для {} (см. DEPLOY.md: certbot)", args.domain);
    }
    println!();
    println!("КЛИЕНТ:");
    println!("  VLYNESS_PROFILES={} VLYNESS_SOCKS_BIND=127.0.0.1:1080 vlyness-client", client_profiles.join(","));
    println!("  прокси: SOCKS5 127.0.0.1:1080");
    Ok(())
}
