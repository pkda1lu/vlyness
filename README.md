# VLYNESS

Исследовательский проект: разбор VLESS/REALITY/XHTTP по байтам и дизайн транспорта нового поколения, устойчивого к поведенческому DPI (ТСПУ, 2026).

Не «ещё один шифр». Центральная идея — **связная легенда (coherent cover)** вместо обфускации: цель не «выглядеть случайно» (случайное = редкое = детектируемое), а **попасть в большой класс легитимного трафика**, вычистить который цензору дорого.

## Документы

| # | Файл | О чём |
|---|---|---|
| 00 | [docs/00-vless-anatomy.md](docs/00-vless-anatomy.md) | VLESS по байтам: формат кадра, XTLS Vision, REALITY, транспорты Xray, что VLESS даёт и не даёт |
| 01 | [docs/01-threat-model-tspu.md](docs/01-threat-model-tspu.md) | Модель угроз: ТСПУ как каскад слоёв L0–L4, что реально детектится в 2026, таблица «сигнал → лечится ли» |
| 02 | [docs/02-vlyness-design.md](docs/02-vlyness-design.md) | Дизайн VLYNESS: принцип когерентности, выбор легенды, IP/ASN, TLS без подлога, HTTP-несущая, ratchet-токен, anti-probing, shaping, клиентская дисциплина |
| 03 | [docs/03-wire-spec.md](docs/03-wire-spec.md) | Черновик байтовой спецификации v0.1 |
| 04 | [docs/04-roadmap.md](docs/04-roadmap.md) | Дорожная карта прототипа и методология измерения «неотличимости» |
| 05 | [docs/05-whitelist-traversal.md](docs/05-whitelist-traversal.md) | Проход сквозь белые списки: закон среды, три уровня строгости фильтра, таксономия носителей (co-tenancy/ECH, сервис-канал, refraction), бутстрап профилей |

## Три вывода, на которых держится дизайн

1. **Обфускация как «шум» мертва.** Классификатор ловит не «плохой» паттерн, а **редкий**. Устойчива только маскировка под массовый класс.
2. **Ловят несогласованность, а не признак.** Chrome-fingerprint нормален; Chrome на IP европейского ДЦ, с SNI, которого не было в DNS, и сессией на два часа — аномален. Защита = сквозная согласованность легенды (DNS, SNI, cert, JA3, HTTP/2, UA, форма трафика, ASN, время суток описывают одно приложение).
3. **Стоимость ошибки асимметрична.** Срабатывание = 120–600 с blackhole, а попытки «починить» штрафуются сильнее. Значит клиент обязан вести себя консервативно — и это даёт больше, чем любой шифр.

## Честные границы (подробно в 02 §10)

Протокол **не** решает репутацию ASN/подсети (только выбором площадки), тайминг-корреляцию глобального наблюдателя и компрометацию сервера. Whitelist-режим **проходится** — но только внутри разрешённого носителя, который надо иметь и вовремя менять ([док 05](docs/05-whitelist-traversal.md)). Абсолютной неотличимости не существует; всё измеряется как сдвиг стоимости детекта на дату замера.

## Код

Ядро на Rust: [`crates/vlyness-core`](crates/vlyness-core). Собрать и прогнать тесты:

```bash
cargo test -p vlyness-core
```

Статус **M1 (криптоядро)** — готово, 33 теста зелёные:

| Модуль | Спек | Что делает |
|---|---|---|
| [`auth`](crates/vlyness-core/src/auth.rs) | §3 | ratchet-токен: per-session salt/nonce/tag, KDF-BLAKE2s по эпохам, константная длина cookie, проверка в постоянном времени |
| [`frame`](crates/vlyness-core/src/frame.rs) | §5 | plaintext-кадр E2E-слоя: type/payloadLen/padLen + padding под будущим AEAD |
| [`address`](crates/vlyness-core/src/address.rs) | §6 | VLESS-совместимое адресное ядро: streamId/cmd/port/addr (IPv4/domain/IPv6) |
| [`noise`](crates/vlyness-core/src/noise.rs) | §4 | Noise_IK хендшейк (0-RTT, prologue=AUTH) + transport-режим (ChaCha20-Poly1305) + rekey |
| [`replay`](crates/vlyness-core/src/replay.rs) | §3 | анти-реплей: кэш nonce по окну эпох; пойманный cookie нельзя переиграть |

Сквозной тест `full_stack_carries_address_frame` проверяет всю цепочку: AddressFrame → Frame → Noise transport → и обратно.

Статус **P0 (дисциплина подключений)** — готово, 27 тестов. Крейт [`crates/vlyness-discipline`](crates/vlyness-discipline). Это то, что по модели угроз даёт больше практической стойкости, чем шифр: закрывает самые частые триггеры ТСПУ 2026 (пачки соединений, ретрай-штормы, ротацию fingerprint под штрафом).

| Модуль | Дизайн | Что делает |
|---|---|---|
| [`clock`](crates/vlyness-discipline/src/clock.rs) | — | инъектируемые часы/джиттер → вся логика детерминированно тестируема на мок-часах |
| [`backoff`](crates/vlyness-discipline/src/backoff.rs) | §5 | экспоненциальный backoff с полным джиттером (2 с → 300 с) |
| [`budget`](crates/vlyness-discipline/src/budget.rs) | §5 | потолок одновременных TLS (=1), интервал между попытками (≥800 мс), без реконнект-шторма |
| [`blackhole`](crates/vlyness-discipline/src/blackhole.rs) | §9 | детектор тихого дропа (отличает «нас заморозили» от «сеть упала») + эскалация тишины 150 с → 600 с → смена профиля |
| `ConnectionManager` ([lib.rs](crates/vlyness-discipline/src/lib.rs)) | §5,§9 | оркестратор: сводит всё в одну машину состояний |

Интеграционный тест `full_tspu_freeze_scenario` проигрывает весь сценарий заморозки: канал → тихий дроп → тишина 150 с → пробный коннект → повтор → 600 с → рекомендация сменить профиль.

Статус **Profile-движок** — готово, 17 тестов. Крейт [`crates/vlyness-profile`](crates/vlyness-profile). Реализует главный анти-детект принцип (§1): «ловят несогласованность, а не признак».

| Модуль | Что делает |
|---|---|
| [`model`](crates/vlyness-profile/src/model.rs) | Profile как единая легенда (serde JSON): identity/placement/carrier/tls/http/traffic/budget/schedule + ECH |
| [`validate`](crates/vlyness-profile/src/validate.rs) | валидатор когерентности: fp↔SETTINGS↔UA↔PQ = одно устройство; carrier↔placement↔traffic совместимы; ECH обязателен под WL-SNI; ротация fingerprint запрещена — собирает все нарушения разом |

Статус **traffic shaping** — готово, 14 тестов. Крейт [`crates/vlyness-shaping`](crates/vlyness-shaping). Закрывает признаки формы (§8) — форма трафика важнее содержания.

| Модуль | Дизайн | Что делает |
|---|---|---|
| [`sampler`](crates/vlyness-shaping/src/sampler.rs) | §8.1 | длины из эмпирического распределения (марковская цепочка, бимодальность), а не uniform padding — сам по себе аномалия |
| [`cadence`](crates/vlyness-shaping/src/cadence.rs) | §8.2 | постоянный ритм запросов + idle-fill: idle-туннель выглядит как воспроизведение видео |
| [`symmetrize`](crates/vlyness-shaping/src/symmetrize.rs) | §8.3 | бюджет восходящего канала под целевое down:up |

Статус **сессионный транспорт** — готово, 8 тестов (6 unit + 2 async-integration). Крейт [`crates/vlyness-transport`](crates/vlyness-transport). Первый слой, реально бегающий по сокету.

| Модуль | Что делает |
|---|---|
| [`record`](crates/vlyness-transport/src/record.rs) | кадры `[u16 len][body]` на любом async-потоке (хендшейк и transport-режим) |
| [`session`](crates/vlyness-transport/src/session.rs) | `Session` + `split()` на `SessionReader`/`SessionWriter` для **полного дуплекса**; rekey по счётчику кадров (прозрачно); фрагментация больших потоков (`send_stream_data`); padding от sampler'а. Носитель сменный |
| [`mux`](crates/vlyness-transport/src/mux.rs) | логические потоки (streamId/адрес) поверх ядра — всё в одном соединении (признак №5) |

Интеграционные тесты (loopback): `full_session_open_echo_close`, `full_duplex_concurrent_send_and_recv` (writer шлёт 50 сообщений залпом, reader собирает эхо параллельно), `rekey_is_transparent_across_many_frames`, `large_stream_is_fragmented_and_reassembled` (100 КБ), `wrong_auth_prologue_fails_handshake`.

Статус **carrier: TLS + HTTP/2** — готово, 4 async-integration теста на реальном TCP. Крейт [`crates/vlyness-carrier`](crates/vlyness-carrier). **Полный стек бежит по сокету:** TCP → TLS 1.3 → HTTP/2 → cookie-auth → Noise → mux → туннель.

| Модуль | Что делает |
|---|---|
| [`tls`](crates/vlyness-carrier/src/tls.rs) | TLS 1.3 поверх реального TCP (rustls + ring), фиксированная версия/провайдер |
| [`h2bridge`](crates/vlyness-carrier/src/h2bridge.rs) | мост `AsyncRead/AsyncWrite` поверх одного HTTP/2-стрима (учёт flow-control) |
| [`http`](crates/vlyness-carrier/src/http.rs) | `stream-one` (один двунаправленный POST) и `segments` (GET download + POST upload, спаривание по pid); AUTH в cookie (= Noise-prologue), honest-fallback (§7) |
| [`tls` ECH](crates/vlyness-carrier/src/tls.rs) | `client_config_grease_ech` (GREASE-ECH, анти-ossification) и `client_config_ech` (настоящий ECHConfigList носителя — co-tenancy сквозь WL-SNI, §5.2); HPKE через aws-lc-rs |

Ключевые доказанные свойства:
- `tunnel_over_tls_h2_with_cookie_auth` — полный стек: TLS+h2, AUTH в cookie замкнут на Noise-prologue, эхо 3 KB внутри одного h2-стрима.
- `honest_fallback_serves_real_site` — **зонд получает настоящий сайт (200 + контент), а не RST/404** (§7): запрос без валидного токена или не на туннельный путь неотличим от обычного посетителя.
- `wrong_server_key_breaks_session_inside_tls` — **TLS сам по себе не аутентифицирует**: при неверном ключе сервера Noise рвётся. Ровно поэтому E2E обязателен для co-tenancy (CDN терминирует TLS, но не читает и не подменяет нас).

Статус **релей + бинарники** — готово. Крейты [`vlyness-node`](crates/vlyness-node) (движок релея: mux-потоки ↔ реальные TCP-сокеты; SOCKS5) и [`vlyness-cli`](crates/vlyness-cli) (`vlyness-server` / `vlyness-client`).

| Компонент | Что делает |
|---|---|
| [`node::relay`](crates/vlyness-node/src/relay.rs) | актор-движок: writer-таск мультиплексирует, reader-таск демультиплексирует, по 2 таска на поток. `run_server_relay` (сервер коннектится к целям), `TunnelClient` (клиент открывает потоки) |
| [`node::socks`](crates/vlyness-node/src/socks.rs) | SOCKS5 CONNECT-приём для локальных приложений |
| `vlyness-server` | TLS+h2 + релей + honest-fallback; генерирует ключи/серт |
| `vlyness-client` | валидирует Profile при старте; `ConnectionManager` (budget/backoff) + cadence-драйвер (idle-fill §8.2) + монитор трафика с reference-пробером для blackhole-детекции (§9); локальный SOCKS5 → туннель |

Сквозные тесты `end_to_end_tcp_through_tunnel` и `two_streams_multiplex_over_one_tunnel` гоняют реальный TCP насквозь (app → client → TLS/h2 → server → real connect → echo). Живой прогон бинарников подтверждён: python-SOCKS5-клиент прокачал данные через `vlyness-client → туннель → vlyness-server → эхо-цель`.

### Запуск

Сервер (печатает PSK/ключи/серт для клиента):
```bash
cargo run --bin vlyness-server
```

Клиент (подставить значения из вывода сервера):
```bash
VLYNESS_SERVER_ADDR=127.0.0.1:8443 VLYNESS_CA=./vlyness-cert.pem \
VLYNESS_PSK_B64=... VLYNESS_SERVER_PUB_B64=... \
cargo run --bin vlyness-client
```
Затем указать приложению SOCKS5-прокси `127.0.0.1:1080`. Опции клиента:
- `VLYNESS_MODE=segments` — режим GET+POST вместо одного стрима (по умолчанию `stream`);
- `VLYNESS_ECH=grease` — GREASE-ECH; `VLYNESS_ECH_CONFIG_B64=<base64>` — настоящий ECH с ECHConfigList носителя;
- `VLYNESS_PROFILE=<путь.json>` — валидация когерентности при старте (отказ, если легенда несогласована) + cadence/budget из профиля;
- `VLYNESS_REFERENCE=<host:port>` — контрольный хост для blackhole-детекции (без него детектор не эскалирует).

Дальше (см. [дорожную карту](docs/04-roadmap.md)): режим `segments` (GET сегментов / POST телеметрии — максимум правдоподобия под медиа), cadence-драйвер + полное подключение blackhole-детектора (reference-пробер) в клиент, **ECH-путь co-tenancy** (док 05).

## Назначение

Двойное. Проектируется под доступ к информации в условиях цензуры и авторизованное исследование устойчивости сетей — на своей инфраструктуре или с согласия владельца. Не под атаку на инфраструктуру и не под массовое злоупотребление.
