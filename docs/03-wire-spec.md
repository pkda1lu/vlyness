# 03. VLYNESS wire spec (черновик v0.1)

Статус: черновик для прототипа. Не финал. Криптопримитивы фиксированы, чтобы избежать negotiation-канала (набор алгоритмов сам по себе fingerprint — учимся на JA3).

## 1. Криптонабор (фиксирован, без переговоров)

| Роль | Алгоритм |
|---|---|
| KEM/DH | X25519 |
| Хендшейк | Noise_IK_25519_ChaChaPoly_BLAKE2s |
| AEAD данных | ChaCha20-Poly1305 (или AES-256-GCM при аппаратном AES; выбор клиента, не влияет на wire) |
| KDF | KDF-BLAKE2s — extract+expand на нативном keyed-BLAKE2s (не HMAC-HKDF; см. ниже) |
| Хэш/MAC токена | keyed BLAKE2s-256 |

`KDF-BLAKE2s` определяется как:
```
extract:  PRK = BLAKE2s-MAC(key = salt, msg = ikm)
expand:   OKM = BLAKE2s-MAC(key = PRK,  msg = info || 0x01)     # один 32-байтовый блок
```
Почему не HMAC-HKDF: BLAKE2 имеет собственный keyed-режим, и HMAC поверх BLAKE2s не является идиоматичным (и не собирается стандартным HMAC, требующим eager-buffer hash). Единый примитив keyed-BLAKE2s и для вывода ключей, и для тега — меньше зависимостей и меньше поверхности для fingerprint по набору алгоритмов (§1). Реализация: `crates/vlyness-core/src/auth.rs`.

Отсутствие ciphersuite-negotiation умышленно: нечего перебирать зонду, нечего fingerprint'ить по набору.

## 2. Уровни инкапсуляции

```
┌─ настоящий TLS 1.3 (свой домен / CDN)                     ← виден DPI как HTTPS
│  ┌─ HTTP/2 (или /3) несущая                               ← виден как медиа-API
│  │  cookie: sid=<AUTH>                                     ← §3
│  │  ┌─ E2E-слой (Noise + AEAD-кадры)                       ← невидим (внутри TLS+тело)
│  │  │  ┌─ адресный хедер (VLESS-совместимый, урезанный)    ← §5
│  │  │  │  └─ полезные данные пользователя
```

Строки «виден DPI как HTTPS / как медиа-API» — единственное, что доступно ТСПУ при целом внешнем TLS. Всё ниже cookie — внутри тела и/или внутри AEAD.

## 3. Токен аутентификации (AUTH)

Строится клиентом на каждую сессию.

```
epoch      := uint64( floor(unixtime / 3600) )           # окно 1 час
salt       := random(16)                                  # per-session
clientNonce:= random(12)                                  # per-session, антиреплей
authKey    := KDF-BLAKE2s( salt, PSK,                     # PSK — общий секрет из подписки
                 info = "vlyness/auth/v1" || LE64(epoch) ) # 32 байта
authTag    := BLAKE2s-MAC(key=authKey, msg = salt || clientNonce)[0:16]

AUTH       := base64url( salt || clientNonce || authTag )   # 16+12+16 = 44 байта → 59 симв.
```

* Длина AUTH **константна** (59 символов base64url без padding, из 44 сырых байт). Это критично: переменная длина cookie — канал. Закреплено тестом `token_length_is_constant`.
* Сервер принимает `epoch ∈ {now−1, now, now+1}` (толерантность к дрейфу часов ~1 ч).
* Антиреплей: сервер держит кэш виденных `clientNonce` на 2 эпохи. Повтор → обращение как с зондом (honest fallback, §6), **не** ошибка.
* `PSK` (32 байта) и статический публичный ключ сервера `S_pub` (для §4) выдаются в строке подписки.

Формат cookie (длины всех значений константны):
```
Cookie: sid=<AUTH>; v=<2-симв. константа профиля>
```

## 4. E2E-хендшейк (Noise IK, 0-RTT)

Клиент знает `S_pub`, поэтому шлёт данные уже в первом сообщении.

```
-> e, es, s, ss, [payload_0]        # msg1: эфемерный ключ клиента + шифр статики клиента + первые данные
<- e, ee, se, [payload_1]           # msg2: эфемерный ключ сервера + подтверждение
                                    # далее transport-режим, две AEAD-цепочки (c->s, s->c)
```

* `msg1` встраивается в тело первого HTTP-запроса (для `stream`) или первого `POST /telemetry` (для `segments`).
* `msg2` — в теле первого ответа.
* Rekey: автоматически каждые 2^20 кадров или 2^34 байт, что раньше.
* Ключи хендшейка привязываются к AUTH (`prologue = AUTH`), чтобы нельзя было переклеить украденный AUTH к чужому хендшейку.

## 5. Кадр E2E-слоя

Внутри AEAD. Наружу видна только длина шифртекста, которая уже прошла через sampler длин (док 02 §8.1).

```
Открытый (до шифрования):
+--------+-----------+-------------+-----------------+-------------+
|  1 B   |    2 B    |    2 B      |   payloadLen B  |   padLen B  |
+--------+-----------+-------------+-----------------+-------------+
|  type  | payloadLen|   padLen    |     payload     |   padding   |
+--------+-----------+-------------+-----------------+-------------+

type: 0x01 STREAM_DATA   0x02 STREAM_OPEN   0x03 STREAM_CLOSE
      0x04 KEEPALIVE      0x05 REKEY         0x06 ADDRESS
padLen: длина случайного заполнителя; padding содержимого не несёт
```

Заголовок (5 B) + payload + padding шифруются как единый AEAD-объект; +16 B тега. `payloadLen`/`padLen` находятся **внутри** шифртекста → наблюдателю недоступны; он видит лишь суммарную длину, которую задаёт sampler.

## 6. Адресный кадр (type=0x06 ADDRESS) — VLESS-совместимое ядро

Открытие нового логического потока к цели. Формат намеренно повторяет адресную часть VLESS, чтобы переиспользовать логику роутинга Xray.

```
+-----------+--------+--------+-----------+---------+
|   2 B     |  1 B   |  2 B   |    1 B     |   N B   |
+-----------+--------+--------+-----------+---------+
| streamId  |  cmd   |  port  | addrType  |  addr   |
+-----------+--------+--------+-----------+---------+

cmd:      0x01 TCP   0x02 UDP
addrType: 0x01 IPv4(4)   0x02 domain(1+len)   0x03 IPv6(16)
```

Отличия от VLESS-хедера (док 00 §2):
* нет `ver` и нет `UUID` — аутентификация ушла в §3/§4;
* добавлен `streamId` — потому что всё мультиплексируется в одном TLS (док 02 §5, признак №5);
* `flow`/addons убраны — Vision заменён shaping-слоем (§8 док 02), который работает и для не-TLS внутреннего трафика.

## 7. Honest fallback (серверная логика)

Псевдокод обработки входящего HTTP-запроса. Цель — **неразличимость по времени и по ответу**.

```
on_request(req):
    t0 = now()
    result = REAL_SITE                       # по умолчанию — обычный сайт
    if req.path matches TUNNEL_ROUTES:
        auth = parse_cookie_sid(req)         # timing-safe, всегда полный разбор
        ok   = verify_auth(auth)             # timing-safe, всегда полный HKDF+MAC
        if ok and not replayed(auth):
            result = TUNNEL
        else:
            result = DEMO_MEDIA              # настоящий медиа-сегмент из статики
    # выровнять время ответа независимо от ветки:
    sleep_until(t0 + profile.base_latency + jitter())
    serve(result)
```

Инварианты:
* любой путь возвращает **валидный успешный ответ** ожидаемого для сайта типа; никаких 403/404/RST по признаку авторизации;
* `verify_auth` выполняется полностью даже для заведомо мусорного cookie (нет ранних выходов);
* `DEMO_MEDIA` и `TUNNEL` отдают контент одинакового класса длин/таймингов;
* заголовки ответа идентичны во всех ветках и соответствуют Profile.

## 8. Параметры Profile (сериализуемый объект)

```jsonc
{
  "id": "media-abr-h2-v1",
  "identity":  { "domain": "example.tld", "acme": true },
  "placement": { "mode": "cdn|colo|direct", "target_asn_class": "cdn" },
  "tls":       { "alpn": ["h2"], "fp": "okhttp-4", "pq_keyshare": false },
  "http":      { "version": 2, "settings_profile": "okhttp-4",
                 "ua": "ExampleMedia/3.2 (Android 14)",
                 "routes": { "seg": "/v1/media/{sid}/seg/{n}.m4s",
                             "tel": "/v1/media/{sid}/telemetry" } },
  "session":   { "auth_cookie": "sid", "profile_cookie_val": "m1" },
  "traffic":   { "mode": "segments",
                 "seg_interval_ms": 4000, "seg_jitter_ms": 800,
                 "len_hist": "…эмпирическая гистограмма…",
                 "len_markov": "…матрица переходов…",
                 "target_ratio_down_up": 15,
                 "idle_fill": true },
  "budget":    { "max_tls_conns": 1, "min_conn_interval_ms": 800,
                 "backoff_base_ms": 2000, "backoff_cap_ms": 300000,
                 "rotate_fingerprint": false },
  "schedule":  { "active_hours": [7,24], "max_session_min": 180 }
}
```

**Инвариант когерентности проверяется валидатором при загрузке профиля** (док 02 §1): `tls.fp` ↔ `http.settings_profile` ↔ `http.ua` должны быть из одного «устройства»; `traffic.mode` должен быть совместим с `placement.mode` (например, `stream` несовместим с `cdn`); `len_hist` должна соответствовать `traffic.mode`. Несовместимый профиль отклоняется до старта, а не «работает криво».

## 9. Открытые вопросы для прототипа

1. Насколько дорого `segments`-cadence по трафику в простое и приемлемо ли это на мобильном тарифе. Нужен замер.
2. Реальные `len_hist`/`settings_profile` надо снимать с живых приложений — заготовить сборщик профилей (пассивный, со своего же трафика, без нарушения приватности третьих лиц).
3. QUIC/HTTP-3 путь: WebTransport datagrams против QUIC-паддинга — что реалистичнее по fingerprint.
4. Механизм ротации/доставки профилей как расходников без централизованной точки, которую саму можно заблокировать.

Дорожная карта прототипа — [04-roadmap.md](04-roadmap.md).
