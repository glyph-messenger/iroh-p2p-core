# Roadmap / Идеи развития iroh-p2p-core

Идеи реализации, собранные на основе анализа использования библиотеки в
[Glyph](https://github.com/glyph-messenger/glyph) и [Rune](https://github.com/glyph-messenger/rune).

---

## Контекст

Библиотека молодая (два коммита), adoption частичный:

- **Rune** использует почти всё (`EndpointId`, `Identity`, `WireSignature`, `PeerBook`,
  `ReplayFilter`, `framing`), но дублирует паттерн подписанных тикетов
  (`rune-protocol/src/ticket.rs` — почти копия `SignedTicket<T>`) и повторяет
  `sign_bytes/sign/verify` трижды в `rune-protocol/src/messages.rs`
  (`JoinRequest`, `PeerAnnouncement`, `PeerLeave`).
- **Glyph** использует только `EndpointId`, `ENDPOINT_ID_LEN`, `SIGNATURE_LEN`, `P2pError`,
  а `Identity`, `ReplayFilter`, `PeerBook` копирует 1:1 в
  `glyph-crypto/src/identity.rs`, `glyph-crypto/src/replay.rs`, `glyph-net/src/addr.rs`
  (~600 строк дубликатов).

---

## Приоритет 1 — устранение дублирования

### 1.1 Универсальный паттерн «подписанное сообщение»

Самый повторяющийся код в обоих проектах — `sign_bytes()` (bincode + domain separator),
`sign()`, `verify()`. Предложить один из вариантов:

**Вариант A — трейт:**

```rust
/// Тип, который умеет считать канонические байты для подписи.
pub trait Signable {
    fn sign_bytes(&self, domain: &'static [u8]) -> Vec<u8>;

    fn sign_with(&mut self, identity: &Identity, domain: &'static [u8])
    where Self: SetSignature,
    {
        let bytes = self.sign_bytes(domain);
        self.set_signature(WireSignature(identity.sign(&bytes)));
    }

    fn verify_with(&self, signer: &EndpointId, domain: &'static [u8]) -> Result<()>
    where Self: GetSignature,
    {
        let bytes = self.sign_bytes(domain);
        verify(signer, &bytes, self.get_signature().as_bytes())
    }
}

pub trait SetSignature { fn set_signature(&mut self, sig: WireSignature); }
pub trait GetSignature { fn get_signature(&self) -> &WireSignature; }
```

**Вариант B — derive-макрос** (`iroh-p2p-core-derive`):

```rust
#[derive(Signed)]
#[sign_domain = "rune-ctrl-v1"]
struct JoinRequest {
    client_endpoint: EndpointId,
    // ... остальные поля
    #[signature]
    signature: WireSignature,
}
```

Макрос генерирует `sign_bytes/sign/verify` автоматически, исключая поле с атрибутом
`#[signature]` из подписываемых байт.

**Эффект:** rune удаляет ~200 строк (`messages.rs`), glyph — свои
`envelope_sign_bytes/ticket_sign_bytes` из `glyph-protocol/src/codec.rs`.

- [ ] Выбрать вариант (трейт проще и без proc-macro; макрос удобнее)
- [ ] Реализовать + юнит-тесты (tampering, domain separation)
- [ ] Мигрировать rune `messages.rs` и glyph `codec.rs`

### 1.2 `SignedEnvelope` в ядре

У glyph есть готовый паттерн envelope: `version`, `timestamp_ms`, `nonce`, `sender`,
`payload`, `signature` + `verify_envelope_with_replay` (`glyph-crypto/src/identity.rs`).
Это общий примитив для P2P-приложений.

```rust
pub struct SignedEnvelope<P> {
    pub version: u16,
    pub timestamp_ms: u64,
    pub nonce: [u8; 16],
    pub sender: EndpointId,
    pub payload: P,
    pub signature: WireSignature,
}

impl<P> SignedEnvelope<P> {
    pub fn sign(&mut self, identity: &Identity, domain: &'static [u8]);
    pub fn verify(&self, domain: &'static [u8]) -> Result<()>;
    pub fn verify_with_replay(&self, domain: &'static [u8], filter: &ReplayFilter) -> Result<()>;
}
```

**Эффект:** glyph удаляет свой `replay.rs` и `verify_*`-хелперы, переиспользуя ядро.

- [ ] Реализовать `SignedEnvelope` + `encode/decode` (bincode)
- [ ] Мигрировать glyph: заменить `Envelope`-верификацию на ядерную

### 1.3 Переход обоих проектов на `SignedTicket<T>`

В ядре уже есть `from_endpoint_addr`/`to_endpoint_addr`, но rune пишет свои
`ticket_to_endpoint_addr`/`endpoint_addr_to_ticket` в `rune-net/src/addr.rs`.
Тикет-типы у проектов свои (`NetworkTicket`, `InviteTicket`), поэтому прямой переход
невозможен без адаптера.

**Идея:** вынести «адресную часть» тикета в общий тип в ядре:

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TicketAddrInfo {
    pub relay_url: Option<String>,
    pub direct_addrs: Vec<SocketAddr>,
}

impl TicketAddrInfo {
    pub fn from_endpoint_addr(addr: &EndpointAddr) -> Self;
    pub fn to_endpoint_addr(&self, id: EndpointId) -> Result<EndpointAddr>;
}
```

Проекты встраивают `TicketAddrInfo` в свои тикеты и получают конверсии бесплатно.

**Эффект:** убирает дубликат в `rune-net/src/addr.rs` и `glyph-net/src/addr.rs`.

- [ ] Добавить `TicketAddrInfo` в `ticket.rs`
- [ ] Мигрировать rune `addr.rs`, glyph `addr.rs`

---

## Приоритет 2 — улучшение существующих модулей

### 2.1 `ReplayFilter` (используется в rune-host и glyph-server)

- [ ] **Per-sender фильтрация.** Сейчас nonce-пространство глобальное; для multi-user
      сервера правильнее keyed по `EndpointId`:

```rust
pub struct SenderReplayFilter {
    filters: RwLock<HashMap<EndpointId, ReplayFilter>>,
}

impl SenderReplayFilter {
    pub fn check_and_record(&self, sender: EndpointId, ts_ms: u64, nonce: &[u8; 16]) -> Result<()>;
}
```

- [ ] **Раздельные `check()` / `record()`** — сейчас только `check_and_record`,
      нельзя «проверить всё, потом закоммитить» (важно для транзакционной логики host'а).
- [ ] **Инъекция часов** (`now_fn: fn() -> u64` или `Instant`) для детерминированных тестов.
- [ ] Экспорт `len()`, внешний `prune()`.
- [ ] Использовать один тип ключа (сейчас `[u8; 16]` захардкожен в `P2pError::ReplayDetected`).

### 2.2 `PeerBook`

- [ ] **`last_seen`/TTL** — хранить `Instant`/timestamp обновления и уметь выселять
      устаревшие записи (`evict_older_than`).
- [ ] **Итераторы и снимки:** `iter()`, `snapshot() -> HashMap<EndpointId, EndpointAddr>`, `merge(&PeerBook)`.
- [ ] **Serde-персистентность:** `save(&Path)` / `load(&Path)` для переживания рестартов.
- [ ] **Оптимизация `update()`** — сейчас цепочка `existing.clone().with_*()` на каждый
      адрес даёт O(n²) копирований; переписать на одну сборку.

### 2.3 `Identity`

- [ ] **`zeroize` секрета при drop** (сейчас ключ остаётся в памяти).
- [ ] **Версия формата файла** (magic + version) вместо голых 32 байт — иначе будущее
      изменение формата молча сломает старые ключи.
- [ ] **`sign_struct(domain, &T) -> WireSignature`** — одно место для «подписать структуру»
      вместо ручного bincode-оборачивания во всех проектах.
- [ ] **`from_seed([u8; 32])`** для детерминированных тестов и интеграций.

### 2.4 `framing`

- [ ] **`FramedStream<T>`** — асинхронный поток сообщений (как tokio-serde, но на bincode):

```rust
pub struct FramedStream<S, T> { /* ... */ }
impl<S: AsyncRead + AsyncWrite + Unpin, T: Serialize + DeserializeOwned> FramedStream<S, T> {
    pub async fn send(&mut self, msg: &T) -> Result<()>;
    pub async fn recv(&mut self) -> Result<T>;
}
```

- [ ] **Опциональный varint-длинник** — 4 байта на каждое мелкое контрольное сообщение
      (у rune их много) — расточительно.
- [ ] **`write_frame` без `flush`** (флаг/отдельная функция) для пакетной отправки.
- [ ] Конфигурация через структуру (`FramingConfig { max_frame_size, varint, flush }`)
      вместо раскиданных констант.

### 2.5 `ticket`

- [ ] **`expires_at` / `not_before`** и проверка возраста в `verify()`.
- [ ] **`Display` / `FromStr`** для `SignedTicket<T>` (сейчас только `encode_base32`).
- [ ] **Убрать `unwrap_or_default()` в `sign_bytes()`** — скрытая ошибка сериализации
      сейчас превращается в подписывание пустых байт; возвращать `Result<Vec<u8>>`.

### 2.6 `endpoint_id`

- [ ] **Serde как hex-строка** для человекочитаемых форматов (сейчас в JSON — массив чисел):
      `#[serde(with = "hex_serde")]` с сохранением бинарного вида для bincode.
- [ ] `AsRef<[u8]>`, `Borrow<[u8]>` для совместимости с общими API.
- [ ] Ускорение `to_hex()` (константный буфер вместо цикла с `write!`).

### 2.7 `error`

- [ ] Варианты: `RelayUrl`, `InvalidLength`, `Expired` — сейчас всё падает в `Other(String)`.
- [ ] Рассмотреть `#[non_exhaustive]` для semver-гибкости.

---

## Приоритет 3 — новые модули

### 3.1 `nonce`

Оба проекта страдают без нормального источника nonce:

- glyph генерирует nonce хаком через `uuid::Uuid::new_v4()` (`glyph-protocol/src/ids.rs`)
- rune тянет `rand` 0.8 только ради `thread_rng().fill_bytes()` (`rune-core/src/host.rs`)

```rust
pub const NONCE_LEN: usize = 16;
pub fn random_nonce() -> [u8; NONCE_LEN];   // на getrandom
```

- [ ] Реализовать, заменить костыли в glyph и rune, убрать лишние зависимости.

### 3.2 `time`

`unix_now_ms()` есть отдельной копией в glyph (`glyph-protocol/src/types.rs`) и инлайном
в rune (`rune-core/src/host.rs`).

```rust
pub fn unix_now_ms() -> u64;
```

### 3.3 `rate` — RateLimiter / token bucket

Нужен glyph-server и rune-host для защиты от спама join/сообщений.

```rust
pub struct RateLimiter { /* token bucket */ }
impl RateLimiter {
    pub fn new(rate_per_sec: f64, burst: usize) -> Self;
    pub fn try_acquire(&self, key: EndpointId) -> bool;   // keyed-вариант
}
```

### 3.4 `backoff`

Экспоненциальный backoff для переподключений — общая боль обоих проектов.

### 3.5 `connect` — хелперы поверх iroh Endpoint

- `connect_with_retry(endpoint, peer_book, id)` — попытки по всем известным адресам.
- Keepalive / ping-pong с таймаутами (rune уже делает свой `Ping/Pong` вручную).

### 3.6 `secrets` — X25519 + HKDF

Для E2E-производных ключей (glyph key packages, rune при желании):

```rust
pub struct DhKeypair { /* x25519 */ }
pub fn derive_symmetric(dh: SharedSecret, context: &str) -> [u8; 32]; // HKDF/blake3
```

---

## Приоритет 4 — инфраструктура

- [ ] **Feature flags.** Сейчас `EndpointId` в glyph тянет за собой весь `iroh`
      (тяжёлая зависимость) ради одного типа. Разделить:
      - `core` (по умолчанию): `endpoint_id`, `identity`, `signature`, `replay`, `framing` —
        только `iroh-base`
      - `iroh` (опционально): `ticket`, `peerbook` — полный `iroh`
- [ ] **Публикация на crates.io** — убрать git-зависимости и `[patch]`-костыль из
      `glyph/Cargo.toml`.
- [ ] **CI**: в `.github` сейчас нет workflow. Добавить `cargo fmt/clippy/test` + проверку
      всех feature-комбинаций.
- [ ] **Fuzz-тесты** `decode_base32` на мусорных строках (защита от паник),
      proptest для ticket roundtrip.
- [ ] **Бенчмарки** (criterion) для framing и replay.
- [ ] **Документация:** doc-примеры для каждого модуля, `#![deny(missing_docs)]`,
      CHANGELOG.

---

## Известные проблемы в зависимых проектах

1. **Glyph `glyph-protocol/src/ids.rs` (строки 104–123)** реализует
   `impl fmt::Debug/Display/FromStr for EndpointId` — чужой тип из крейта, это нарушение
   orphan rule (E0117), код не скомпилируется. Ядро уже даёт `Display` (полный hex)
   и `Debug` (короткий hex); для `FromStr -> ProtocolError` достаточно существующего
   `#[from] P2pError` в `glyph-protocol/src/error.rs`. Мигрировать glyph на нативные
   impl'ы ядра.
2. **Rune `rune-net/src/addr.rs`** дублирует конверсии ticket ↔ `EndpointAddr` из ядра
   (см. 1.3).
3. **Rune `messages.rs`** — три копии `sign_bytes/sign/verify` (см. 1.1).

---

## Предлагаемый порядок работы

1. 1.1 + 1.2 (derive/трейт подписанных сообщений + `SignedEnvelope`) — максимальный
   эффект, сокращает оба проекта на сотни строк.
2. 2.1 (`ReplayFilter`: per-sender + check/record split) — нужно обоим серверам.
3. 2.2 + 2.3 (`PeerBook` TTL, `Identity` zeroize/версия формата).
4. 3.1–3.2 (nonce/time) — быстрые победы, убирают костыли и зависимости.
5. 1.3 (`TicketAddrInfo`) и миграция тикетов.
6. 4.x (feature flags, crates.io, CI).
