# Модель безопасности

## Threat model

| Атака | Митигация | Статус |
|--------|-----------|--------|
| **Sybil** | PoW-сложность (дефолт 16, adaptive/epoch-based; `MAX_POW_DIFFICULTY=24` — жёсткий потолок) | Реализовано |
| **Eclipse (DHT)** | /24 subnet diversity в k-bucket'ах (K/4=5 max на subnet) | Реализовано |
| **Mailbox flood** | Reject при заполнении (без eviction); per-sender квота; global 100K cap | Реализовано |
| **Replay (routing)** | Двухуровневый dedup: per-(origin,via,seq) + per-(origin,seq); `MAX_ROUTE_ANNOUNCE_AGE_SECS=300` | Реализовано |
| **DHT poisoning** | Валидация `expires_at`; подписанные STORE-анонсы | Реализовано |
| **DHT delete abuse** | `DeletePayload` требует `(algo, pubkey, signature)`; `BLAKE3(pubkey)==key` (только self-owned) | Реализовано |
| **DHT seed exhaustion** | HashSet-based O(1) dedup в iterative lookups | Реализовано |
| **DHT enumeration** | FIND_NODE V2 + FIND_VALUE отдают только node_id (транспорты до-разрешаются per-hop через `ResolveTransport`); Public-only + half-cap фильтр на closest-node ответах | Реализовано (C-06) |
| **Gateway spoofing (session)** | `peer_roles` кэш сверяется с handshake capabilities | Реализовано |
| **Mesh-beacon spoofing (on-link)** | Неподписанные beacon'ы отбрасываются по умолчанию (`require_signed_beacons=true`); role-флаги не анонсируются, пока не задан `advertise_role_in_beacon` | Реализовано (C-03) |
| **Rate flood** | Per-peer token bucket → violation tracker (5 strikes / 5 мин) → ban list | Реализовано |
| **Connection flood** | `MAX_SESSIONS_PER_IP=32`; опциональный PoW challenge на handshake | Реализовано |
| **Congestion** | Backpressure при >78% load; adaptive fan-out режется вдвое при >50% | Реализовано |
| **Transit abuse** | Reputation gate: `MIN_REPUTATION_FOR_TRANSIT=200` | Реализовано |
| **Reputation inflation (поддельный delivery ACK)** | DELIVERED ACK несёт BLAKE3-MAC от `content_id` под per-message E2E-ключом; репутация начисляется только при валидном MAC | Реализовано (C-09) |
| **Cross-algo substitution** | Все подписи верифицируются через `crypto::verify_message(algo, ...)`; algo-байт идёт на проводе | Реализовано |
| **Traffic analysis** | Опциональные `SessionMsg::Padding` кадры выровнены по MTU | Реализовано |

## Криптографические примитивы

| Назначение | Алгоритм | Замечания |
|---------|-----------|-------|
| Identity | Ed25519, Falcon-512 или гибриды Ed25519+Falcon-512/1024 (PQ) | Конфигурируется per-node; `node_id = BLAKE3(pubkey)` |
| Session key exchange | X25519 ephemeral DH | HKDF-SHA256 (salt = `local_id XOR remote_id`, info = `"ovl1-session-v1"`) даёт `tx_key`/`rx_key`/`session_id`; lex-order swap tx/rx ключей даёт обеим сторонам зеркальные назначения |
| Session encryption | ChaCha20-Poly1305 | Per-frame AEAD; 12-байтный counter nonce; rekey при 128 GiB / 32 днях / counter wrap (конфигурируется через `[session] rekey_bytes_threshold` + `rekey_time_threshold_secs`) |
| E2E encryption | ML-KEM-768 encapsulation + ChaCha20-Poly1305 | Маркеры `0xE2` (E2E) / `0xE3` (meta-E2E, скрывает отправителя) |
| Хеширование | BLAKE3 | Node ID, DHT-ключи, PoW, content hashing, HMAC (`keyed`) |
| PoW | `BLAKE3(pubkey ‖ nonce ‖ sign(pubkey, nonce))` с заданным числом ведущих нулевых бит (дефолт 16) | Последовательный; адаптивно растёт к потолку `MAX_POW_DIFFICULTY=24` по мере роста сети |
| Mailbox replica encryption | HKDF(primary_mlkem_dk) + ChaCha20-Poly1305 | Реплики хранят непрозрачные blob'ы |

## Защита ключевого материала

- `PowParams`, `Base64PrivateKey`, `Base64PublicKey`: Debug-вывод редактируется
- `SessionKeys`: кастомный Debug impl с редактированием
- `IdentityConfig`, `MetricsConfig`: Debug-вывод редактируется (C-12)
- Session-ключи деривируются через HKDF-SHA256; tx/rx assignment зеркалится lex-ordering'ом node_id'ов обоих peer'ов
- Переполнение nonce counter'а детектируется, сессия rekey'ится

## Открытые риски

| Риск | Описание | План митигации |
|------|-------------|-----------------|
| Shard filtering bypass | `shard_filtering` — opt-in (default false) | Включить по умолчанию когда сеть > 1M узлов |
| Reputation cold start | Новые узлы стартуют со score 0 → не могут transit'ить сразу | Митигация TBD (peer vouches через `ReputationAttestation` дают некоторое ускорение) |
| Ключевой материал в памяти | Master- и identity-seed'ы mlock'нуты (`SensitiveBytesN`) + `madvise(MADV_DONTDUMP)`; часть session-AEAD-ключей всё ещё в heap | Реализовано (seed'ы); session-ключи в работе |
| Gap в версии протокола | `OVL1_MINOR_VERSION = 1`, но фичи gate'ятся при >=5 | Поднять версию с полным test coverage |
