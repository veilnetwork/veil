# P-Net: приватные оверлей-сети

P-Net (Private Network mode) ограничивает участие в veil только
узлами, у которых есть membership-сертификат, подписанный владельцем
сети. Публичный режим (по умолчанию) принимает любого peer'а; P-Net
отвергает неаутентифицированных peer'ов на gate'е OVL1-рукопожатия.

## Модель доверия

```
Network Owner (Ed25519-ключи в offline-хранилище)
    │  подписывает
    ▼
Membership Cert (на узел; содержит node_id + admin-флаг + valid_until)
    │  предъявляется в HELLO и верифицируется на handshake
    ▼
P-Net Member (допущен в приватную сеть)
```

Две роли участников:

* **Admin** (`admin: true` в cert'е) — может издавать DHT-реплицируемые
  баны, которые распространяются на каждого члена сети. Обычно — на
  bootstrap-узлах.
* **Member** (`admin: false`) — только подключение. Локальные баны
  остаются на хосте (без DHT-репликации).

## Зачем два scope бана

Публичный режим держит баны локальными (анти-DoS — злоумышленник не
может отравить ban-таблицу кластера). Приватный режим доверяет админам
выпускать сетевые баны, потому что admin-cert выдан доверенным
владельцем; это позволяет управлять приватным кластером с любого
admin-узла.

## Настройка оператором

### 1. Сгенерировать ключи владельца (однократно)

```bash
veil-cli network gen-owner \
  --pub-out  /etc/veil/owner.pub \
  --priv-out /etc/veil/owner.priv
```

Держите `owner.priv` **OFFLINE** (USB-токен, шифрованный backup). Кто
угодно с этим ключом может выпускать новые admin-certs.

### 2. Сгенерировать network ID (однократно)

```bash
veil-cli network gen-network-id
# network_id = 948b97b51b...ea87
```

Сохраните 64-символьную hex-строку — каждому участнику нужна в конфиге.

### 3. Подписать cert на каждого участника

```bash
# Admin cert (bootstrap, ops-узлы):
veil-cli network sign-member \
  --owner-pub /etc/veil/owner.pub \
  --owner-priv /etc/veil/owner.priv \
  --network-id "$NETWORK_ID" \
  --member-node-id "$NODE_ID_OF_BOOTSTRAP" \
  --admin \
  --valid-days 365 \
  --out /etc/veil/network.cert

# Member cert (обычный leaf — без `--admin`):
veil-cli network sign-member \
  --owner-pub /etc/veil/owner.pub \
  --owner-priv /etc/veil/owner.priv \
  --network-id "$NETWORK_ID" \
  --member-node-id "$NODE_ID_OF_LEAF" \
  --valid-days 365 \
  --out /etc/veil/network.cert
```

Где взять `node_id`: это `BLAKE3(public_key)` от identity-ключа узла
(поле `public_key` в блоке `[identity]` в `node.toml`). Использовать
`blake3sum` или helper в `build-testnet-configs.py` на контроллере.

### 4. Сконфигурировать узел

Добавить в `node.toml`:

```toml
[network]
mode = "private"
network_id = "948b97b51b...ea87"
owner_pubkey = "<base64 ed25519 owner pubkey>"  # содержимое owner.pub
owner_algo = "ed25519"
membership_cert = "/etc/veil/network.cert"

# Опциональный defense-in-depth — только cert'ы, чей member_node_id
# здесь указан, считаются admin'скими даже если cert.admin = true.
# Пустой список (default) безоговорочно доверяет admin-флагу в cert'е.
admin_node_ids = [
  "<hex node_id доверенного admin 1>",
  "<hex node_id доверенного admin 2>",
]
```

### 5. Перезапустить

Handshake-gate строится при старте runtime. После перезапуска узел
будет требовать cert от входящих peer'ов и сам предъявлять свой cert в
исходящем HELLO.

## Бан с admin-узла

```bash
veil-cli network ban <NODE_ID_HEX> --reason "спам"
```

Идёт через локальный admin IPC-сокет → `AdminCommand::PNetBan` →
подписывает `BanEntry` identity-ключом узла → fan-out на К ближайших
peer'ов через DHT-репликацию → применяется локально. Остальные
участники подбирают бан на следующий тик `p_net_ban_sync` (~60 с).

Проверка на receiver'е:
```bash
veil-cli peers banned
```

## App-layer admission (ogate / oproxy)

Daemon's P-Net gate решает, может ли peer установить OVL1 session
вообще. Приложения поверх daemon — ogate (TUN-bridge), oproxy
(SOCKS5/HTTP-proxy) — могут делегировать свой admission decision
daemon'у вместо поддержания своего static `allowed_node_ids`
списка.

Механизм: каждое приложение запрашивает `LocalAppMsg::PnetStatusQuery`
по своему IPC-сокету и читает кэшированный `MembershipCert` для peer'а
с daemon-стороны. Daemon: cert сохраняется на handshake'е в per-peer
`verified_peer_certs` map и экспортируется через
`PnetStatusProvider`.

### oproxy-server

В `server.toml`:

```toml
pnet_required = true
allowed_node_ids = []   # пусто + pnet_required=true → "доверяй любому cert-verified peer"
allow_all = false        # не нужно когда pnet_required установлен
```

Поведение на входящем stream'е:

1. Source `node_id` проверяется против `allowed_node_ids` (существующий gate).
2. Если `pnet_required = true`, дополнительный `peer_pnet_status(&src)`
   IPC-запрос. Отвергает с `Denied` если `admitted=false` или
   `has_cert=false`.

Daemon RPC failure ⇒ fail-closed (оператор opted in в strict gate;
fallback open противоречил бы смыслу).

### ogate

В `ogate.toml`:

```toml
mode = "authorized"
pnet_required = true

[[peers]]
node_id = "deadbeef..."
addr_v4 = "10.99.0.2"
```

Поведение на startup и SIGHUP reload:

1. ogate подключается к daemon.
2. Итерирует `[[peers]]`; для каждой записи вызывает `peer_pnet_status`.
3. Фильтрует out peer'ов без `has_cert && admitted` (warning на каждое
   удаление).
4. Строит routing table из отфильтрованного списка.

Комбинируй с `mode = "authorized"` для defence-in-depth — peer должен
ОБА иметь verified cert И присутствовать в `[[peers]]` списке.

### Operator flow

```bash
# 1. Daemon в P-Net mode (operator-side, см. секции выше).

# 2. Выпустить cert для peer'а который будет использовать oproxy:
veil-cli network sign-member \
  --owner-pub /etc/veil/owner.pub \
  --owner-priv /etc/veil/owner.priv \
  --network-id "$NETWORK_ID" \
  --member-node-id "$PEER_NODE_ID" \
  --no-expiry \
  --out /etc/veil/peer-cert.bin

# 3. Сторона peer'а: установить cert, перезапустить daemon. Daemon
#    презентует cert в HELLO, daemon b1 верифицирует + кэширует.

# 4. На b1: настроить oproxy-server.toml с pnet_required = true.
sudo oproxy-server --gen-config > /etc/oproxy/server.toml
sudo vim /etc/oproxy/server.toml   # установить pnet_required = true
sudo systemctl restart oproxy-server

# 5. Verify: peer открывает stream → admitted. Случайный non-verified
#    peer → Denied + log entry.
```

## Что отвергается

| Сценарий | Сообщение на handshake'е |
|---|---|
| Узел в public mode подключается к private cluster | `peer did not present а membership cert (network is private)` |
| Cert подписан другим owner'ом (чужая сеть) | `cert verification failed: cert network_id does not match local: expected=... got=...` |
| Cert просрочен | `cert verification failed: cert expired at unix=...` |
| `cert.member_node_id` ≠ authenticated `node_id` peer'а | `cert is не для this peer: cert.member_node_id=... peer_node_id=...` |
| Cert blob битый | `cert blob decode failed: ...` |

## Ansible rollout

В репо есть `ansible/deploy-pnet.yml` (раскатка) и
`ansible/revert-pnet.yml` (откат к public mode). Оба `serial: 1`
rolling — кластер держит quorum во время переключения.

Prerequisites на контроллере:
- `/tmp/pnet/owner.pub` + `/tmp/pnet/owner.priv` + `/tmp/pnet/network_id.hex`
- По одному cert'у на хост в `/tmp/pnet/<cfg-name>.cert` (cfg-name =
  b1/b2/b3 + n1..n5 — см. карту `inv_to_cfg` в `deploy-pnet.yml`).

```bash
# Раскатать:
ansible-playbook -i inventory.yml deploy-pnet.yml

# Откатить (убирает [network] блок + cert, рестартит в public mode):
ansible-playbook -i inventory.yml revert-pnet.yml
```

## Архитектурные заметки

* **Стоимость верификации cert'а**: 1 Ed25519 signature verify (~30 μs
  на современном x86). Handshake gate верифицирует на каждом inbound;
  cert переdecoded'ся на каждом handshake (не кэшируется), поэтому
  изменения admin-allowlist'а вступают в силу немедленно при reload.
* **Latency распространения бана**: ≤60 с (interval apply-задачи). Для
  ускорения можно издать redundant бан с каждого admin-хоста, но
  DHT-fan-out (К=8 ближайших) обычно покрывает кластер за один тик.
* **DHT-ключ**: `BLAKE3(network_id || ":bans:" || banned_node_id)`.
  Receiver'ы верифицируют подпись бана **и** что ключ соответствует —
  это предотвращает misfiling бана под чужой ключ.

## Связанный код

* `crates/veil-identity/src/network_cert.rs` — codec + verifier
  cert'а
* `crates/veil-identity/src/network_ban.rs` — codec `BanEntry` +
  chain-of-trust verifier + DHT-ключ
* `crates/veil-identity/src/network_access.rs` — `NetworkAccessGate`
  (обёртка вокруг handshake-time verifier'а)
* `crates/veil-node-runtime/src/runtime/p_net_ban_sync.rs` —
  `publish_p_net_ban` + периодическая apply-задача
* `crates/veil-cli/src/cmd/network_cmd.rs` — handler'ы подкоманд
  `veil-cli network …`

## Ограничения / открытая работа

* **Нет revocation list**: скомпрометированный admin cert остаётся
  валидным до `valid_until_unix`. Ротация admin-cert'ов через
  re-issue с новым admin keypair'ом и redistribution.
* **Компрометация owner-ключа — катастрофична**: кто угодно с
  owner-privkey может выпускать admin-cert'ы, которые проходят gate
  везде. Обращаться как с root-CA ключом — air-gap, HSM или paper
  backup.
* **Cross-network connectivity**: admin сети A не может построить
  мост к сети B. Каждая сеть — отдельный disjoint trust-домен.
