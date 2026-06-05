# Contributing

## Сборка

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
```

## Code Style

- Никаких `unwrap()` на user-controlled или сетевых данных в production-коде (использовать `?` или `match`)
- Макрос `lock!(mutex)` вместо `.lock().unwrap()` для Mutex
- Типы key material: `Debug` обязан редактировать секреты (см. `crypto/types.rs`)
- Новые поля в `FrameDispatcher`: добавлять в `make_test_dispatcher()` и `make_gossip_dispatcher()`

## Тестирование

- Unit-тесты: `#[cfg(test)] mod tests` в каждом модуле
- Интеграционные тесты: тесты `node/runtime.rs` с реальным TCP
- Simulator-тесты: модуль `sim/` с `SimNetwork`
- Сложность PoW — 16 бит в `#[cfg(test)]` (быстро, см. `identity_policy.rs`)

## Формат коммита

```
краткое описание изменения

Подробности изменений.

Co-Authored-By: ...
```

## Архитектурные решения

- **Никакого async в dispatcher'е**: `dispatch()` синхронный — сразу возвращает `DispatchResult`
- **Single-lock convention**: никогда не держать два `Mutex`-lock'а одновременно
- **Forward compatibility**: неизвестные frame families → `NotHandled` (не `Violation`)
- **TLV extension**: новые поля payload'а — как опциональный TLV-suffix (существующие узлы игнорируют неизвестные tag'и)
