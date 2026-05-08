# SonicDPI macOS NetworkExtension

Каркас System Extension для голоса Discord (UDP) на macOS.
Покрывает [issue #1](https://github.com/by-sonic/sonicdpi/issues/1).

## Зачем оно

В v0.2 macOS-бэкенд работает на pf `rdr-to` + transparent TCP-proxy.
Это покрывает HTTPS-цели (YouTube TLS, Discord-Cloudflare, Discord-Gateway), но **не голос Discord**, потому что голос идёт по UDP на `*.discord.media:19294-19344, 50000-50100`, а pf `rdr-to` для UDP нам не помогает.

`IPPROTO_DIVERT` Apple вырезала из XNU; `pf divert-to` на Sequoia/Tahoe полу-сломан. Единственный санкционированный Apple путь к per-packet inspect+modify — `NEFilterPacketProvider` внутри System Extension.

## Структура

```
macos-nex/
├── HostApp/                 ← .app, который ставит System Extension
│   ├── HostAppMain.swift    ← OSSystemExtensionRequest + NEFilterManager setup
│   ├── Info.plist
│   └── HostApp.entitlements
├── Extension/               ← .systemextension с NEFilterPacketProvider
│   ├── PacketFilterProvider.swift   ← переадресует пакеты в Rust
│   ├── Info.plist
│   └── Extension.entitlements
└── Makefile                 ← build / sign / notarize

crates/sonicdpi-macos-nex/   ← Rust ядро, скомпилированное в .dylib
├── Cargo.toml
└── src/
    ├── lib.rs
    └── ffi.rs               ← C-ABI: init / process / take_modified / shutdown
```

## Что нужно от вас (Apple-сторона)

Эту часть никакой код заменить не может — Apple привязывает System Extensions к paid Developer Program и ручному review.

1. **Apple Developer Program** — $99/год, [developer.apple.com/programs](https://developer.apple.com/programs).
2. **Запросить entitlement** `com.apple.developer.networking.networkextension` через [developer.apple.com/contact/request/system-extension](https://developer.apple.com/contact/request/system-extension). Apple отвечает обычно 1–2 недели, требуется пояснить use-case (мы — opensource DPI-desync для конкретных хостов).
3. **Developer ID Application** сертификат (через Xcode → Preferences → Accounts → Manage Certificates).
4. **App Group** `group.com.bysonic.sonicdpi` (host app + extension должны быть в одной группе).
5. **Notarization profile**:
   ```bash
   xcrun notarytool store-credentials sonicdpi-notary \
       --apple-id you@example.com --team-id TEAMID --password app-specific-password
   ```

## Сборка

```bash
cd macos-nex/

# 1. Компиляция (unsigned — для локальной проверки структуры)
make build

# 2. Подпись Developer ID
make sign DEVELOPER_ID="Developer ID Application: Имя (TEAMID)"

# 3. Нотаризация (для распространения вне App Store)
make notarize

# 4. Локальная установка
make install
```

После `make install` — открыть **System Settings → Privacy & Security → Security**, кликнуть **«Allow»** рядом с «System extension blocked». Без этого SX не загрузится.

## Что сделано

- ✅ Rust крейт `sonicdpi-macos-nex` с C-ABI (`init / process / take_modified / shutdown`).
- ✅ Swift `NEFilterPacketProvider` подкласс с FFI-вызовами.
- ✅ Host app со SystemExtensionRequest и NEFilterManager.
- ✅ Info.plist + entitlements для обоих bundle.
- ✅ Makefile для cross-compile + bundle + sign + notarize.

## Что pending (нужны живой Apple-аккаунт + железо)

- ⏳ Тестовая сборка под живой Developer ID.
- ⏳ Проверка что SX действительно ловит UDP на `*.discord.media`.
- ⏳ Проверка `discord_voice_prime` на реальном звонке.
- ⏳ Burst-инжекция (когда стратегия эмитит 6+ фейков на 1 входящий пакет — текущий Swift-харнес инжектит только первый, надо переделать на `writePackets([NEPacket]...)` с массивом).
- ⏳ Adaptive packet flow для DISCORD voice handshake (RTP detection хорошо ложится на per-packet API).

## Полезные ссылки

- [Apple — Building a System Extension for Network Filtering](https://developer.apple.com/documentation/networkextension/filtering_network_traffic)
- [Apple — Configuring an NEFilterPacketProvider](https://developer.apple.com/documentation/networkextension/nefilterpacketprovider)
- [WWDC 2019 — Network Extensions for the modern Mac](https://developer.apple.com/videos/play/wwdc2019/714/)
