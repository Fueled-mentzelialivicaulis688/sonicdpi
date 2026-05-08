# SonicDPI — диагностика «у меня не работает»

Это runbook для того момента, когда engine скомпилирован, запускается, но
YouTube или Discord всё равно не подключаются. Каждый блок — отдельный тест,
который дает однозначный ответ на одну гипотезу. Разделы идут от **самой
дешёвой и частой причины** (DNS) до **самой глубокой** (нужна доработка
engine).

Автоматизация: `scripts\diag.bat` (cmd) или `scripts\diag.ps1` (admin
PowerShell) прогоняет все блоки разом, складывает артефакты в
`diag-out\<timestamp>\`. Идеально для запуска через VS Code / AI-ассистента —
весь output в одной папке, его можно загрузить в чат и попросить разобрать.

---

## 0. Что должно быть установлено

| тулза            | проверка                                  | если нет                                     |
|------------------|-------------------------------------------|----------------------------------------------|
| Rust 1.78+       | `cargo --version`                         | rustup от https://rustup.rs                  |
| Admin shell      | New-Object Security.Principal.…IsInRole   | запусти PowerShell/cmd «как администратор»    |
| WinDivert.dll    | `dist\WinDivert.dll` существует           | пересобрать — build script положит автоматом |
| curl.exe         | `where curl` (есть в Win10+)              | поставь curl или возьми из Git for Windows   |
| nslookup         | `where nslookup` (есть в Win)             | стандартный, должен быть                     |

Опционально (для глубокой диагностики):
- **Wireshark** — https://www.wireshark.org/download.html. Поставит Npcap,
  даст pcap. Без него обходимся `pktmon` (см. ниже).
- **tracert** — встроен.

---

## 1. Сборка и smoke-test

Должно проходить чисто на любой Win10/11 с Rust 1.78+.

```cmd
cargo clean -p sonicdpi-engine
cargo build --release --workspace
cargo test --workspace --lib
```

**Что должно быть**: 6/6 unit-тестов passed, ноль warnings, build OK на
~30-60 секунд.

**Если падает компиляция**:
- `error: linker link.exe not found` → ставь Visual Studio Build Tools
  (workload «Desktop development with C++») или подними existing VS до
  актуальной.
- `error: failed to remove file ... target\release\sonicdpi.exe` →
  старый `sonicdpi.exe` или `sonicdpi-tray.exe` запущены, прибей через
  `taskkill /F /IM sonicdpi.exe /IM sonicdpi-tray.exe`.

После build перекинь свежие бинари в `dist\` (где tray ищет engine):

```cmd
copy /Y target\release\sonicdpi.exe       dist\sonicdpi.exe
copy /Y target\release\sonicdpi-tray.exe  dist\sonicdpi-tray.exe
```

`scripts\diag.ps1` делает это автоматически.

---

## 2. DNS resolution — самая частая первопричина

Если провайдер отравляет DNS для blacklist-доменов, твой клиент никуда не
коннектится **до** того как WinDivert хоть что-то увидит. Никакие seqovl /
fake / TTL не помогут — пакетов нет.

```cmd
nslookup discord.com
nslookup gateway.discord.gg
nslookup discord.com 1.1.1.1
nslookup gateway.discord.gg 1.1.1.1
```

**Расшифровка**:

| локально              | через 1.1.1.1         | вердикт                                       |
|-----------------------|-----------------------|-----------------------------------------------|
| ip типа 162.159.x.x   | ip типа 162.159.x.x   | DNS чист, иди дальше — это не DNS             |
| `0.0.0.0` / NXDOMAIN  | ip типа 162.159.x.x   | **DNS-poisoning от провайдера**               |
| NXDOMAIN              | NXDOMAIN              | реально нет DNS-записи (или сеть не работает) |

**Фикс DNS-poisoning** (нужны admin):

```cmd
:: посмотри как у тебя называется интерфейс
netsh interface show interface

:: подставь название (часто "Ethernet" или "Wi-Fi")
netsh interface ip set dns "Ethernet" static 1.1.1.1
netsh interface ip add dns "Ethernet" 1.0.0.1 index=2
ipconfig /flushdns
```

После этого повтори nslookup — должны идти 1.1.1.1 ответы.

Альтернатива — DNS-over-HTTPS в самом Windows (Settings → Network → Edit DNS,
выбери Encrypted only). На Win10 нужно ≥ 21H2.

---

## 3. Маршрут до сервера — жив ли он вообще

```cmd
tracert -d 162.159.137.232
```

**Что искать**:
- 5-12 хопов, RTT < 100ms, без `* * *` → роут OK, проблема выше (TLS/DPI).
- Оборвался на 2-5 хопе и дальше `* * *` → провайдер блокирует **IP**
  (RKN-blacklist). Никакой DPI engine не поможет — нужна альтернативная
  маршрутизация (Cloudflare WARP, VPS, прокси).
- 30 хопов и выходит за RU-ASN → нормально, длинный route, но вернулся
  значит сеть работает.

**Геометрия для TTL fooling**:

Хопы, которые в RU-ASN — это потенциальные позиции TSPU. Обычно TSPU стоит
на 2-3 хопе у крупных ISP (Ростелеком, ER-Telecom, Билайн). TTL fake =
**хоп после TSPU, но до сервера**. Для классических 7-хоп маршрутов TSPU
≈ 3, выход из RU ≈ 4, edge сервиса ≈ 6-7 → **TTL=4** идеально.

Если у тебя другая геометрия:

| хопов до edge | TTL fake | где умирает фейк             |
|---------------|----------|------------------------------|
| 4             | 2        | сразу после TSPU             |
| 5-6           | 3        | в зарубежной транзитной сети |
| 7-8 (типично) | 4        | как раз между TSPU и edge    |
| 9-12          | 5-6      | дальше, но до edge           |

Меняй TTL в `crates/sonicdpi-engine/src/profile.rs`:
`fake_multisplit[].fooling = "ttl=N"`. Или в TOML-профиле через
`sonicdpi show youtube-discord -o my.toml`, правишь, запускаешь
`sonicdpi run --profile my.toml`.

---

## 4. Probe — что он показывает (и что НЕТ)

```cmd
dist\sonicdpi.exe probe -H discord.com --profiles youtube-discord
dist\sonicdpi.exe probe -H gateway.discord.gg --profiles youtube-discord
```

**Важно**: probe ходит через **userspace transparent-proxy**, не через
WinDivert. Он показывает **базовое поведение сети** для конкретного
SNI/IP, БЕЗ DPI bypass. Полезен для:

- Подтверждения что без обхода действительно режется (`LOSS read`).
- Получения timing handshake'а как baseline.
- Сравнения нескольких профилей **в proxy-mode** (на macOS — рабочий путь,
  на Win — диагностика).

**НЕ полезен для**: проверки работает ли наш fake/split на реальном
DPI. Probe не задействует engine на уровне пакетов. Лог `engine.log`
во время probe **не покажет** строк `flow classified target=DiscordCloudflare`.

Расшифровка результатов probe:

| результат            | смысл                                                   |
|----------------------|--------------------------------------------------------|
| `connect` < 1s, OK   | TCP до сервера проходит, TLS handshake работает        |
| `LOSS connect`       | TCP не устанавливается — RST/IP-блок/firewall          |
| `LOSS read`          | TCP установился, TLS ClientHello отправлен, ответа нет |
|                      | → SNI-блок на TSPU или CF-side RST после ClientHello   |
| `LOSS Этот хост…`    | DNS не резолвится → раздел 2                            |

`LOSS read` на discord-доменах — это нормальный дефолт твоей сети. Это не
говорит «engine сломан», это говорит «сеть без обхода блокирует».

---

## 5. Реальный трафик — engine + curl

Запусти engine в одном окне, в другом — curl. WinDivert ловит curl-пакеты,
engine применяет стратегии. Это **рабочий тест**.

**Окно 1 (Admin)**:

```cmd
dist\sonicdpi.exe run -vv --log-file run.log --profile youtube-discord
```

— оставь висеть, не закрывай.

**Окно 2 (любое)**:

```cmd
:: должно быть http=200 если engine пробивает
curl -s -o NUL -w "http=%%{http_code} time=%%{time_total}s\n" --max-time 12 https://discord.com/api/v10/gateway
curl -s -o NUL -w "http=%%{http_code} time=%%{time_total}s\n" --max-time 12 https://gateway.discord.gg/
curl -s -o NUL -w "http=%%{http_code} time=%%{time_total}s\n" --max-time 12 https://www.youtube.com/
```

**Расшифровка**:

| вывод                    | смысл                                                         |
|--------------------------|---------------------------------------------------------------|
| `http=200 time=0.5s`     | engine пробил, всё ок                                         |
| `http=000 time=12.0s`    | timeout — handshake режется молча, фейк не маскирует SNI      |
| `http=000 time=2.1s`     | TCP RST в районе TLS handshake                                |
| `connect=0 time=0.05s`   | DNS-фейл — resolve не прошёл (раздел 2)                       |

Параллельно смотри `run.log`. Должно быть видно как минимум:

```
flow classified by SNI/QUIC/RTP target=DiscordCloudflare dst=162.159.x.x
strategy fired strategy="fake-multisplit" target=Some(DiscordCloudflare)
emit strategy="fake-multisplit" seg=0 len=177 ttl=Some(4) hex=45 00 00 b1 ...
```

Если строк **нет** при попытке curl на discord.com:
- engine не классифицирует поток. Проверь что DNS отдал ip из 162.159.x.x.
- если ip какой-то RU-локальный (DNS poisoned) — engine не классифицирует
  его как DiscordCloudflare (по DNS-cache target определяется), стратегия
  не сработает. См. раздел 2.

Если строки есть, fake emitted с TTL=Some(4), а curl всё равно умер →
TSPU умнее наших фейков (раздел 7).

---

## 6. Tray vs прямой запуск

Tray spawn-ит `sonicdpi.exe` из своей же папки (`dist\`). Если ты собрал
свежий бинарь в `target\release\` но не скопировал в `dist\`, tray
запустит **старую версию**.

Проверка дат:

```cmd
dir target\release\sonicdpi.exe
dir dist\sonicdpi.exe
```

Если `dist` старее — обнови через `copy /Y` (или просто прогони
`scripts\diag.ps1` — он копирует автоматом).

В логе ищи строку с PID и временем запуска:
`engine child spawned pid=NNNN profile=youtube-discord` — это от tray, и
сразу после неё должен быть `WinDivert::network() returned OK`.

---

## 7. TSPU stateful — engine emit-ит, curl всё равно умер

Если в `run.log` строки `strategy="fake-multisplit"` есть, fake-пакеты с
`ttl=Some(4)` эмитятся, а curl на discord.com висит timeout — TSPU у твоего
ISP **stateful** и переклассифицирует поток на каждом ClientHello, не
залипая на первом.

Что попробовать **без правки кода** (через TOML-профиль):

```cmd
dist\sonicdpi.exe show youtube-discord -o tune.toml
```

В `tune.toml` найди секцию `[[strategies.fake_multisplit]]` и кручи:

| параметр       | пробуй                              | смысл                                          |
|----------------|-------------------------------------|------------------------------------------------|
| `fooling`      | `ttl=2`, `ttl=3`, `ttl=6`, `ttl=8`  | подбор геометрии под trace                     |
| `decoy_host`   | `vk.me`, `max.ru`, `mail.ru`,       | какой RU-домен реально в whitelist твоего TSPU |
|                | `ozon.ru`, `4pda.to`                |                                                |
| `repeats`      | `1`, `2`, `4`, `6`                  | мало → TSPU не успевает захватить;             |
|                |                                     | много → CF rate-limit                          |

Запуск:

```cmd
dist\sonicdpi.exe run --profile tune.toml -vv --log-file tune.log
```

Если **никакая комбинация** не пробивает — нужны engine-фичи которых пока
нет (см. `docs/2026-05-status.md`):

1. `fake-tls-mod=rnd,dupsid` — мутация **реального** ClientHello (не
   только fake'а). Прячет SNI=discord.com от классификатора, который
   reassembl-ит поток.
2. `tls_multidisorder` для real-CH с per-target gating — out-of-order
   эмиссия настоящих сегментов, без fake.

Эти две — главные кандидаты для v0.3.

**Рабочий fallback пока v0.3 не подъехал**: Cloudflare WARP
(https://1.1.1.1/). Туннелирует через IP вне SNI-блока. Не наша задача
это починить — но как stop-gap для пользователя — пять минут.

---

## 8. Wireshark capture (опционально, точный диагноз)

Когда нужно понять **кто именно режет** — TSPU или CF, и в какой момент,
ставь Wireshark + Npcap. Capture filter:

```
host 162.159.137.232 and tcp.port == 443
```

Запусти Wireshark, открой Discord, дай ему упасть, останови захват.
Ищи в потоке:

| что видно                                | кто виноват                              |
|------------------------------------------|------------------------------------------|
| `RST` от 162.159.x.x с TTL=58/115/250    | CF (нормальная TTL цепочка от CF backbone)|
| `RST` от 162.159.x.x с TTL=64/128/255    | **TSPU инжектит RST** под видом сервера. |
|                                          | Сравни TTL с легит-ответом от того же IP |
| Никаких RST, только timeout              | silent drop где-то посередине            |
| RST от 192.168.0.1 / 109.172.x.x (твой   | домашний роутер или провайдерский edge — |
| ISP)                                     | прямая блокировка                        |

Без Wireshark — `pktmon` (встроен в Win10/11):

```powershell
pktmon filter remove
pktmon filter add -i 162.159.137.232 -t TCP
pktmon start --etw -p 0 -m real-time
:: ← в этот момент попробуй curl/Discord
:: ← Ctrl+C когда завершишь
pktmon stop
```

`pktmon format` распарсит trace в человекочитаемый вид.

---

## 9. Куда смотреть когда «движок работает но Discord client не открывается»

Если curl `https://discord.com` через engine отдаёт `http=200` (наш
обход прошёл!), а Discord-клиент при этом всё равно висит «Connecting…»:

- **Discord cache**: закрой Discord, удали `%AppData%\discord\Cache`,
  `%AppData%\discord\Code Cache`, открой заново.
- **Hosts файл**: проверь `%SystemRoot%\System32\drivers\etc\hosts` — нет
  ли там захардкоженных `discord.com 0.0.0.0` от старых антизапрет-скриптов.
- **Windows firewall**: ничего не должно резать `Discord.exe`. Settings
  → Privacy & security → Windows Security → Firewall & network → Allow
  an app.
- **Discord-клиент использует QUIC/UDP** для voice — наш engine ловит
  19294-19344 + 50000-50032. Если у тебя голос/видео-вызов не работает а
  чат работает — проверь что в `run.log` есть `strategy="discord-voice-prime"`
  записи во время вызова.

---

## 10. Когда что-то совсем сломалось

Соберите всё что есть и ко мне в чат:

```cmd
scripts\diag.bat
:: ↑ создаст diag-out\<timestamp>\, в нём:
::   sanity.txt          — версии тулчейна
::   build.log           — лог cargo build (если был запуск)
::   cargo-test.log      — unit-тесты
::   dns.txt             — nslookup'ы
::   tracert.txt         — маршрут
::   probe.txt           — userspace probe
::   curl.txt            — реальный трафик через engine
::   engine.log          — полный лог engine
::   engine-summary.txt  — сводка по log'у (что firing-овалось)
```

Папка `diag-out\<timestamp>\` весит обычно <5 MB и всё что нужно для
разбора там есть.
