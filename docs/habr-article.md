# Как я починил себе YouTube и Discord на Windows, Linux и macOS — свой DPI-desync на Rust и история про 89 неудачных конфигов

> **TL;DR:** взял идеи из открытого DPI-инструментария (zapret, GoodbyeDPI, byedpi), выкинул C, переписал на Rust как один кросс-платформенный workspace под Windows + Linux + macOS, и в процессе обнаружил, что мой собственный «дефолтный» профиль не пробивает мой собственный провайдер. Пришлось писать sweep-харнес который перебирает 89 комбинаций (decoy × fooling × repeats × strategy) и тыкается curl-ом в discord.com и youtube.com. Один-единственный конфиг сработал. И это был не тот, который я закладывал по памяти из мануалов.

---

## Предыстория

В январе у меня был `UnblockPro` — гибрид GoodbyeDPI и собственного шаперона, под Windows. Работало. Потом я портировал его на macOS — отдельный проект, отдельный код, отдельный набор багов. Когда захотел Linux, понял, что повторять третий раз пайплайн «парс TLS — modify — emit» это уже самонаказание.

Решил собрать всё заново. Один Rust-workspace, четыре крейта:

```
crates/
├── sonicdpi-engine/     ← платформенно-независимый "мозг"
├── sonicdpi-platform/   ← перехват пакетов на каждой ОС
├── sonicdpi-cli/        ← бинарь sonicdpi
└── sonicdpi-tray/       ← бинарь с системным треем
```

Правило: `engine` ничего не знает про WinDivert / NFQUEUE / pf, `platform` ничего не знает про стратегии. Если в `engine` появляется `cfg(target_os = ...)` — я не туда что-то засунул.

Перехват:

| ОС | Backend | Особенности |
|---|---|---|
| Windows | WinDivert 2.2.2 (vendored, EV-signed) | Требует админ; WinDivert.dll рядом с .exe |
| Linux | NFQUEUE через чистый Rust `nfq` (не GPL `libnetfilter_queue`) | `cap_net_admin` + nftables |
| macOS | pf `rdr-to` + transparent TCP-proxy | Только TCP в v0.2 — `IPPROTO_DIVERT` Apple вырезала из XNU, голос Discord на Mac пока не идёт |

Лицензионная заметка к слову: WinDivert — LGPL-3, остальное у меня MIT/Apache-2. Динамическая линковка через DLL держит остальной код permissive. cargo-deny на это пушит палец, но этот договорняк описан в `THIRD_PARTY_LICENSES.md`.

## Стратегии — что в итоге

Открытый DPI-инструментарий описывает примерно десять разных техник десинка пакетов. Я прошёл по их каталогу и реализовал пять:

- **`tls-multisplit`** — режу ClientHello на куски с seqovl-перекрытием и пихаю в overlay-регион байты «безопасного» SNI вроде `4pda.to`. DPI пересобирает first-write-wins, видит безопасный байт-шаблон и не палит реальный SNI.
- **`fake-multidisorder`** — N штук фейковых ClientHello уходят впереди настоящего, с TCP-fooling (TS=1 для PAWS, MD5SIG, или badseq). DPI коммитится на фейковый SNI, реальный CH идёт следом и проходит.
- **`hostfakesplit`** — переименовываю SNI в первом сегменте на `www.google.com`, реальный пакет улетает следом.
- **`quic-fake-initial`** — то же самое для YouTube QUIC: бёрст фейковых Initial с SNI=google перед настоящим.
- **`discord-voice-prime`** — UDP-фейки в форме STUN / Discord-RTP перед настоящим голосом, чтобы классификатор не успел навесить ярлык.

В коде каждая стратегия — это `impl Strategy { fn apply(...) -> Option<Action> }`, и они складываются в `StrategyPipeline`. Профиль (TOML) описывает, какие из них подключать и с какими параметрами.

Дефолтный профиль я взял по памяти — «zapret ALT9 же, decoy `ozon.ru`, fooling `ts`, repeats 4, всё работает». Закоммитил, собрал, поставил, запустил.

## И тут Discord перестал открываться

Точнее — TCP-коннект до `gateway.discord.gg:443` идёт, а TLS handshake умирает в таймаут. Curl даёт честный `code=000 time=5.0s`. YouTube — работает. Discord — нет.

Ладно. Открыл лог. Стратегии fire-ятся. Декои улетают. Пакетов до Cloudflare-узла Discord приходит «достаточно». А handshake всё равно дохнет.

Полез в проблему по своему же diag-скрипту:

```powershell
.\diag.ps1
```

(он у меня лежит в репе — `diag.ps1`, делает DNS-чек, tracert, запускает энжин в фоне, curl-ит несколько хостов, парсит лог. Когда что-то ломается — первая остановка.)

Результат:

```
PHASE 0 — engine OFF baseline
  discord.com:        000 (4.0s)
  gateway.discord.gg: 000 (4.0s)
  www.youtube.com:    000 (4.0s)

HTTPS PROBE WHILE ENGINE RUNNING
  https://discord.com/api/v9/gateway          code=000 time=5.0s   ← все ещё мертво
  https://gateway.discord.gg/                 code=000 time=5.0s
  https://dl.discordapp.net/...               (висит, тянется до timeout)
```

То есть ни мой default, ни три ALT-профиля, ни даже встроенный `sonicdpi probe` (у меня есть subcommand, прогоняет все билтины) — ничего не отрабатывает. Всё `LOSS read`.

```
probing gateway.discord.gg:443 with 5 profile(s)
  youtube-discord                LOSS read
  youtube-discord-aggressive     LOSS read
  youtube-discord-multidisorder  LOSS read
  youtube-discord-seqovl         LOSS read
  youtube-discord-hostfakesplit  LOSS read
```

Красивая такая колонка из пяти неудач.

## А вот сейчас интересно

Посыпался когнитивный диссонанс. У меня в `C:\Users\Sonic\Desktop\2\` лежит фолдер с конфигами zapret/Flowseal — `general (ALT9).bat`, его я конкретно использовал и в этот момент он у меня работает. Но мой код, который **по памяти** реализует тот же ALT9, не работает.

Начал ставить точки по логу.

Что я закоммитил в дефолтный профиль:

```rust
host_fake_split: vec![
    HostFakeSplitCfg {
        fake_host: "www.google.com",
        targets: [YouTube, DiscordGateway],
        repeats: 4,
        fooling: "ts",
    },
    HostFakeSplitCfg {
        fake_host: "ozon.ru",
        targets: [DiscordCloudflare],
        repeats: 4,
        fooling: "ts,md5sig",
    },
],
```

Лог говорит — `flow classified by SNI/QUIC/RTP target=DiscordCloudflare`. Класификатор работает. А вот fire-ов `hostfakesplit` нет. Совсем. Стратегия не срабатывает.

Открываю `apply()` в `HostFakeSplit`:

```rust
fn apply(&self, pkt: &mut Packet, flow: &mut Flow) -> Option<Action> {
    if flow.hello_seen || pkt.proto != L4Proto::Tcp { return None; }
    if !is_client_hello(pkt.payload()) { return None; }
    // ...
    let renamed = rewrite_sni_same_length(payload, &self.fake_host)?;
    //                                    ^^^^^^^^^^^^^^^^^^^^^^^
```

И вот оно. `rewrite_sni_same_length` — функция `Option<Vec<u8>>`, требует чтобы новый SNI был **той же длины**, что и оригинальный. `discord.com` это 11 байт. `ozon.ru` это 7 байт. Mismatch → `None` → стратегия молча возвращает `None`, `flow.hello_seen` остаётся `false`, никаких декоев не уходит, реальный CH идёт DPI-узлу провайдера без фольги.

Пять минут разглядывания собственного коммита, и я понял, что моя реализация hostfakesplit вообще не делает то, что я думал. Канонический подход эмитит **N штук самодостаточных** фейковых ClientHello (с разной TLS-структурой, со своим SNI, своей длиной), а у меня попытка переписать оригинал поверх существующего payload-а с теми же длинами.

Перепишу. Сделал чтобы стратегия принимала готовый `fake_payload: Vec<u8>` (через `embedded_or_synth_ch(fake_host)`), а не пыталась мутировать оригинал. Длины разные? Похуй, мы вообще не зависим от длины оригинала.

## После фикса — снова всё ломается

Соник, что ты сделал? Запускаю `probe` повторно — те же `LOSS read` на всех пяти профилях. Что-то более глубокое.

Тут я понял, что догадки кончились. Память про «ALT9 = ts fooling, ozon decoy, repeats 4» — это снимок состояния на октябрь. На календаре май. DPI-логика провайдеров за это время патчится много раз. И эмпирика — единственный способ узнать, какая комбинация **сейчас** работает на **моём провайдере**.

Написал `sweep.ps1`. Логика прямая:

1. Дампим базовый профиль для секции `[targets]`.
2. Генерим N TOML-файлов, каждый — отдельная комбинация.
3. Для каждого: глушим старый engine, стартуем новый с этим TOML, спим 2 секунды (WinDivert поднимается), curl-им четыре хоста, ловим http_code и time, глушим engine.
4. Финал — таблица «config X / N out of M успешных curl-ов / средний RTT».

Матрица:

```
host_fake_split   × {ozon.ru, vk.me, max.ru, www.google.com, 4pda.to, dzen.ru}
                  × {ts, md5sig, ts+md5sig, badseq, ttl=4}
                  × {repeats=4, repeats=6}
fake_multisplit   × 4 декоя × 3 fooling-а × repeats=4
fake_multidisorder× 4 декоя × 3 fooling-а × repeats=4
tls_multisplit    × 4 варианта seqovl/decoy
default-current   × 1
─────────────────────────────────────
                                                              = 89 конфигов
```

89 × (engine spawn 2s + 4 curl-а × ~1s + остановка) ≈ 27 минут.

Запустил. Пошёл сделать чай.

## Вывод

Когда вернулся:

```
[ 75/89] fmd_ozon.ru_ts_md5sig_r4         0/4   ╳
[ 76/89] fmd_ozon.ru_badseq_r4            4/4   ✓✓✓✓
[ 77/89] fmd_vk.me_ts_r4                  0/4   ╳
[ 78/89] fmd_vk.me_ts_md5sig_r4           0/4   ╳
[ 79/89] fmd_vk.me_badseq_r4              4/4   ✓✓✓✓
[ 80/89] fmd_max.ru_ts_r4                 0/4   ╳
[ 81/89] fmd_max.ru_ts_md5sig_r4          0/4   ╳
[ 82/89] fmd_max.ru_badseq_r4             4/4   ✓✓✓✓
[ 83/89] fmd_4pda.to_ts_r4                0/4   ╳
[ 84/89] fmd_4pda.to_ts_md5sig_r4         0/4   ╳
[ 85/89] fmd_4pda.to_badseq_r4            4/4   ✓✓✓✓
```

Из 89 конфигов **четыре** дали 4/4. И все четыре — это `fake_multidisorder` с `fooling = "badseq"`. Декой не важен (любой подходил), repeats=4, всё.

Ни один `host_fake_split` не зашёл. Ни один `tls_multisplit`. Ни один `fake_multisplit`. И — внимание — `fake_multidisorder` с fooling `ts` или `ts,md5sig` (то, что считалось каноном пол-года назад) тоже **не работает**. Только `badseq`.

Победный конфиг:

```toml
[strategies.fake_multidisorder]
fooling = "badseq"
repeats = 4
decoy_host = "ozon.ru"

[strategies.quic_fake_initial]
repeats = 6
decoy_host = "www.google.com"
```

```
=== TOP 15 ===
fmd_ozon.ru_badseq_r4     4/4   discord=200/0.08s | gateway=404/0.22s | dl=301/0.06s | www=200/0.28s
fmd_4pda.to_badseq_r4     4/4   ...
fmd_max.ru_badseq_r4      4/4   ...
fmd_vk.me_badseq_r4       4/4   ...
hfs_dzen.ru_badseq_r4     0/4
fms_max.ru_ttl_4_r4       0/4
... (84 нуля)
```

## Почему именно `badseq`

Объяснение, которое я в результате склеил: DPI-узел на моём провайдере (за последний апдейт?) перестал дропать декои, у которых TCP-options содержат TSval=1 (это PAWS-trigger — нормальный TCP-стек обязан их отбрасывать как «вне-таймстамповые»). Раньше PAWS делал работу за тебя: декой долетал до сервера, сервер его молча выкидывал на L4, всё чисто. Сейчас декой долетает, проходит TCP, попадает в TLS-стек **сервера**, сервер шлёт TLS Alert / RST на разрыв, и **этот RST убивает реальный коннект** — потому что для DPI и для нашего ядра это пакеты от того же 5-tuple.

`badseq` — это TCP seq «вне окна». Для **сервера** такой пакет невидим (он его дропает на L4 как retransmit или garbage), но **для DPI** — это всё ещё TLS-byteshape с правильным SNI. То есть DPI его коммитит как «начало флоу к ozon.ru», а сервер его не видит и не отвечает на него ничем. Реальный CH летит за ним нетронутый.

Проще говоря: PAWS-фольга больше не fire-and-forget. `badseq` — fire-and-forget.

Я это записал себе в заметки (рецепт сегодня работает, а через две недели может развалиться). Если кто-то читает это в августе, и `badseq` уже не вывозит — sweep.ps1 в репе, прогон 25 минут, найдёт следующее.

## Что в итоге получилось

[github.com/by-sonic/sonicdpi](https://github.com/by-sonic/sonicdpi)

Готовые сборки на каждую ОС в [Releases](https://github.com/by-sonic/sonicdpi/releases/latest):

- `SonicDPI-windows-x64.zip` — внутри `sonicdpi-tray.exe` (двойной клик → UAC → значок в трее)
- `SonicDPI-linux-x64.tar.gz` / `arm64`
- `SonicDPI-macos-x64.tar.gz` / `arm64` (Apple Silicon)

CI собирает всё через GitHub Actions, fmt + clippy + test зелёные на всех трёх ОС. Для тех, кто хочет поковырять — там же `sweep.ps1` (мой харнес) и `diag.ps1` (быстрая диагностика «у меня сломалось»). И, что мне приятно — `sonicdpi probe -H gateway.discord.gg -t 5` прогоняет все профили против хоста и печатает Wilson-ranking, можно дёргать без полного запуска.

Ещё один тулинг-кусок: на Windows `sonicdpi.exe install --profile youtube-discord` ставит как службу (через winsvc), Linux — генерит systemd unit, macOS — launchd plist. Установил один раз, забыл.

## Что дальше

- v0.3 — macOS NetworkExtension System Extension для голоса Discord (TCP уже работает, голос — нет).
- v0.4 — adaptive probing harness внутри самого engine: рота­ция профилей при просадке.
- v0.5 — нормальный Tauri-GUI. Сейчас UI — это только тей. Полноценное окно для не-CLI-пользователей.

Если кто-то хочет помочь — issues и PR-ы открыты. Особенно интересны полевые данные: какой провайдер, какой регион, какой профиль зашёл. У меня нет инфраструктуры чтобы тестить со ста разных ISP, и ваш `sweep.ps1`-вывод — это золото.

И последнее: если у вас «у меня sonicdpi не работает» — `diag.ps1` в корне репо, прогон 30 секунд, кидайте вывод в issue. Это сильно сокращает мне дорогу до фикса.

---

Ссылки:
- репо: [github.com/by-sonic/sonicdpi](https://github.com/by-sonic/sonicdpi)
- релизы: [/releases/latest](https://github.com/by-sonic/sonicdpi/releases/latest)
- мои предыдущие посты: [habr.com/ru/users/by-sonic](https://habr.com/ru/users/by-sonic/articles/)
