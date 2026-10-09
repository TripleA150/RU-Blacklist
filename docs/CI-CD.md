# Устройство репозитория и CI/CD

## Структура

```
config/          что вы правите руками
  black-names.txt      паттерны имён, по которым ASN и сети попадают в блок-лист
  white-names.txt      паттерны-исключения
  gov-netnames.txt     netname'ы гос. сетей (whois)
  custom-blacklist.txt свои ASN и префиксы
  allowlist.txt        префиксы, которые никогда не блокируются
  vk-names.txt         паттерны для VK-списков
  vk-exclude.txt       исключения для VK-списков
data/            данные RIPE, обновляются автоматически (scripts/refresh-ripe-data.sh)
output/          готовые списки, обновляются автоматически (scripts/build.sh)
  txt/                 blacklist.txt, blacklist-v4/v6.txt, blacklist-vk*.txt, blacklist_with_comments.txt
  nftables/            .nft-файлы (перезагружаются атомарно)
  ipset/               .ipset-файлы для iptables (перезагружаются атомарно)
  routes/              маршруты VK-сетей в loopback
ru_blacklist/    Python-код (запуск: python3 -m ru_blacklist.<модуль>)
scripts/         build.sh, refresh-ripe-data.sh, lib.sh, install-deps.sh
deploy/          автообновление на сервере (systemd timer), см. deploy/README.md
tests/           pytest + интеграционный тест деплоя
docs/            эта документация
```

Ссылки для скачивания: `https://raw.githubusercontent.com/TripleA150/RU-Blacklist/main/output/<папка>/<файл>`,
например `.../main/output/txt/blacklist.txt` или `.../main/output/nftables/blacklist.nft`.

## Как всё обновляется

```
 воскресенье 01:23 UTC                     ежедневно 03:17 UTC                     сервер, каждые 6 ч
┌──────────────────────┐   workflow_call   ┌──────────────────────────┐  raw    ┌─────────────────────────┐
│ refresh-ripe-data    │ ────────────────▶ │ update-blacklists        │ ──────▶ │ ru-blacklist-update     │
│ RIPEstat + дампы RIPE│                   │ сборка → проверки → push │  GitHub │ (systemd timer, pull)   │
│ → data/              │                   │ → output/                │         │ → nftables / ipset      │
└──────────────────────┘                   └──────────────────────────┘         └─────────────────────────┘
                     ci.yml: каждый push и PR — линтеры, тесты, загрузка файлов в nft/ipset, e2e деплоя
```

| Workflow | Когда | Что делает |
|---|---|---|
| `ci.yml` | каждый push в `main`, каждый PR, вручную | ruff, pytest (Python 3.10 и 3.13), shellcheck, actionlint. Запускает `scripts/build.sh --offline`, загружает `.nft`/`.ipset` в nftables и ipset в отдельном network namespace и прогоняет серверный скрипт деплоя end-to-end (оба бэкенда). |
| `update-blacklists.yml` | ежедневно в 03:17 UTC (10:17 по UTC+7), вручную, после `refresh-ripe-data` | `scripts/build.sh` (RIPEstat + whois), те же проверки, что в `ci.yml`, сравнение с опубликованной версией, коммит изменений в `main`. |
| `refresh-ripe-data.yml` | по воскресеньям в 01:23 UTC, вручную | `scripts/refresh-ripe-data.sh`: список RU-ресурсов из RIPEstat, дампы RIPE DB (`aut-num`, `inetnum`, `inet6num`, `organisation`), офлайн-резолв имён ASN и сетей → `data/`, затем запускает `update-blacklists`. |
| `dependabot.yml` | еженедельно | Открывает PR с обновлениями Python-пакетов и GitHub Actions. CI проверяет каждый такой PR. |

Пуш идёт встроенным `GITHUB_TOKEN` (`permissions: contents: write`), секреты не нужны. Коммит появляется
только если изменилось содержимое; строки `# Last updated` / `# Generated` при сравнении игнорируются.

## Защита от плохих данных

1. **При сборке.** Если whois или RIPEstat ответили ошибкой, job падает, а опубликованные файлы остаются прежними.
2. **Shrink guard.** `python3 -m ru_blacklist.diff` сравнивает новый `blacklist.txt` и `blacklist-vk.txt` с версией в `main` по **покрытому адресному пространству**, а не по числу строк. Если пропало больше 25% IPv4- или IPv6-покрытия, публикация отменяется. Отчёт с таблицей и списком добавленных/удалённых сетей попадает в Summary запуска.
3. **Проверка загрузки.** Перед коммитом все `.nft` и `.ipset` реально загружаются (по два раза) в изолированный network namespace, а серверный скрипт применяется с обоими бэкендами.
4. **На сервере.** `ru-blacklist-update` не применяет список с мусором, со слишком малым числом записей или резко уменьшившийся. В этих случаях он оставляет текущие правила (подробнее в [`deploy/README.md`](../deploy/README.md)).

Если уменьшение ожидаемое (например, вы удалили паттерн), запустите
**Actions → Update blacklists → Run workflow** с галочкой *skip_guard*.

## Как менять списки

- **Паттерны имён:** `config/black-names.txt`, `config/white-names.txt`, `config/vk-names.txt` (одно регулярное выражение на строку, есть комментарии и закомментированные предложения).
- **Свои адреса и ASN:** `config/custom-blacklist.txt`, одна запись на строку: `AS12345` (все префиксы,
  которые ASN анонсирует, обновляются ежедневно) или `203.0.113.0/24`.
- **Ложные срабатывания:** добавьте префикс в `config/allowlist.txt`, и он будет вырезан из всех списков.
- **Гос. netname'ы:** `config/gov-netnames.txt`.

Опечатку (не ASN и не префикс, битая регулярка) CI покажет сразу после push. Изменения попадут в списки
при следующем ежедневном запуске; чтобы применить сразу, запустите **Update blacklists** вручную.

## Настройки GitHub

- Если включите защиту ветки `main` (branch protection / rulesets), разрешите пуш для `github-actions[bot]`, иначе ежедневные коммиты перестанут проходить.
- Письма о сбоях запусков по расписанию GitHub отправляет тому, кто последним менял `cron` в файле workflow. Настраиваются в **Settings → Notifications → Actions**.
- В публичных репозиториях GitHub отключает расписания после 60 дней без активности и предупреждает об этом письмом; включить их обратно можно на вкладке Actions.

## Локально

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt

scripts/build.sh --offline              # пересобрать форматы из закоммиченных данных
scripts/build.sh                        # полная сборка (нужна сеть: RIPEstat, whois)
scripts/refresh-ripe-data.sh            # обновить data/ (нужна сеть, качает дампы RIPE DB)

pytest
ruff check .
shellcheck -x scripts/*.sh deploy/*.sh tests/integration/*.sh
actionlint
sudo tests/integration/test_deploy.sh   # нужны nft, ipset, iptables; хост не затрагивается
```
