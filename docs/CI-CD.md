# Устройство репозитория и CI/CD

## Структура

```
config/rules.txt все ручные правила: паттерны имён, исключения, netname'ы, свои ASN/префиксы,
                 allowlist и PTR-поиск (формат описан в начале файла)
data/            данные RIPE, обновляются автоматически (scripts/refresh-ripe-data.sh)
output/          готовые списки, обновляются автоматически (scripts/build.sh)
  txt/                 blacklist.txt, blacklist-v4/v6.txt, blacklist_with_comments.txt
  nftables/            .nft-файлы (перезагружаются атомарно)
  ipset/               .ipset-файлы для iptables (перезагружаются атомарно)
ru_blacklist/    Python-код (запуск: python3 -m ru_blacklist.<модуль>)
scripts/         build.sh, refresh-ripe-data.sh, lib.sh
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
2. **Shrink guard.** `python3 -m ru_blacklist.diff` сравнивает новый `blacklist.txt` с версией в `main` по **покрытому адресному пространству**, а не по числу строк. Если пропало больше 25% IPv4- или IPv6-покрытия, публикация отменяется. Отчёт с таблицей и списком добавленных/удалённых сетей попадает в Summary запуска.
3. **Проверка загрузки.** Перед коммитом все `.nft` и `.ipset` реально загружаются (по два раза) в изолированный network namespace, а серверный скрипт применяется с обоими бэкендами.
4. **На сервере.** `ru-blacklist-update` не применяет список с мусором, со слишком малым числом записей или резко уменьшившийся. В этих случаях он оставляет текущие правила (подробнее в [`deploy/README.md`](../deploy/README.md)).

Если уменьшение ожидаемое (например, вы удалили паттерн), запустите
**Actions → Update blacklists → Run workflow** с галочкой *skip_guard*.

## Как менять списки

Всё правится в одном файле `config/rules.txt`, по одному правилу на строку:

| Правило | Что делает |
|---|---|
| `name <regex>` | блокирует ASN и сети из `data/`, чьи имена совпадают (grep -E, без учёта регистра) |
| `!name <regex>` | исключение для `name` |
| `netname <NAME>` | блокирует сети, зарегистрированные под этим netname (whois) |
| `AS12345` | блокирует все префиксы, которые ASN анонсирует (обновляется ежедневно) |
| `203.0.113.0/24` | блокирует адрес или префикс |
| `!203.0.113.0/24` | никогда не блокировать (сильнее всех правил) |
| `ptr <prefix\|ASN>` | где проверять PTR-записи (не больше 262 144 адресов суммарно) |
| `ptr-key <regex>` | ключевое слово в PTR, например `tspu`; совпавшие адреса блокируются как /32 |

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
