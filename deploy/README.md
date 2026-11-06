# Автообновление блок-листа на сервере

`ru-blacklist-update` раз в 6 часов скачивает свежие `blacklist-v4.txt` и `blacklist-v6.txt`
из этого репозитория и атомарно применяет их к файрволу сервера: **новые входящие**
соединения из этих сетей отбрасываются. Сервер сам забирает данные (pull), поэтому
GitHub не нужны ни SSH-доступ, ни IP сервера, и всё работает за NAT.

## Установка

Требования: Linux с systemd, `curl` или `wget`; для бэкенда nftables — `nft`, для ipset — `ipset` и `iptables`.

```bash
curl -fsSL https://raw.githubusercontent.com/TripleA150/RU-Blacklist/main/deploy/install.sh | sudo sh
# или из клона: sudo ./RU-Blacklist/deploy/install.sh

sudo nano /etc/ru-blacklist.conf                    # BACKEND, ALLOW_PREFIXES
sudo ru-blacklist-update --dry-run | less           # посмотреть, что будет применено
sudo systemctl start ru-blacklist-update.service     # применить сейчас
sudo systemctl start ru-blacklist-update.timer       # включить автообновление
journalctl -u ru-blacklist-update -n 20              # лог
cat /var/lib/ru-blacklist/last-applied               # когда и сколько применено
```

> [!IMPORTANT]
> Если вы заходите на сервер по SSH из России, добавьте свой IP или подсеть в
> `ALLOW_PREFIXES`: в списки попадают и крупные диапазоны провайдеров. Текущая
> SSH-сессия не оборвётся (блокируются только новые соединения), но переподключиться не получится.

## Как это устроено

- **nftables.** Скрипт ведёт отдельную таблицу `inet ru_blacklist` с set'ами `gov_v4`/`gov_v6` и цепочкой `input` с приоритетом `-10`. Таблица целиком пересоздаётся одной транзакцией `nft -f`, разрыва в защите нет. Остальные таблицы не затрагиваются.
- **ipset + iptables.** Set'ы `ru-bl-gov-v4`/`ru-bl-gov-v6` обновляются через временный set и `swap`. Цепочка `RU_BL_INPUT` пересобирается через `iptables-restore --noflush`, переход в неё стоит первым правилом INPUT (то же для ip6tables).
- **Защита от плохих данных.** Список с мусором, меньше `MIN_ENTRIES` записей или резко уменьшившийся (`MAX_SHRINK_PERCENT`) не применяется, текущие правила остаются. Если GitHub недоступен, берётся кэш из `/var/lib/ru-blacklist`. Принудительно: `--force`.
- **После перезагрузки** таймер срабатывает через минуту и восстанавливает правила, даже без сети (из кэша). Сохранять их в `iptables-persistent` или `/etc/nftables.conf` не нужно.

> [!NOTE]
> `systemctl reload nftables` (или `flush ruleset` в `/etc/nftables.conf`) удаляет и таблицу
> `ru_blacklist`; её сразу вернёт `systemctl start ru-blacklist-update`, иначе — следующий запуск таймера.

## Удаление

```bash
sudo ru-blacklist-update --remove
sudo systemctl disable --now ru-blacklist-update.timer
sudo rm /usr/local/sbin/ru-blacklist-update /etc/systemd/system/ru-blacklist-update.* /etc/ru-blacklist.conf
sudo systemctl daemon-reload
```
