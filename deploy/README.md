# Автообновление блок-листов на сервере

`ru-blacklist-update` раз в 6 часов скачивает свежие списки из этого репозитория
и атомарно применяет их к файрволу сервера. Сервер сам забирает данные (pull):
GitHub не нужны ни SSH-доступ, ни IP сервера, работает и за NAT.

Что блокируется (настраивается в `/etc/ru-blacklist.conf`):

| Параметр | По умолчанию | Что делает |
|---|---|---|
| `BLOCK_GOV_INPUT` | `yes` | Дропает **новые входящие** соединения из гос. сетей (`blacklist-v4/v6.txt`) |
| `BLOCK_VK_FORWARD` | `yes` | Отклоняет трафик **VPN-клиентов** к сетям VK/MAX/OK (`blacklist-vk-*.txt`), цепочка FORWARD |
| `BLOCK_VK_OUTPUT` | `no` | Отклоняет **собственный** трафик сервера к VK/MAX/OK, цепочка OUTPUT |

Какой вариант для VK выбрать:

- **WireGuard / AmneziaWG / OpenVPN.** Трафик клиентов маршрутизируется через сервер, поэтому нужен `BLOCK_VK_FORWARD=yes`. Чтобы ограничиться VPN-интерфейсами, задайте `VPN_IFACES="wg0"`.
- **Xray (VLESS/Reality) / sing-box / Shadowsocks / Outline.** Прокси сам открывает соединения от имени сервера, поэтому нужен `BLOCK_VK_OUTPUT=yes`.

VK-сети отклоняются через `reject` (TCP RST / ICMP admin-prohibited), а не `drop`.
Так приложения на телефоне сразу получают ошибку и не висят на таймаутах.

## Установка

Требования: Linux с systemd, `curl` или `wget`; для бэкенда nftables нужен `nft`, для бэкенда ipset нужны `ipset` и `iptables`.

```bash
# из клона репозитория
git clone https://github.com/TripleA150/RU-Blacklist.git
sudo ./RU-Blacklist/deploy/install.sh

# или одной командой
curl -fsSL https://raw.githubusercontent.com/TripleA150/RU-Blacklist/main/deploy/install.sh | sudo sh
```

После установки:

```bash
sudo nano /etc/ru-blacklist.conf                    # BACKEND, VPN_IFACES, ALLOW_PREFIXES
sudo ru-blacklist-update --dry-run | less           # посмотреть, что будет применено
sudo systemctl start ru-blacklist-update.service     # применить сейчас
sudo systemctl start ru-blacklist-update.timer       # включить автообновление
journalctl -u ru-blacklist-update -n 20              # лог
cat /var/lib/ru-blacklist/last-applied               # когда и сколько применено
```

> [!IMPORTANT]
> Если вы заходите на сервер по SSH из России, добавьте свой IP или подсеть в
> `ALLOW_PREFIXES`. В гос. списки попадают и крупные диапазоны провайдеров,
> поэтому без этого есть риск потерять доступ к серверу. Текущая SSH-сессия
> не оборвётся (блокируются только новые соединения), но переподключиться уже не получится.

## Как это устроено

- **nftables.** Скрипт создаёт отдельную таблицу `inet ru_blacklist` с set'ами `gov_v4`, `gov_v6`, `vk_v4`, `vk_v6` и цепочками на хуках input/forward/output с приоритетом `-10`. Таблица целиком пересоздаётся одной транзакцией `nft -f`, поэтому разрыва в защите нет. Ваши правила в других таблицах не затрагиваются: `drop`/`reject` в любой базовой цепочке срабатывает независимо от `accept` в других.
- **ipset + iptables.** Скрипт создаёт set'ы `ru-bl-gov-v4`, `ru-bl-vk-v4` и т.д. и обновляет их через временный set и `swap`. Свои цепочки `RU_BL_INPUT`, `RU_BL_FORWARD`, `RU_BL_OUTPUT` он пересобирает через `iptables-restore --noflush`, а переходы в них ставит первым правилом в INPUT/FORWARD/OUTPUT (и то же самое для ip6tables).
- **Защита от плохих данных.** Списки с мусором (например, HTML-страница ошибки), со слишком малым числом записей (`MIN_*_ENTRIES`) или резко уменьшившиеся (`MAX_SHRINK_PERCENT`) не применяются, и текущие правила остаются. Если GitHub недоступен, используется кэш из `/var/lib/ru-blacklist`. Принудительно применить можно через `--force`.
- **После перезагрузки** таймер срабатывает через минуту после старта и восстанавливает правила, даже без сети (из кэша). Сохранять эти правила в `iptables-persistent` или `/etc/nftables.conf` не нужно.

> [!NOTE]
> `systemctl reload nftables` (или `nft flush ruleset` в `/etc/nftables.conf`)
> удаляет и таблицу `ru_blacklist`. Восстановить её сразу можно командой
> `systemctl start ru-blacklist-update`, иначе это сделает следующий запуск таймера.

## Удаление

```bash
sudo ru-blacklist-update --remove
sudo systemctl disable --now ru-blacklist-update.timer
sudo rm /usr/local/sbin/ru-blacklist-update /etc/systemd/system/ru-blacklist-update.* /etc/ru-blacklist.conf
sudo systemctl daemon-reload
```
