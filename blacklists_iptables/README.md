# ipset blacklists for iptables

Short: ready-to-use `ipset restore` files (general and VK-only, separated by IPv4/IPv6).

## Download links

- https://raw.githubusercontent.com/TripleA150/RU-Blacklist/main/blacklists_iptables/blacklist-v4.ipset
- https://raw.githubusercontent.com/TripleA150/RU-Blacklist/main/blacklists_iptables/blacklist-v6.ipset
- https://raw.githubusercontent.com/TripleA150/RU-Blacklist/main/blacklists_iptables/blacklist-vk-v4.ipset
- https://raw.githubusercontent.com/TripleA150/RU-Blacklist/main/blacklists_iptables/blacklist-vk-v6.ipset

## How to use

Each file fills `<set>-tmp`, atomically swaps it with `<set>` and destroys the temporary set,
so `ipset restore` can be repeated at any time, also while iptables rules reference the set.

### 1) Protect the server from incoming connections

```bash
ipset restore < blacklist-v4.ipset
ipset restore < blacklist-v6.ipset
iptables  -I INPUT -m set --match-set blacklist-v4 src -m conntrack --ctstate NEW -j DROP
ip6tables -I INPUT -m set --match-set blacklist-v6 src -m conntrack --ctstate NEW -j DROP
```

### 2) Block VK/MAX/OK traffic of the server and of VPN clients

```bash
ipset restore < blacklist-vk-v4.ipset
ipset restore < blacklist-vk-v6.ipset
iptables  -I OUTPUT  -m set --match-set blacklist-vk-v4 dst -j REJECT
iptables  -I FORWARD -m set --match-set blacklist-vk-v4 dst -j REJECT
ip6tables -I OUTPUT  -m set --match-set blacklist-vk-v6 dst -j REJECT
ip6tables -I FORWARD -m set --match-set blacklist-vk-v6 dst -j REJECT
```

Sets created by older versions of these files have different `hashsize`/`maxelem` values;
destroy them once (`ipset destroy <set>` after removing the rules that use them) before switching.

For automatic updates with ready-made rules see [`deploy/README.md`](../deploy/README.md).
