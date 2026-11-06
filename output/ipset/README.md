# ipset blacklist for iptables

- https://raw.githubusercontent.com/TripleA150/RU-Blacklist/main/output/ipset/blacklist-v4.ipset
- https://raw.githubusercontent.com/TripleA150/RU-Blacklist/main/output/ipset/blacklist-v6.ipset

Each file fills `<set>-tmp` and atomically swaps it with `<set>`, so `ipset restore` can be
repeated at any time, also while iptables rules use the set.

```bash
ipset restore < blacklist-v4.ipset
ipset restore < blacklist-v6.ipset
iptables  -I INPUT -m set --match-set blacklist-v4 src -m conntrack --ctstate NEW -j DROP
ip6tables -I INPUT -m set --match-set blacklist-v6 src -m conntrack --ctstate NEW -j DROP
```

For automatic updates with ready-made rules see [`deploy/README.md`](../../deploy/README.md).
