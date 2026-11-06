# nftables blacklist

- https://raw.githubusercontent.com/TripleA150/RU-Blacklist/main/output/nftables/blacklist.nft (IPv4 + IPv6)
- `blacklist-v4.nft`, `blacklist-v6.nft` — the same split by family; load either the mixed file or the pair.

Each file can be loaded again at any time: the sets are flushed and refilled in one atomic `nft -f` transaction.

```bash
sudo nft -f blacklist.nft
sudo nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }'
sudo nft add rule inet filter input ip saddr @blacklist_v4 counter reject
sudo nft add rule inet filter input ip6 saddr @blacklist_v6 counter reject
```

For automatic updates with ready-made rules see [`deploy/README.md`](../../deploy/README.md).
