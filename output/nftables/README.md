# nftables blacklists

Short: ready-to-use nftables set files (general and VK-only, separated by IPv4/IPv6).

## Download links

- https://raw.githubusercontent.com/TripleA150/RU-Blacklist/main/output/nftables/blacklist.nft
- https://raw.githubusercontent.com/TripleA150/RU-Blacklist/main/output/nftables/blacklist-v4.nft
- https://raw.githubusercontent.com/TripleA150/RU-Blacklist/main/output/nftables/blacklist-v6.nft
- https://raw.githubusercontent.com/TripleA150/RU-Blacklist/main/output/nftables/blacklist-vk.nft
- https://raw.githubusercontent.com/TripleA150/RU-Blacklist/main/output/nftables/blacklist-vk-v4.nft
- https://raw.githubusercontent.com/TripleA150/RU-Blacklist/main/output/nftables/blacklist-vk-v6.nft

## How to use

Every file can be loaded again at any time (e.g. from cron after downloading a fresh copy):
the sets are flushed and refilled inside one atomic `nft -f` transaction. The `-v4`/`-v6`
files only touch their own set, so load either the mixed file or the pair, not both.

For automatic updates with ready-made rules see [`deploy/README.md`](../../deploy/README.md).

### 1) Protect VM from incoming connections (general blacklists)

Load either mixed or split general set files:

```bash
sudo nft -f blacklist.nft
# or:
sudo nft -f blacklist-v4.nft
sudo nft -f blacklist-v6.nft
```

Apply rules for inbound traffic to the VM:

```bash
sudo nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }'
sudo nft add rule inet filter input ip saddr @blacklist_v4 counter reject
sudo nft add rule inet filter input ip6 saddr @blacklist_v6 counter reject
```

### 2) Block VK outbound traffic for VPN clients via NAT/FORWARD

Load either mixed or split VK set files:

```bash
sudo nft -f blacklist-vk.nft
# or:
sudo nft -f blacklist-vk-v4.nft
sudo nft -f blacklist-vk-v6.nft
```

Apply rules for forwarded client traffic (replace `<VPN_IFACE>`):

```bash
sudo nft add chain inet filter forward '{ type filter hook forward priority 0; policy accept; }'
sudo nft add rule inet filter forward iifname "<VPN_IFACE>" ip daddr @blacklist_vk_v4 counter reject
sudo nft add rule inet filter forward iifname "<VPN_IFACE>" ip6 daddr @blacklist_vk_v6 counter reject
```
