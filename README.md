# XNS Resolver

XNS Resolver makes XNS names usable as native Tor addresses on Linux. A name
such as `example.xns` is looked up through an XNS indeXer, converted from its
Ed25519 owner key to the corresponding Tor v3 onion address, and routed through
Tor without application-specific XNS support.

It is a fork of [TSR](https://github.com/aeeravsar/TSR), reduced to the single
purpose of resolving XNS names over Tor.

## Requirements

- Linux with `systemd-resolved`
- Tor with a SOCKS5 listener
- Root privileges for TUN and routing setup
- An XNS indeXer URL

## Build

```sh
go build -o xns-resolver ./cmd/xns-resolver
```

## Run

```sh
sudo ./xns-resolver --indexer https://indexer.xns.rocks
```

The indeXer is the only required option. Tor is expected at
`socks5://127.0.0.1:9050` by default.

```text
--indexer URL       XNS indeXer URL
--tor-proxy URL     Tor SOCKS5 proxy URL
--tun NAME          TUN interface name
--cidr CIDR         virtual IPv4 range
--gateway IP        virtual gateway address
--dns HOST:PORT     DNS listener on the virtual gateway
--mtu N             TUN MTU
```

Once running, applications can use `name.xns` directly. TCP is forwarded to the
Tor v3 onion address derived from the name's XNS owner key. The original
hostname remains in the application protocol, so an HTTP onion service can
accept `Host: name.xns`.

Only single-label XNS names are resolved. The cache is memory-only and is empty
after every restart. Finalized records are cached until their estimated
expiration; records with fewer than 10 confirmations are checked again after
one minute.

## XNS

- [Website](https://xns.rocks)
- [Documentation](https://xns.rocks/docs)
- [Source code](https://github.com/exilens/xns)
- [Donate](https://xns.rocks/donate)
