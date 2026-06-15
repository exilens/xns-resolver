# XNS Resolver

XNS Resolver makes XNS names usable over Tor and I2P on Linux. A name such as
`example.xns` is looked up through an XNS indeXer, converted from its Ed25519
owner key to the corresponding network address, and routed without
application-specific XNS support.

It is a fork of [TSR](https://github.com/aeeravsar/TSR), reduced to the single
purpose of resolving XNS names.

## Requirements

- Linux with `systemd-resolved`
- Tor with a SOCKS5 listener, or I2P with a SAM listener
- Root privileges for TUN and routing setup
- An XNS indeXer URL

## Build

```sh
go build -o xns-resolver ./cmd/xns-resolver
```

## Run

Tor:

```sh
sudo ./xns-resolver \
  --network tor \
  --indexer https://indexer.xns.rocks \
  --tor-socks socks5://127.0.0.1:9050
```

I2P:

```sh
sudo ./xns-resolver \
  --network i2p \
  --indexer https://indexer.xns.rocks \
  --i2p-sam 127.0.0.1:7656
```

Once running, applications can use `name.xns` and its subdomains directly. For
`indexer.name.xns`, the rightmost label before `.xns` is the claimed XNS name,
while `indexer` is preserved for the application. The HTTP service receives
the original `Host: indexer.name.xns` header.

Subdomain existence is decided by the service's virtual-host configuration,
not by XNS Resolver. The cache is memory-only and is empty after every restart.
Finalized records are cached until their estimated expiration; records with
fewer than 10 confirmations are checked again after one minute.

Tor mode derives a Tor v3 onion address and opens each connection through the
specified SOCKS5 listener. I2P mode derives the extended base32 address used by
an encrypted LeaseSet2 destination and opens each connection through the
specified SAM listener. An I2P service created with
[xns-i2p](https://github.com/exilens/xns-i2p) must publish LeaseSet type 5.

```text
--network tor|i2p   destination network
--indexer URL       XNS indeXer URL
--tor-socks URL     Tor SOCKS5 URL, required for Tor
--i2p-sam HOST:PORT I2P SAM listener, required for I2P
--tun NAME          TUN interface name
--cidr CIDR         virtual IPv4 range
--gateway IP        virtual gateway address
--dns HOST:PORT     DNS listener on the virtual gateway
--mtu N             TUN MTU
```

## XNS

- [Website](https://xns.rocks)
- [Documentation](https://xns.rocks/docs)
- [Source code](https://github.com/exilens/xns)
- [Donate](https://xns.rocks/donate)
