# TSR (The Sovereign Router)

## Why and How

Normally, if you want to benefit from the beauty of onion services or eepsites in a program, you have three choices:
- Implement native Tor/I2P support to the source code
- Sniff and modify packets on the fly to route through the desired network's proxy.
- Route all traffic over the desired network's proxy.

With the first option, you have to patch the program's source code to handle the ".onion"/".b32.i2p" domains to route through the relevant network's proxy. If the program is not open source, or you don't want to recompile the program for every release just to achieve something very fundamental, you would go for the second option, try to hijack packets on the fly to use the relevant network's proxy, this again is a precision surgery operation. Or you could go for the third option, the easiest one everyone uses, running the program to use the proxy for everything. But what if the program requires more than one network? Now you have to route even the clearnet packets over Tor, or worse, can't even use clearnet on I2P if you haven't setup an I2P outproxy.

But there is a smarter way. Instead of going deep and messing with individual programs, we can change the ground things operate in. TSR achieves that by managing the system's DNS to route specified domains through it's own handler, which creates a TUN device to allocate a specified virtual IP range to map the domains to the virtual IPs, then when a program connects to a virtual IP, TSR opens a connection over the specified proxy to the mapped address, and forwards the packet.

This, in practice, lets your OS natively speak the I2P/Tor language. Now you can use any program/service over these networks seamlessly. Imagine how seamless it is now to just `ssh user@host.i2p`, or use an onion Monero node in a wallet program that doesn't natively support it.

## Usage

**Warning:** Currently only systemd-resolved is supported.

Compile:
```
go build -o tsrd ./cmd/tsrd
```
Generate config:
```
sudo mkdir -p /etc/tsr
sudo ./tsrd --generate-config /etc/tsr/config.toml
```
You might want to edit the config to add different routes or change default parameters, here is the default config:
```
[dns]
listen = "10.203.0.1:53"

[net]
tun = "tsr0"
cidr = "10.203.0.0/16"
gateway = "10.203.0.1"
mtu = 1500

[[route]]
name = "tor"
domains = [".onion"]
proxy = "socks5://127.0.0.1:9050"

[[alias]]
target = ".onion"
domains = [".onio", ".onionn"]

[[route]]
name = "i2p"
domains = [".i2p", ".b32.i2p"]
proxy = "http://127.0.0.1:4444"
``` 
Run TSR:
```
sudo ./tsrd --config /etc/tsr/config.toml
```
Congrats, now your OS can speak I2P/Tor natively.