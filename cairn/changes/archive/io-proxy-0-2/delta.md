---
cairn: delta
change: io-proxy-0-2
---

## ADDED Requirements

### Requirement: Target hosts

The target SHALL be a hostname or an IP literal. An IPv6 literal SHALL be taken with or without the brackets a URL writes around it: it reaches a SOCKS5 proxy as an address, an HTTP proxy between brackets, and a direct connection bare.

A target an HTTP `CONNECT` request cannot carry (anything outside a registered name or an IP literal, a space or a line break included) SHALL fail the connect before anything is written to the proxy. A target a SOCKS5 request cannot carry (an empty name, or one over 255 bytes) SHALL fail the same way.

A proxy that ends the stream before its handshake is complete SHALL fail the connect, never hand back a stream.

#### Scenario: A bracketed IPv6 target
- GIVEN the target `[2001:db8::1]`, as a URL writes it
- WHEN the connection goes through a SOCKS5 proxy
- THEN the proxy is asked for the address `2001:db8::1`, not for a domain name

#### Scenario: A target holding a line break
- GIVEN a target host holding a line break
- WHEN the connection goes through an HTTP proxy
- THEN the connect fails and the proxy has received nothing

## MODIFIED Requirements

None.

## REMOVED Requirements

None.
