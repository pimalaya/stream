---
cairn: change
id: io-proxy-0-2
status: landed
created: 2026-11-13
---

# Move the proxy handshakes to io-proxy 0.2

## Why

io-proxy 0.2.0 was released on 2026-11-13. It validates the target of an HTTP `CONNECT` request, which 0.1 wrote into the request unchecked (a host holding a line break added header lines of its own), it fails on an end of stream where 0.1 could report an open tunnel, and it takes the proxy password as a secret instead of a plain string. Every connect of the family goes through this crate, so the fixes reach nobody until the requirement here moves.

The family audit of 2026-11-13 (FAM-22) also recorded that a bracketed IPv6 target, which is how a URL writes one, reached the SOCKS5 request as a domain name.

## What

The io-proxy requirement moves from 0.1.1 to 0.2. `Proxy::connect` hands the password over as the `SecretString` it already holds, and takes an IPv6 target with or without its brackets.

Nothing of io-proxy appears in a public signature of this crate, before or after, so the release can be a patch one.

## Cost

A target host an HTTP proxy request cannot carry now fails the connect, where it used to be written as given. A bracketed IPv6 target on a direct connection now connects, where it used to fail to resolve.

## Consumers

Every io- protocol crate opening its stream here picks the change up with the patch release, without a line to change. io-imap still passes the URL host with its brackets, which this change makes harmless for the connect itself.
