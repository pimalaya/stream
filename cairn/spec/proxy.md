---
cairn: spec
capability: proxy
status: current
---

# Proxy

How a connection reaches its target: directly, through a SOCKS5 proxy, through an HTTP `CONNECT` proxy, or through whatever the environment names. Every transport funnels through the same connect, so proxy support is uniform across IMAP, SMTP, HTTP and any protocol added later.

### Requirement: Tunnels only

A proxy SHALL be used as a tunnel: the target host and port stay opaque to it, TLS still terminates at the target, and certificate validation stays bound to the target host.

Plaintext HTTP forward proxying (absolute-URI request lines) SHALL NOT be supported. It would leak proxy awareness into the HTTP layer, and every Pimalaya HTTP backend is HTTPS.

SOCKS5 SHALL carry the hostname to the proxy rather than an address resolved locally (`socks5h` semantics), so a target only the proxy can resolve still connects.

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

### Requirement: Resolution from the environment

The default proxy SHALL be resolved at connect time, not before, so the decision sees the actual target host.

`all_proxy` SHALL be read first, then `https_proxy`, each in its lowercase spelling before its uppercase one, an empty value counting as unset. A variable that fails to parse SHALL be logged and skipped rather than aborting the connection, falling through to the next source and finally to a direct connection.

#### Scenario: A malformed variable
- GIVEN `all_proxy` holding something that is not a proxy URL
- WHEN a connection is opened
- THEN the variable is ignored, and the connect continues through the next source

### Requirement: Bypass

Loopback targets SHALL always bypass the proxy, a proxy having no way to reach the caller's own machine. Beyond those, `no_proxy` SHALL bypass a target when an entry matches it exactly or as a domain suffix, and `*` SHALL bypass everything.

#### Scenario: A suffix entry
- GIVEN `no_proxy=example.com`
- WHEN `mail.example.com` is the target
- THEN the connection goes direct

### Requirement: Proxy URLs

A proxy SHALL be namable as a URL. `socks5`, `socks5h` and `socks` mean SOCKS5 and default to port 1080; `http` and `https` mean HTTP `CONNECT` and default to port 8080. Any other scheme SHALL be rejected. A username in the URL SHALL become proxy credentials, the password held as a secret and kept out of `Debug` output and logs.

#### Scenario: Credentials in the URL
- GIVEN `socks5://alice:secret@10.0.0.1:1080`
- WHEN it is parsed
- THEN it names a SOCKS5 proxy at that address carrying alice's credentials, and the password never prints
