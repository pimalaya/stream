---
cairn: spec
capability: tls
status: current
---

# TLS

The provider-agnostic vocabulary a consumer fills in to say how a session should be secured, and the two backends that read it. The backend types (`rustls`, `native-tls`) SHALL NOT escape this crate: a consumer names what it wants, never the library that will do it.

### Requirement: Provider selection

The provider SHALL be selectable, and an unset provider SHALL fall back to the first enabled feature, rustls with ring first, then rustls with aws-lc-rs, then native-tls.

Asking for a provider whose feature is off SHALL fail with a message naming the missing feature rather than silently using the other one.

#### Scenario: A build without native-tls
- GIVEN a consumer selecting the native-tls provider
- WHEN the crate was built without that feature
- THEN the connect fails, saying which cargo feature is missing

### Requirement: Trust

Server certificates SHALL be verified against the platform trust store by default.

A consumer MAY name one extra certificate to trust in the server, as a PEM path held apart from the client's own certificate so neither can be mistaken for the other. Under rustls it SHALL be pinned to the server's leaf and also offered as an extra trust anchor, which is what a self-signed CA-marked leaf (Proton Bridge) needs, a normal chain build rejecting it. Under native-tls it SHALL be added as a root certificate.

#### Scenario: A pinned self-signed leaf
- GIVEN a PEM holding the certificate a local bridge presents as its leaf
- WHEN the session is opened against that bridge
- THEN the certificate is accepted verbatim, where a chain build would have refused it

### Requirement: ALPN

ALPN identifiers SHALL be offered during a rustls handshake when the consumer lists any, and an empty list SHALL skip ALPN negotiation.

They live on the rustls options rather than beside the provider choice because native-tls exposes no ALPN switch, so the field would promise something one backend cannot keep. Protocol crates ship their own default identifiers for a config layer to copy in.

### Requirement: Client certificate

A consumer MAY name a client certificate and its private key as two PEM paths, presented when the server asks for one during the handshake. The certificate file MAY carry the intermediates after the leaf. Without one, nothing SHALL be presented, which is the default.

Both backends SHALL present it. Under native-tls the key SHALL be PKCS#8; under rustls PKCS#1 and SEC1 keys SHALL be read too.

#### Scenario: A server requiring a client certificate
- GIVEN a server that refuses any handshake without a client certificate its CA signed
- WHEN the session is opened with such a certificate and its key
- THEN the handshake completes, where without them the server refuses it
