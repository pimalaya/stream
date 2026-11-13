---
cairn: delta
change: client-identity
---

## ADDED Requirements

### Requirement: Client certificate

A consumer MAY name a client certificate and its private key as two PEM paths, presented when the server asks for one during the handshake. The certificate file MAY carry the intermediates after the leaf. Without one, nothing SHALL be presented, which is the default.

Both backends SHALL present it. Under native-tls the key SHALL be PKCS#8; under rustls PKCS#1 and SEC1 keys SHALL be read too.

#### Scenario: A server requiring a client certificate
- GIVEN a server that refuses any handshake without a client certificate its CA signed
- WHEN the session is opened with such a certificate and its key
- THEN the handshake completes, where without them the server refuses it

## MODIFIED Requirements

### Requirement: Trust

Server certificates SHALL be verified against the platform trust store by default.

A consumer MAY name one extra certificate to trust in the server, as a PEM path held apart from the client's own certificate so neither can be mistaken for the other. Under rustls it SHALL be pinned to the server's leaf and also offered as an extra trust anchor, which is what a self-signed CA-marked leaf (Proton Bridge) needs, a normal chain build rejecting it. Under native-tls it SHALL be added as a root certificate.

#### Scenario: A pinned self-signed leaf
- GIVEN a PEM holding the certificate a local bridge presents as its leaf
- WHEN the session is opened against that bridge
- THEN the certificate is accepted verbatim, where a chain build would have refused it

## REMOVED Requirements

None.
