---
cairn: delta
change: client-identity
---

## ADDED Requirements

### Requirement: Client identity

A consumer MAY name a client certificate and its private key as two PEM paths, presented when the server asks for one during the handshake. The certificate file MAY carry the intermediates after the leaf. Without one, nothing SHALL be presented, which is the default.

Both backends SHALL present it. Under native-tls the key SHALL be PKCS#8; under rustls PKCS#1 and SEC1 keys SHALL be read too.

#### Scenario: A server requiring a client certificate
- GIVEN a server that refuses any handshake without a client certificate its CA signed
- WHEN the session is opened with such a certificate and its key
- THEN the handshake completes, where without them the server refuses it

## MODIFIED Requirements

None.

## REMOVED Requirements

None.
