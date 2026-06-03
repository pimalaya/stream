//! Protocol-agnostic [SASL] credential descriptors.
//!
//! Each variant carries only the bits the mechanism transmits on the wire;
//! protocol-specific framing (`AUTHENTICATE LOGIN`, GS2 header, etc.) lives in
//! the consumer crate (`io-imap`, `io-smtp`, `io-pop3`, ...).
//!
//! [SASL]: https://www.rfc-editor.org/rfc/rfc4422

use secrecy::SecretString;

/// Tag identifying a SASL mechanism without its credentials.
#[derive(Clone, Debug)]
pub enum SaslMechanism {
    Anonymous,
    Login,
    Plain,
    OAuthBearer,
    XOAuth2,
    ScramSha256,
}

/// SASL credentials for a single authentication mechanism.
#[derive(Clone, Debug)]
pub enum Sasl {
    Anonymous(SaslAnonymous),
    Login(SaslLogin),
    Plain(SaslPlain),
    Oauthbearer(SaslOauthbearer),
    Xoauth2(SaslXoauth2),
    ScramSha256(SaslScramSha256),
}

impl From<SaslAnonymous> for Sasl {
    fn from(sasl: SaslAnonymous) -> Self {
        Self::Anonymous(sasl)
    }
}

impl From<SaslLogin> for Sasl {
    fn from(sasl: SaslLogin) -> Self {
        Self::Login(sasl)
    }
}

impl From<SaslPlain> for Sasl {
    fn from(sasl: SaslPlain) -> Self {
        Self::Plain(sasl)
    }
}

impl From<SaslOauthbearer> for Sasl {
    fn from(sasl: SaslOauthbearer) -> Self {
        Self::Oauthbearer(sasl)
    }
}

impl From<SaslXoauth2> for Sasl {
    fn from(sasl: SaslXoauth2) -> Self {
        Self::Xoauth2(sasl)
    }
}

impl From<SaslScramSha256> for Sasl {
    fn from(sasl: SaslScramSha256) -> Self {
        Self::ScramSha256(sasl)
    }
}

/// ANONYMOUS mechanism credentials ([RFC 4505]).
///
/// Carries an optional trace token (typically an email-like string the server
/// can log); no secrets.
///
/// [RFC 4505]: https://www.rfc-editor.org/rfc/rfc4505
#[derive(Clone, Debug)]
pub struct SaslAnonymous {
    pub message: Option<String>,
}

/// LOGIN mechanism credentials ([draft-murchison-sasl-login]).
///
/// Legacy two-prompt cleartext scheme; also used as the credential shape for
/// protocol-level `LOGIN` commands (e.g. IMAP `LOGIN`, [RFC 3501 §6.2.3]).
///
/// [draft-murchison-sasl-login]: https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login-00
/// [RFC 3501 §6.2.3]: https://www.rfc-editor.org/rfc/rfc3501#section-6.2.3
#[derive(Clone, Debug)]
pub struct SaslLogin {
    pub username: String,
    pub password: SecretString,
}

/// PLAIN mechanism credentials ([RFC 4616]).
///
/// Single-message scheme sending `authzid NUL authcid NUL password`;
/// `authzid` is optional.
///
/// [RFC 4616]: https://www.rfc-editor.org/rfc/rfc4616
#[derive(Clone, Debug)]
pub struct SaslPlain {
    pub authzid: Option<String>,
    pub authcid: String,
    pub passwd: SecretString,
}

/// OAUTHBEARER mechanism credentials ([RFC 7628]).
///
/// `host` and `port` are sent verbatim in the GS2 header and should match the
/// server being contacted.
///
/// [RFC 7628]: https://www.rfc-editor.org/rfc/rfc7628
#[derive(Clone, Debug)]
pub struct SaslOauthbearer {
    pub username: String,
    pub host: String,
    pub port: u16,
    pub token: SecretString,
}

/// XOAUTH2 mechanism credentials ([Google XOAUTH2]).
///
/// Pre-standard OAuth 2.0 SASL scheme; same shape as OAUTHBEARER minus the
/// GS2 host/port fields. Not IETF-standardised.
///
/// [Google XOAUTH2]: https://developers.google.com/gmail/imap/xoauth2-protocol
#[derive(Clone, Debug)]
pub struct SaslXoauth2 {
    pub username: String,
    pub token: SecretString,
}

/// SCRAM-SHA-256 mechanism credentials ([RFC 7677], [RFC 5802]).
///
/// Salted password-based scheme; the password never leaves the client.
///
/// [RFC 7677]: https://www.rfc-editor.org/rfc/rfc7677
/// [RFC 5802]: https://www.rfc-editor.org/rfc/rfc5802
#[derive(Clone, Debug)]
pub struct SaslScramSha256 {
    pub username: String,
    pub password: SecretString,
}
