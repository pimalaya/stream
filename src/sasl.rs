//! # SASL
//!
//! Protocol-agnostic descriptions of [SASL] authentication
//! credentials. Consumers in other Pimalaya crates (`io-imap`, `io-smtp`,
//! `io-pop3`, ...) translate these into the appropriate protocol-level
//! commands.
//!
//! Each variant carries only the bits the mechanism actually transmits;
//! protocol-specific framing (`AUTHENTICATE LOGIN`, GS2 header, etc.) lives in
//! the consumer.
//!
//! [SASL]: https://www.rfc-editor.org/rfc/rfc4422

use secrecy::SecretString;

/// Tag for a SASL mechanism without its credentials.
///
/// Use when the choice of mechanism needs to flow through a config or wire
/// boundary separately from the credentials themselves.
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
///
/// One variant per supported mechanism; each variant wraps the per-mechanism
/// struct that carries its credentials.
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

/// ANONYMOUS mechanism ([RFC 4505]): unauthenticated access carrying an
/// optional trace token (typically an email-like string the server can log). No
/// secrets.
///
/// [RFC 4505]: https://www.rfc-editor.org/rfc/rfc4505
#[derive(Clone, Debug)]
pub struct SaslAnonymous {
    pub message: Option<String>,
}

/// LOGIN mechanism: legacy two-prompt scheme that sends the username and
/// password as base64-encoded server challenges. Never RFC- standardised (the
/// [draft-murchison-sasl-login] expired) but widely implemented. Also used as
/// the cleartext-credentials shape for protocol-level `LOGIN` commands
/// (e.g. IMAP `LOGIN`, [RFC 3501 §6.2.3]).
///
/// [draft-murchison-sasl-login]: https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login-00
/// [RFC 3501 §6.2.3]: https://www.rfc-editor.org/rfc/rfc3501#section-6.2.3
#[derive(Clone, Debug)]
pub struct SaslLogin {
    pub username: String,
    pub password: SecretString,
}

/// PLAIN mechanism ([RFC 4616]): single-message scheme that sends `authzid NUL
/// authcid NUL password` base64-encoded. `authzid` (authorization identity) is
/// optional; `authcid` is the authentication identity.
///
/// [RFC 4616]: https://www.rfc-editor.org/rfc/rfc4616
#[derive(Clone, Debug)]
pub struct SaslPlain {
    pub authzid: Option<String>,
    pub authcid: String,
    pub passwd: SecretString,
}

/// OAUTHBEARER mechanism ([RFC 7628]): bearer-token scheme carrying the token
/// plus a GS2 header that names the user and the server host/port pair. `host`
/// and `port` are sent verbatim in the GS2 header and should match the server
/// the caller is talking to.
///
/// [RFC 7628]: https://www.rfc-editor.org/rfc/rfc7628
#[derive(Clone, Debug)]
pub struct SaslOauthbearer {
    pub username: String,
    pub host: String,
    pub port: u16,
    pub token: SecretString,
}

/// XOAUTH2 mechanism: Google's pre-standard OAuth 2.0 SASL scheme.  Same shape
/// as OAUTHBEARER minus the host/port GS2 header fields.  Not
/// IETF-standardised; documented at:
/// <https://developers.google.com/gmail/imap/xoauth2-protocol>.
#[derive(Clone, Debug)]
pub struct SaslXoauth2 {
    pub username: String,
    pub token: SecretString,
}

/// SCRAM-SHA-256 mechanism ([RFC 7677]): salted password-based scheme in the
/// SCRAM family ([RFC 5802]). The password never leaves the client; the
/// mechanism proves possession of it via a salted hash exchange.
///
/// [RFC 7677]: https://www.rfc-editor.org/rfc/rfc7677
/// [RFC 5802]: https://www.rfc-editor.org/rfc/rfc5802
#[derive(Clone, Debug)]
pub struct SaslScramSha256 {
    pub username: String,
    pub password: SecretString,
}
