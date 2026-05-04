use secrecy::SecretString;

#[derive(Clone, Debug)]
pub struct Sasl {
    pub mechanism: Option<SaslMechanism>,
    pub login: Option<SaslLogin>,
    pub plain: Option<SaslPlain>,
    pub anonymous: Option<SaslAnonymous>,
}

#[derive(Clone, Debug)]
pub enum SaslMechanism {
    Login,
    Plain,
    Anonymous,
}

#[derive(Clone, Debug)]
pub struct SaslLogin {
    pub username: String,
    pub password: SecretString,
}

#[derive(Clone, Debug)]
pub struct SaslPlain {
    pub authzid: Option<String>,
    pub authcid: String,
    pub passwd: SecretString,
}

#[derive(Clone, Debug)]
pub struct SaslAnonymous {
    pub message: Option<String>,
}
