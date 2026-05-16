use secrecy::SecretString;

#[derive(Clone, Debug)]
pub enum SaslMechanism {
    Login,
    Plain,
    Anonymous,
}

#[derive(Clone, Debug)]
pub enum Sasl {
    Login(SaslLogin),
    Plain(SaslPlain),
    Anonymous(SaslAnonymous),
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
