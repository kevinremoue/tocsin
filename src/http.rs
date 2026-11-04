//! Outbound HTTP client, shared by the vulnerability sources and the notifiers.
use std::time::Duration;

pub fn client() -> reqwest::Result<reqwest::Client> {
    // reqwest is built without a bundled crypto provider: use ring, which sqlx already depends on.
    // Fails harmlessly when a provider is already installed (several clients, tests).
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .user_agent(concat!(
            "tocsin/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/kevinremoue/tocsin)"
        ))
        .timeout(Duration::from_secs(60))
        .build()
}
