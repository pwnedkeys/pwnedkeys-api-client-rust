use pwnedkeys_core::Key;

use crate::Error;

pub struct AsyncClient {
    api_key: Option<String>,
    base_url: reqwest::Url,
    client: reqwest::Client,
}

impl AsyncClient {
    pub fn new(api_key: Option<impl Into<String>>) -> Self {
        Self {
            api_key: api_key.map(|s| s.into()),
            base_url: reqwest::Url::parse("https://v1.pwnedkeys.com").unwrap(),
            client: reqwest::Client::new(),
        }
    }

    pub async fn is_pwned(&self, key: &Key) -> Result<bool, Error> {
        let mut req = self.client.get(self.base_url.join(&key.fingerprint()).unwrap());

        if let Some(api_key) = &self.api_key {
            req = req.header("Authorization", format!("Bearer {api_key}"));
        }

        match req.send().await {
            Ok(res) if res.status() == reqwest::StatusCode::OK => Ok(true),
            Ok(res) if res.status() == reqwest::StatusCode::NOT_FOUND => Ok(false),
            Ok(res) => Err(Error::UnexpectedResponse { status: res.status().as_u16(), body: res.text().await.ok() }),
            Err(res) => Err(Error::Request(res)),
        }
    }
}
