use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("API returned unexpected response code: {status}")]
    UnexpectedResponse {
        status: u16,
        body: Option<String>,
    },
    #[error("API request failed: {0}")]
    Request(reqwest::Error),
}
