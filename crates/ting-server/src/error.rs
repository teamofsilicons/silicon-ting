use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, Clone)]
pub struct Error {
    pub status: u16,
    pub body: Value,
}
impl Error {
    pub fn new(
        status: u16,
        code: &str,
        message: impl Into<String>,
        hint: impl Into<String>,
    ) -> Self {
        Self {
            status,
            body: json!({"error":{"code":code,"message":message.into(),"hint":hint.into(),"retryable":status==429 || status==503}}),
        }
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(
            400,
            "invalid_input",
            message,
            "Correct the request using the v1 contract and retry.",
        )
    }
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(
            503,
            "dependency_unavailable",
            message,
            "Try again when the dependency is available. Obtain a fresh proof for app requests.",
        )
    }
    pub fn not_found() -> Self {
        Self::new(
            404,
            "not_found",
            "The resource was not found.",
            "Check its ID and the selected org.",
        )
    }
    pub fn details(mut self, details: Value) -> Self {
        self.body["error"]["details"] = details;
        self
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.body["error"]["code"])
    }
}
impl std::error::Error for Error {}
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        tracing::error!(error=%e,"database operation failed");
        Self::new(
            503,
            "storage_unavailable",
            "Durable storage is unavailable.",
            "Retry later; do not assume a mutation succeeded.",
        )
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::invalid("The request is not valid JSON for this operation.")
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (
            StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Json(self.body),
        )
            .into_response()
    }
}
