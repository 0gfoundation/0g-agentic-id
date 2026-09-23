//! HTTP error mapping.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    /// Extra machine-readable fields merged into the TOP LEVEL of the error
    /// body, beside `error`. Used where a client needs a value to act on
    /// rather than prose — the settings compare-and-swap returns the current
    /// `version` here so a client can rebase without parsing the message.
    pub details: Option<serde_json::Value>,
}

impl ApiError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: msg.into(),
            details: None,
        }
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: msg.into(),
            details: None,
        }
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: msg.into(),
            details: None,
        }
    }

    /// 403 — authenticated but not permitted. The contract-mode clone policy
    /// gate uses this: the buyer's signature verified, the on-chain
    /// authorizer (or its pre-check) said no.
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: msg.into(),
            details: None,
        }
    }

    /// 409 — the write is authentic but would clobber something it is not
    /// allowed to. Two users: the settings compare-and-swap (stale
    /// `base_version`, with the current version in `details` so the client
    /// can rebase) and the container-seeded settings path (a seed may fill a
    /// never-configured row, never replace an owner's document).
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "conflict",
            message: msg.into(),
            details: None,
        }
    }

    /// Attach machine-readable fields to an error body.
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// 402 with a stable code — the deploy-edge preflight uses these so
    /// clients can route "not acked" / "not funded" to the right fix-up
    /// UI instead of parsing prose.
    pub fn precondition(code: &'static str, msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::PAYMENT_REQUIRED,
            code,
            message: msg.into(),
            details: None,
        }
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
            message: msg.into(),
            details: None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({
            "error": {
                "code": self.code,
                "message": self.message,
            }
        });
        if let (Some(serde_json::Value::Object(extra)), Some(obj)) =
            (self.details, body.as_object_mut())
        {
            obj.extend(extra);
        }
        (self.status, Json(body)).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!(error = ?e, "unhandled error");
        ApiError::internal(e.to_string())
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
