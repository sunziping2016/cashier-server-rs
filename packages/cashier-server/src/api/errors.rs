use actix_web::{web, error::ResponseError, HttpResponse};
use err_derive::Error;
use serde::{Deserialize, Serialize};

#[derive(Debug, Error, Deserialize, Serialize, Clone)]
#[serde(tag = "type")]
pub enum ApiError {
    #[error(display = "{} not implemented", _0)]
    NotImplemented {
        api: String,
    },
    #[error(display = "internal server error")]
    InternalServerError,
    #[error(display = "user does not exist or wrong password")]
    WrongUserOrPassword,
    #[error(display = "user is blocked")]
    UserBlocked,
    #[error(display = "invalid authorization header")]
    InvalidAuthorizationHeader,
    #[error(display = "token revoked")]
    TokenRevoked,
    #[error(display = "invalid token causing by {}", error)]
    InvalidToken {
        error: String,
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct ApiErrorWrapper {
    code: u32,
    message: String,
    data: ApiError,
}

impl From<ApiError> for ApiErrorWrapper {
    fn from(error: ApiError) -> Self {
        let code = match &error {
            ApiError::NotImplemented {..} => 501,
            ApiError::InternalServerError => 500,
            ApiError::WrongUserOrPassword
            | ApiError::UserBlocked
            | ApiError::InvalidAuthorizationHeader
            | ApiError::TokenRevoked
            | ApiError::InvalidToken {..} => 401,
        };
        ApiErrorWrapper {
            code,
            message: format!("{}", error),
            data: error,
        }
    }
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ApiError::NotImplemented {..} =>
                HttpResponse::NotImplemented().json(ApiErrorWrapper::from(self.clone())),
            ApiError::InternalServerError =>
                HttpResponse::InternalServerError().json(ApiErrorWrapper::from(self.clone())),
            ApiError::WrongUserOrPassword
            | ApiError::UserBlocked
            | ApiError::InvalidAuthorizationHeader
            | ApiError::TokenRevoked
            | ApiError::InvalidToken {..} =>
                HttpResponse::Unauthorized().json(ApiErrorWrapper::from(self.clone())),
        }
    }
}

pub type Result<T> = std::result::Result<T, ApiError>;
pub type ApiResult<T> = Result<web::Json<ApiResultWrapper<T>>>;

#[derive(Debug, Deserialize, Serialize)]
pub struct ApiResultWrapper<T: Serialize> {
    code: u32,
    message: String,
    data: T,
}

impl<T: Serialize> From<T> for ApiResultWrapper<T> {
    fn from(data: T) -> Self {
        ApiResultWrapper {
            code: 200,
            message: "okay".into(),
            data,
        }
    }
}

pub fn respond<T: Serialize>(data: T) -> ApiResult<T> {
    Ok(web::Json(data.into()))
}

