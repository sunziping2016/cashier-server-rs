use actix_web::{web, error::ResponseError, HttpResponse};
use err_derive::Error;
use serde::{Deserialize, Serialize};
use validator::ValidationErrors;

#[derive(Debug, Serialize, Clone)]
pub struct ValidationError {
    field: String,
    message: Vec<String>,
}

#[macro_export]
macro_rules! internal_server_error {
    () => {
        ApiError::InternalServerError {
            file: file!(),
            line: line!(),
            message: None,
        }
    };
    ( $e: expr ) => {
        ApiError::InternalServerError {
            file: file!(),
            line: line!(),
            message: Some(format!("{:#?}", $e)),
        }
    }
}


#[derive(Debug, Error, Serialize, Clone)]
#[serde(tag = "type")]
pub enum ApiError {
    #[error(display = "{} not implemented", _0)]
    NotImplemented {
        api: String,
    },
    #[error(display = "internal server error")]
    InternalServerError {
        #[serde(skip_serializing)]
        file: &'static str,
        #[serde(skip_serializing)]
        line: u32,
        #[serde(skip_serializing)]
        message: Option<String>,
    },
    #[error(display = "user does not exist or wrong password")]
    WrongUserOrPassword,
    #[error(display = "user is blocked")]
    UserBlocked,
    #[error(display = "invalid authorization header")]
    InvalidAuthorizationHeader,
    #[error(display = "invalid token causing by {}", error)]
    InvalidToken {
        error: String,
    },
    #[error(display = "permission denied, requires {} {} permission", action, subject)]
    PermissionDenied {
        subject: String,
        action: String,
    },
    #[error(display = "missing authorization header")]
    MissingAuthorizationHeader,
    #[error(display = "attempt to create a user with more roles than creator's")]
    AttemptToElevateRole,
    #[error(display = "duplicated user with same {} field", field)]
    DuplicatedUser {
        field: String,
    },
    #[error(display = "invalid json payload causing by {}", error)]
    JsonPayloadError {
        error: String,
    },
    #[error(display = "validation failed")]
    ValidationError {
        errors: Vec<ValidationError>,
    },
}

impl From<ValidationErrors> for ApiError {
    fn from(errors: ValidationErrors) -> Self {
        ApiError::ValidationError {
            errors: errors.field_errors()
                .iter()
                .map(|(k,
                          v)| ValidationError {
                    field: (*k).into(),
                    message: v.iter()
                        .map(|err| err.message.as_ref()
                            .map(|msg| String::from(msg.to_owned())))
                        .filter(Option::is_some)
                        .map(|x| x.unwrap())
                        .collect(),
                })
                .collect()
        }
    }
}

#[derive(Debug, Serialize)]
struct ApiErrorWrapper {
    code: u32,
    message: String,
    data: ApiError,
}

impl From<ApiError> for ApiErrorWrapper {
    fn from(error: ApiError) -> Self {
        let code = match &error {
            ApiError::NotImplemented { .. } => 501,
            ApiError::InternalServerError { .. } => 500,
            ApiError::WrongUserOrPassword
            | ApiError::UserBlocked
            | ApiError::InvalidAuthorizationHeader
            | ApiError::InvalidToken { .. } => 401,
            ApiError::PermissionDenied { .. }
            | ApiError::AttemptToElevateRole => 403,
            ApiError::MissingAuthorizationHeader => 400,
            ApiError::DuplicatedUser { .. } => 409,
            ApiError::JsonPayloadError { .. }
            | ApiError::ValidationError { .. } => 400,
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
            ApiError::NotImplemented { .. } =>
                HttpResponse::NotImplemented().json(ApiErrorWrapper::from(self.clone())),
            ApiError::InternalServerError { .. } =>
                HttpResponse::InternalServerError().json(ApiErrorWrapper::from(self.clone())),
            ApiError::WrongUserOrPassword
            | ApiError::UserBlocked
            | ApiError::InvalidAuthorizationHeader
            | ApiError::InvalidToken { .. } =>
                HttpResponse::Unauthorized().json(ApiErrorWrapper::from(self.clone())),
            ApiError::PermissionDenied { .. }
            | ApiError::AttemptToElevateRole =>
                HttpResponse::Forbidden().json(ApiErrorWrapper::from(self.clone())),
            ApiError::MissingAuthorizationHeader =>
                HttpResponse::BadRequest().json(ApiErrorWrapper::from(self.clone())),
            ApiError::DuplicatedUser { .. } =>
                HttpResponse::Conflict().json(ApiErrorWrapper::from(self.clone())),
            ApiError::JsonPayloadError { .. }
            | ApiError::ValidationError { .. } =>
                HttpResponse::BadRequest().json(ApiErrorWrapper::from(self.clone())),
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

