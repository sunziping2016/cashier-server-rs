use super::errors::{ApiError, Result, ApiResult, respond};
use actix_web::{web};
use bson::doc;
use serde::{Serialize, Deserialize};
use crate::api::auth::{Auth, JwtClaims, get_jwt_secret};
use crate::api::app_state::AppState;
use bson::document::ValueAccessError;
use chrono::SubsecRound;

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenAcquiredResponse {
    pub jwt: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AcquireTokenByUsernameRequest {
    pub username: String,
    pub password: String,
}

pub async fn acquire_token_by_username(
    app_data: web::Data<AppState>,
    request: web::Json<AcquireTokenByUsernameRequest>,
    _auth: Auth,
) -> ApiResult<TokenAcquiredResponse> {
    // Verify username and password
    let user = app_data.db.collection(crate::constants::USER_COLLECTION)
        .find_one(doc! {
            "username": &request.username,
        }, mongodb::options::FindOneOptions::builder().projection(doc! {
            "password": 1,
            "blocked": 1,
        }).build())
        .await
        .map_err(|_| ApiError::InternalServerError)?
        .ok_or_else(|| ApiError::WrongUserOrPassword)?;
    let verified = bcrypt::verify(
        &request.password,
        user.get_str("password")
            .map_err(|_| ApiError::InternalServerError)?,
    ).map_err(|_| ApiError::InternalServerError)?;
    if !verified { return Err(ApiError::WrongUserOrPassword); }
    // Verify not blocked
    let blocked = user.get_bool("blocked");
    match blocked {
        Ok(value) => if value { return Err(ApiError::UserBlocked); },
        Err(err) => match err {
            ValueAccessError::NotPresent => (),
            _ => return Err(ApiError::InternalServerError),
        }
    }
    let secret = get_jwt_secret(&app_data.db).await?;
    let uid = user.get_object_id("_id").map_err(|_| ApiError::InternalServerError)?;
    let issued_at = chrono::Utc::now().round_subsecs(0);
    let expires_at = issued_at + chrono::Duration::seconds(crate::constants::JWT_EXPIRE_SECONDS);
    let jti = app_data.db.collection(crate::constants::TOKEN_COLLECTION)
        .insert_one(doc! {
            "user": uid,
            "issuedAt": issued_at,
            "expiresAt": expires_at,
            "acquireMethod": "username",
            "revoked": false,
        }, None)
        .await
        .map_err(|_| ApiError::InternalServerError)?
        .inserted_id;
    let jti = if let bson::Bson::ObjectId(id) = jti { id } else {
        return Err(ApiError::InternalServerError);
    };
    let jwt = jsonwebtoken::encode(&jsonwebtoken::Header::default(), &JwtClaims {
        uid: uid.to_hex(),
        iat: issued_at.timestamp(),
        exp: expires_at.timestamp(),
        jti: jti.to_hex(),
    }, &jsonwebtoken::EncodingKey::from_secret(&secret))
        .map_err(|_| ApiError::InternalServerError)?;
    respond(TokenAcquiredResponse {
        jwt,
    })
}

pub async fn acquire_token_by_email() -> ApiResult<TokenAcquiredResponse> {
    Err(ApiError::NotImplemented { api: "acquire token by email".into() })
}

pub async fn resume_token() -> ApiResult<TokenAcquiredResponse> {
    Err(ApiError::NotImplemented { api: "resume token".into() })
}

pub async fn revoke_token_by_uid() -> Result<web::HttpResponse> {
    Err(ApiError::NotImplemented { api: "revoke token by uid".into() })
}

pub async fn revoke_token_for_me() -> Result<web::HttpResponse> {
    Err(ApiError::NotImplemented { api: "revoke toke for me".into() })
}

pub async fn list_token_by_uid() -> Result<web::HttpResponse> {
    Err(ApiError::NotImplemented { api: "list token by uid".into() })
}

pub async fn list_token_for_me() -> Result<web::HttpResponse> {
    Err(ApiError::NotImplemented { api: "list token for me".into() })
}

pub async fn read_token_by_jti() -> Result<web::HttpResponse> {
    Err(ApiError::NotImplemented { api: "read token by jti".into() })
}

pub async fn revoke_token_by_jti() -> Result<web::HttpResponse> {
    Err(ApiError::NotImplemented { api: "revoke token jti".into() })
}

pub async fn read_token_for_me_by_jti() -> Result<web::HttpResponse> {
    Err(ApiError::NotImplemented { api: "read token for me by jti".into() })
}

pub async fn revoke_token_for_me_by_jti() -> Result<web::HttpResponse> {
    Err(ApiError::NotImplemented { api: "revoke token for me by jti".into() })
}

pub fn token_api(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/tokens")
            .route("/acquire-by-username", web::post().to(acquire_token_by_username))
            .route("/acquire-by-email", web::post().to(acquire_token_by_email))
            .route("/resume", web::post().to(resume_token))
            .service(
                web::scope("/users")
                    .route("/me", web::get().to(list_token_for_me))
                    .route("/me", web::delete().to(revoke_token_for_me))
                    .route("/{uid}", web::get().to(list_token_by_uid))
                    .route("/{uid}", web::delete().to(revoke_token_by_uid))
            )
            .service(
                web::scope("/jwt")
                    .route("/{jti}", web::get().to(read_token_by_jti))
                    .route("/{jti}", web::delete().to(revoke_token_by_jti))
            )
            .service(
                web::scope("/jwt-me")
                    .route("/{jti}", web::get().to(read_token_for_me_by_jti))
                    .route("/{jti}", web::delete().to(revoke_token_for_me_by_jti))
            )
    );
}