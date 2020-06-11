use actix_web::{web};
use bson::doc;
use serde::{Serialize, Deserialize};
use crate::{
    api::{
        extractors::{
            auth::{Auth, JwtClaims, get_jwt_secret},
            json::Json,
        },
        errors::{ApiError, Result, ApiResult, respond},
        app_state::AppState,
        helpers::{serialize_object_id, deserialize_object_id},
    },
    internal_server_error,
};
use bson::document::ValueAccessError;
use chrono::{SubsecRound, Utc};
use std::convert::TryFrom;
use futures::stream::StreamExt;
use validator::Validate;
use validator_derive::Validate;

async fn create_token(
    db: &mongodb::Database,
    uid: &bson::oid::ObjectId,
    acquire_method: &str,
) -> std::result::Result<String, ApiError> {
    let secret = get_jwt_secret(db).await?;
    let issued_at = chrono::Utc::now().round_subsecs(0);
    let expires_at = issued_at + chrono::Duration::seconds(crate::constants::JWT_EXPIRE_SECONDS);
    let jti = db.collection(crate::constants::TOKEN_COLLECTION)
        .insert_one(doc! {
            "user": uid,
            "issuedAt": issued_at,
            "expiresAt": expires_at,
            "acquireMethod": acquire_method,
            "revoked": false,
        }, None)
        .await
        .map_err(|e| internal_server_error!(e))?
        .inserted_id;
    let jti = if let bson::Bson::ObjectId(id) = jti { id } else {
        return Err(internal_server_error!());
    };
    Ok(jsonwebtoken::encode(&jsonwebtoken::Header::default(), &JwtClaims {
        uid: uid.to_hex(),
        iat: issued_at.timestamp(),
        exp: expires_at.timestamp(),
        jti: jti.to_hex(),
    }, &jsonwebtoken::EncodingKey::from_secret(&secret))
        .map_err(|e| internal_server_error!(e))?)
}

async fn create_token_for_user(
    db: &mongodb::Database,
    user: &bson::Document,
    password: &str,
    acquire_method: &str,
) -> std::result::Result<String, ApiError> {
    let verified = bcrypt::verify(
        password,
        user.get_str("password")
            .map_err(|e| internal_server_error!(e))?,
    ).map_err(|e| internal_server_error!(e))?;
    if !verified { return Err(ApiError::WrongUserOrPassword); }
    // Verify not blocked
    let blocked = user.get_bool("blocked");
    match blocked {
        Ok(value) => if value { return Err(ApiError::UserBlocked); },
        Err(err) => match err {
            ValueAccessError::NotPresent => (),
            _ => return Err(internal_server_error!()),
        }
    }
    create_token(
        db,
        user.get_object_id("_id").map_err(|e| internal_server_error!(e))?,
        acquire_method,
    ).await
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenAcquiredResponse {
    pub jwt: String,
}

#[derive(Debug, Validate, Deserialize, Serialize)]
pub struct AcquireTokenByUsernameRequest {
    #[validate(regex = "crate::constants::USERNAME_REGEX")]
    pub username: String,
    #[validate(regex = "crate::constants::PASSWORD_REGEX")]
    pub password: String,
}

pub async fn acquire_token_by_username(
    app_data: web::Data<AppState>,
    request: Json<AcquireTokenByUsernameRequest>,
    auth: Auth,
) -> ApiResult<TokenAcquiredResponse> {
    auth.try_permission("token", "acquire-by-username")?;
    let user = app_data.db.collection(crate::constants::USER_COLLECTION)
        .find_one(doc! {
            "username": &request.username,
            "deleted": false,
        }, mongodb::options::FindOneOptions::builder().projection(doc! {
            "password": 1,
            "blocked": 1,
        }).build())
        .await
        .map_err(|e| internal_server_error!(e))?
        .ok_or_else(|| ApiError::WrongUserOrPassword)?;
    respond(TokenAcquiredResponse {
        jwt: create_token_for_user(&app_data.db, &user, &request.password, "username").await?,
    })
}

#[derive(Debug, Validate, Deserialize, Serialize)]
pub struct AcquireTokenByEmailRequest {
    #[validate(email)]
    pub email: String,
    #[validate(regex = "crate::constants::PASSWORD_REGEX")]
    pub password: String,
}

pub async fn acquire_token_by_email(
    app_data: web::Data<AppState>,
    request: Json<AcquireTokenByEmailRequest>,
    auth: Auth,
) -> ApiResult<TokenAcquiredResponse> {
    auth.try_permission("token", "acquire-by-email")?;
    let user = app_data.db.collection(crate::constants::USER_COLLECTION)
        .find_one(doc! {
            "email": &request.email,
            "deleted": false,
        }, mongodb::options::FindOneOptions::builder().projection(doc! {
            "password": 1,
            "blocked": 1,
        }).build())
        .await
        .map_err(|e| internal_server_error!(e))?
        .ok_or_else(|| ApiError::WrongUserOrPassword)?;
    respond(TokenAcquiredResponse {
        jwt: create_token_for_user(&app_data.db, &user, &request.password, "email").await?,
    })
}

pub async fn resume_token(
    app_data: web::Data<AppState>,
    auth: Auth,
) -> ApiResult<TokenAcquiredResponse> {
    auth.try_permission("token", "resume")?;
    respond(TokenAcquiredResponse {
        jwt: create_token(
            &app_data.db,
            &auth.jwt.ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid,
            "resume").await?,
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    #[serde(serialize_with = "serialize_object_id", deserialize_with = "deserialize_object_id")]
    pub id: bson::oid::ObjectId,
    #[serde(serialize_with = "serialize_object_id", deserialize_with = "deserialize_object_id")]
    pub user: bson::oid::ObjectId,
    #[serde(rename = "issuedAt")]
    pub issued_at: chrono::DateTime<Utc>,
    #[serde(rename = "expiresAt")]
    pub expires_at: chrono::DateTime<Utc>,
    #[serde(rename = "acquireMethod")]
    pub acquire_method: String,
}

impl TryFrom<bson::Document> for Token {
    type Error = bson::document::ValueAccessError;

    fn try_from(value: bson::Document) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            id: value.get_object_id("_id")?.clone(),
            user: value.get_object_id("user")?.clone(),
            issued_at: value.get_datetime("issuedAt")?.clone(),
            expires_at: value.get_datetime("expiresAt")?.clone(),
            acquire_method: value.get_str("acquireMethod")?.to_owned(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenListResponse {
    pub tokens: Vec<Token>,
}

pub async fn list_token_for_me(
    app_data: web::Data<AppState>,
    auth: Auth,
) -> ApiResult<TokenListResponse> {
    auth.try_permission("token", "list-self")?;
    let uid = &auth.jwt.ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    let mut cursor = app_data.db.collection(crate::constants::TOKEN_COLLECTION)
        .find(doc! {
            "user": uid,
            "revoked": false,
        }, None)
        .await
        .map_err(|e| internal_server_error!(e))?;
    let mut tokens = Vec::new();
    while let Some(doc) = cursor.next().await {
        tokens.push(
            Token::try_from(doc.map_err(|e| internal_server_error!(e))?)
                .map_err(|e| internal_server_error!(e))?
        );
    }
    respond(TokenListResponse {
        tokens
    })
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenRevokeResponse {
    count: i64,
}

pub async fn revoke_token_for_me(
    app_data: web::Data<AppState>,
    auth: Auth,
) -> ApiResult<TokenRevokeResponse> {
    auth.try_permission("token", "revoke-self")?;
    let uid = &auth.jwt.ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    let result = app_data.db.collection(crate::constants::TOKEN_COLLECTION)
        .update_many(doc! {
            "user": uid,
            "revoked": false,
        }, doc! {
            "$set": {
                "revoked": true,
            },
        }, None)
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(TokenRevokeResponse {
        count: result.modified_count
    })
}

pub async fn list_token_by_uid() -> Result<web::HttpResponse> {
    Err(ApiError::NotImplemented { api: "list token by uid".into() })
}

pub async fn revoke_token_by_uid() -> Result<web::HttpResponse> {
    Err(ApiError::NotImplemented { api: "revoke token by uid".into() })
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

pub fn tokens_api(cfg: &mut web::ServiceConfig) {
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
                web::scope("/my-jwt")
                    .route("/{jti}", web::get().to(read_token_for_me_by_jti))
                    .route("/{jti}", web::delete().to(revoke_token_for_me_by_jti))
            )
    );
}