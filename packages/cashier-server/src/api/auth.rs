use actix_web::{web, FromRequest};
use chrono::{Utc, NaiveDateTime};
use futures::future::{BoxFuture, FutureExt};
use crate::api::errors::ApiError;
use serde::{Serialize, Deserialize};
use crate::api::app_state::AppState;
use bson::doc;
use jsonwebtoken::{decode, DecodingKey, Validation};
use std::convert::TryFrom;

#[derive(Debug)]
pub struct Jwt {
    pub jti: bson::oid::ObjectId,
    pub uid: bson::oid::ObjectId,
    pub issued_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
    pub acquire_method: String,
}

#[derive(Debug)]
pub struct Permission {
    pub id: bson::oid::ObjectId,
    pub subject: String,
    pub action: String,
    pub display_name: String,
    pub description: String,
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug)]
pub struct Role {
    pub id: bson::oid::ObjectId,
    pub name: String,
    pub permissions: Vec<bson::oid::ObjectId>,
    pub display_name: String,
    pub description: String,
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug)]
pub struct User {
    pub id: bson::oid::ObjectId,
    pub username: String,
    pub roles: Vec<bson::oid::ObjectId>,
    pub email: Option<String>,
    pub nickname: Option<String>,
    pub avatar: Option<String>,
    pub avatar128: Option<String>,
    pub blocked: bool,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

#[derive(Debug)]
pub struct Auth {
    pub jwt: Option<Jwt>,
    // pub user: Option<User>,
    pub roles: Vec<Role>,
    // pub permissions: Vec<Permission>,
}

impl TryFrom<bson::Document> for Role {
    type Error = bson::document::ValueAccessError;

    fn try_from(value: bson::Document) -> Result<Self, Self::Error> {
        let mut permissions = Vec::new();
        for permission in value.get_array("permissions")? {
            permissions.push(if let bson::Bson::ObjectId(id) = permission {
                id.clone() } else { return Err(bson::document::ValueAccessError::UnexpectedType) })
        }
        Ok(Self {
            id: value.get_object_id("_id")?.clone(),
            name: value.get_str("name")?.to_owned(),
            permissions,
            display_name: value.get_str("displayName")?.to_owned(),
            description: value.get_str("description")?.to_owned(),
            created_at: value.get_datetime("createdAt")?.clone(),
            expires_at: value.get_datetime("expiresAt")?.clone(),
        })
    }
}

impl FromRequest for Auth {
    type Error = ApiError;
    type Future = BoxFuture<'static, Result<Self, ApiError>>;
    type Config = ();

    fn from_request(req: &web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let app_data = if let Some(st) = req.app_data::<web::Data<AppState>>() {
            st.clone()
        } else {
            return futures::future::err(ApiError::InternalServerError).boxed();
        };
        let auth = if let Some(header) = req.headers().get("Authorization") {
            let header = if let Ok(result) = header.to_str() { result } else {
                return futures::future::err(ApiError::InvalidAuthorizationHeader).boxed()
            };
            let fragments: Vec<&str> = header.split_ascii_whitespace().collect();
            if fragments.len() == 2 && fragments[0] == "Bearer" {
                Some(String::from(fragments[1]))
            } else {
                return futures::future::err(ApiError::InvalidAuthorizationHeader).boxed()
            }
        } else { None };
        async move {
            let jwt = if let Some(token) = auth {
                let secret = get_jwt_secret(&app_data.db).await?;
                let claims = decode::<JwtClaims>(&token, &DecodingKey::from_secret(&secret), &Validation::default())
                    .map_err(|err| ApiError::InvalidToken { error: format!("{:?}", err.into_kind())})?.claims;
                let jti = bson::oid::ObjectId::with_string(&claims.jti).map_err(|_| ApiError::InternalServerError)?;
                let uid = bson::oid::ObjectId::with_string(&claims.uid).map_err(|_| ApiError::InternalServerError)?;
                let jwt_doc = app_data.db.collection(crate::constants::TOKEN_COLLECTION)
                    .find_one(doc! {
                        "_id": &jti,
                        "revoked": false,
                    }, mongodb::options::FindOneOptions::builder().projection(doc! {
                        "_id": 0,
                        "acquireMethod": 1,
                    }).build())
                    .await
                    .map_err(|_| ApiError::InternalServerError)?
                    .ok_or_else(|| ApiError::TokenRevoked)?;
                let acquire_method = jwt_doc.get_str("acquireMethod")
                    .map_err(|_| ApiError::InternalServerError)?
                    .to_owned();
                Some(Jwt {
                    jti,
                    uid,
                    issued_at: chrono::DateTime::from_utc(NaiveDateTime::from_timestamp(claims.iat, 0), Utc),
                    expires_at: chrono::DateTime::from_utc(NaiveDateTime::from_timestamp(claims.exp, 0), Utc),
                    acquire_method,
                })
            } else { None };
            let mut roles: Vec<Role> = Vec::new();
            // Add default role
            if let Some(default_role) = app_data.db.collection(crate::constants::ROLE_COLLECTION)
                .find_one(doc! {
                    "name": "default",
                    "deleted": false,
                }, None)
                .await
                .map_err(|_| ApiError::InternalServerError)? {
                roles.push(Role::try_from(default_role).map_err(|_| ApiError::InternalServerError)?);
            }
            if let Some(Jwt {ref uid, ..}) = jwt {
                // TODO
            }
            Ok(Auth {
                jwt,
                roles
            })
        }.boxed()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub uid: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

pub async fn get_jwt_secret(db: &mongodb::Database) -> std::result::Result<Vec<u8>, ApiError> {
    Ok(db.collection(crate::constants::GLOBAL_SETTINGS_COLLECTION)
        .find_one(doc! {}, mongodb::options::FindOneOptions::builder().projection(doc! {
            "jwtSecret": 1,
            "_id": 0,
        }).build())
        .await
        .map_err(|_| ApiError::InternalServerError)?
        .ok_or_else(|| ApiError::InternalServerError)?
        .get_binary_generic("jwtSecret")
        .map_err(|_| ApiError::InternalServerError)?
        .clone())
}