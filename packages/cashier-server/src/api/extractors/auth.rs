use actix_web::{web, FromRequest};
use chrono::{Utc, NaiveDateTime};
use futures::{
    future::{BoxFuture, FutureExt},
    stream::StreamExt,
};
use crate::{
    internal_server_error,
    api::{
        errors::ApiError,
        app_state::AppState,
    }
};
use serde::{Serialize, Deserialize};
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
    pub updated_at: chrono::DateTime<Utc>,
}

#[derive(Debug)]
pub struct Role {
    pub id: bson::oid::ObjectId,
    pub name: String,
    pub permissions: Vec<bson::oid::ObjectId>,
    pub display_name: String,
    pub description: String,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
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

impl TryFrom<bson::Document> for Permission {
    type Error = bson::document::ValueAccessError;

    fn try_from(value: bson::Document) -> Result<Self, Self::Error> {
        println!("Permission {:?}", value);
        Ok(Self {
            id: value.get_object_id("_id")?.clone(),
            subject: value.get_str("subject")?.to_owned(),
            action: value.get_str("action")?.to_owned(),
            display_name: value.get_str("displayName")?.to_owned(),
            description: value.get_str("description")?.to_owned(),
            created_at: value.get_datetime("createdAt")?.clone(),
            updated_at: value.get_datetime("updatedAt")?.clone(),
        })
    }
}

impl TryFrom<bson::Document> for Role {
    type Error = bson::document::ValueAccessError;

    //noinspection DuplicatedCode
    fn try_from(value: bson::Document) -> Result<Self, Self::Error> {
        println!("Role {:?}", value);
        Ok(Self {
            id: value.get_object_id("_id")?.clone(),
            name: value.get_str("name")?.to_owned(),
            permissions: value.get_array("permissions")?.iter()
                .map(|permission| if let bson::Bson::ObjectId(id) = permission {
                    Ok(id.clone())
                } else { Err(bson::document::ValueAccessError::UnexpectedType) })
                .collect::<Result<Vec<_>, _>>()?,
            display_name: value.get_str("displayName")?.to_owned(),
            description: value.get_str("description")?.to_owned(),
            created_at: value.get_datetime("createdAt")?.clone(),
            updated_at: value.get_datetime("updatedAt")?.clone(),
        })
    }
}

impl TryFrom<bson::Document> for User {
    type Error = bson::document::ValueAccessError;

    //noinspection ALL
    fn try_from(value: bson::Document) -> Result<Self, Self::Error> {
        println!("User {:?}", value);
        Ok(Self {
            id: value.get_object_id("_id")?.clone(),
            username: value.get_str("username")?.to_owned(),
            roles: value.get_array("roles")?.iter()
                .map(|role| if let bson::Bson::ObjectId(id) = role {
                    Ok(id.clone())
                } else { Err(bson::document::ValueAccessError::UnexpectedType) })
                .collect::<Result<Vec<_>, _>>()?,
            email: value.get_str("email").ok().map(String::from),
            nickname: value.get_str("nickname").ok().map(String::from),
            avatar: value.get_str("avatar").ok().map(String::from),
            avatar128: value.get_str("avatar128").ok().map(String::from),
            blocked: value.get_bool("blocked").unwrap_or_else(|_| false),
            created_at: value.get_datetime("createdAt")?.clone(),
            updated_at: value.get_datetime("updatedAt")?.clone(),
        })
    }
}

#[derive(Debug)]
pub struct Auth {
    pub jwt: Option<Jwt>,
    pub user: Option<User>,
    pub roles: Vec<Role>,
    pub permissions: Vec<Permission>,
}

impl Auth {
    pub fn has_permission(&self, subject: &str, action: &str) -> bool {
        self.permissions.iter()
            .find(|permission| permission.subject == subject && permission.action == action)
            .is_some()
    }

    pub fn try_permission(&self, subject: &str, action: &str) -> std::result::Result<(), ApiError> {
        if self.has_permission(subject, action) { Ok(()) } else {
            Err(ApiError::PermissionDenied {
                subject: subject.into(),
                action: action.into()
            })
        }
    }
}

impl FromRequest for Auth {
    type Error = ApiError;
    type Future = BoxFuture<'static, Result<Self, ApiError>>;
    type Config = ();

    fn from_request(req: &web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        // Fetch app data
        let app_data = if let Some(st) = req.app_data::<web::Data<AppState>>() {
            st.clone()
        } else {
            return futures::future::err(internal_server_error!()).boxed();
        };
        // Fetch header
        let auth = if let Some(header) = req.headers().get("Authorization") {
            let header = if let Ok(result) = header.to_str() { result } else {
                return futures::future::err(ApiError::InvalidAuthorizationHeader).boxed();
            };
            let fragments: Vec<&str> = header.split_ascii_whitespace().collect();
            if fragments.len() == 2 && fragments[0] == "Bearer" {
                Some(String::from(fragments[1]))
            } else {
                return futures::future::err(ApiError::InvalidAuthorizationHeader).boxed();
            }
        } else { None };
        async move {
            // Examine JWT
            let jwt = if let Some(token) = auth {
                let secret = get_jwt_secret(&app_data.db).await?;
                let claims = decode::<JwtClaims>(&token, &DecodingKey::from_secret(&secret), &Validation::default())
                    .map_err(|err| ApiError::InvalidToken { error: format!("{:?}", err.into_kind()) })?.claims;
                let jti = bson::oid::ObjectId::with_string(&claims.jti).map_err(|e| internal_server_error!(e))?;
                let uid = bson::oid::ObjectId::with_string(&claims.uid).map_err(|e| internal_server_error!(e))?;
                let jwt_doc = app_data.db.collection(crate::constants::TOKEN_COLLECTION)
                    .find_one(doc! {
                        "_id": &jti,
                        "revoked": false,
                    }, mongodb::options::FindOneOptions::builder().projection(doc! {
                        "_id": 0,
                        "acquireMethod": 1,
                    }).build())
                    .await
                    .map_err(|e| internal_server_error!(e))?
                    .ok_or_else(|| ApiError::InvalidToken { error: "TokenRevoked".into() })?;
                println!("Jwt {:#?}", jwt_doc);
                let acquire_method = jwt_doc.get_str("acquireMethod")
                    .map_err(|e| internal_server_error!(e))?
                    .to_owned();
                Some(Jwt {
                    jti,
                    uid,
                    issued_at: chrono::DateTime::from_utc(NaiveDateTime::from_timestamp(claims.iat, 0), Utc),
                    expires_at: chrono::DateTime::from_utc(NaiveDateTime::from_timestamp(claims.exp, 0), Utc),
                    acquire_method,
                })
            } else { None };
            // Fetch and check users
            let user = if let Some(Jwt { ref uid, .. }) = jwt {
                Some(User::try_from(app_data.db.collection(crate::constants::USER_COLLECTION)
                    .find_one(doc! {
                        "_id": uid,
                        "deleted": false,
                    }, None)
                    .await
                    .map_err(|e| internal_server_error!(e))?
                    .ok_or_else(|| ApiError::InvalidToken { error: "InvalidUser".into() })?
                ).map_err(|e| internal_server_error!(e))?)
            } else { None };
            if let Some(User { blocked, .. }) = user {
                if blocked {
                    return Err(ApiError::InvalidToken { error: "UserBlocked".into() });
                }
            }
            // Fetch Default Role
            let mut roles: Vec<Role> = Vec::new();
            if let Some(default_role) = app_data.db.collection(crate::constants::ROLE_COLLECTION)
                .find_one(doc! {
                    "name": "default",
                    "deleted": false,
                }, None)
                .await
                .map_err(|e| internal_server_error!(e))? {
                roles.push(Role::try_from(default_role).map_err(|e| internal_server_error!(e))?);
            }
            // Fetch roles
            if let Some(User { roles: ref role_ids, .. }) = user {
                if !role_ids.is_empty() {
                    let mut cursor = app_data.db.collection(crate::constants::ROLE_COLLECTION)
                        .find(doc! {
                        "_id": { "$in": role_ids },
                        "deleted": false,
                    }, None)
                        .await
                        .map_err(|e| internal_server_error!(e))?;
                    while let Some(doc) = cursor.next().await {
                        roles.push(
                            Role::try_from(doc.map_err(|e| internal_server_error!(e))?)
                                .map_err(|e| internal_server_error!(e))?
                        );
                    }
                }
            }
            // Fetch permissions
            let mut permission_ids: Vec<_> = roles.iter()
                .flat_map(|role| role.permissions.iter())
                .collect();
            permission_ids.sort();
            permission_ids.dedup();
            let mut permissions: Vec<Permission> = Vec::new();
            if !permission_ids.is_empty() {
                let mut cursor = app_data.db.collection(crate::constants::PERMISSION_COLLECTION)
                    .find(doc! {
                        "_id": { "$in": permission_ids },
                        "deleted": false,
                    }, None)
                    .await
                    .map_err(|e| internal_server_error!(e))?;
                while let Some(doc) = cursor.next().await {
                    permissions.push(
                        Permission::try_from(doc.map_err(|e| internal_server_error!(e))?)
                            .map_err(|e| internal_server_error!(e))?
                    );
                }
            }
            Ok(Auth {
                jwt,
                user,
                roles,
                permissions,
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
    let doc = db.collection(crate::constants::GLOBAL_SETTINGS_COLLECTION)
        .find_one(doc! {}, mongodb::options::FindOneOptions::builder().projection(doc! {
            "jwtSecret": 1,
            "_id": 0,
        }).build())
        .await
        .map_err(|e| internal_server_error!(e))?
        .ok_or_else(|| internal_server_error!())?;
    println!("Settings {:#?}", doc);
    Ok(doc
        .get_binary_generic("jwtSecret")
        .map_err(|e| internal_server_error!(e))?
        .clone())
}