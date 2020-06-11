use actix_web::{web, HttpRequest};
use bson::doc;
use crate::{
    api::{
        extractors::{
            auth::Auth,
            json::Json,
        },
        errors::{ApiError, ApiResult, respond},
        app_state::AppState,
        helpers::{serialize_object_id, deserialize_object_id},
    },
    internal_server_error,
};
use serde::{Serialize, Deserialize};
use validator::Validate;
use validator_derive::Validate;

#[derive(Debug, Validate, Deserialize, Serialize)]
pub struct CreateUserRequest {
    #[validate(regex = "crate::constants::USERNAME_REGEX")]
    pub username: String,
    #[validate(regex = "crate::constants::PASSWORD_REGEX")]
    pub password: String,
    // roles must be a subset of creator's roles
    pub roles: Vec<String>,
    #[validate(email)]
    pub email: Option<String>,
    #[validate(regex = "crate::constants::NICKNAME_REGEX")]
    pub nickname: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateUserResponse {
    #[serde(serialize_with = "serialize_object_id", deserialize_with = "deserialize_object_id")]
    pub id: bson::oid::ObjectId,
}

async fn create_user(
    app_data: web::Data<AppState>,
    request: Json<CreateUserRequest>,
    auth: Auth,
) -> ApiResult<CreateUserResponse> {
    auth.try_permission("user", "create")?;
    // TODO: check username and email duplication
    let query = if let Some(ref email) = request.email {
        doc! {
            "$or": [
                 {"username": &request.username},
                 {"email": email},
            ],
            "deleted": false,
        }
    } else {
        doc! {
            "username": &request.username,
            "deleted": false,
        }
    };
    if let Some(duplicated_user) = app_data.db.collection(crate::constants::USER_COLLECTION)
        .find_one(query, None)
        .await
        .map_err(|e| internal_server_error!(e))? {
        return Err(ApiError::DuplicatedUser {
            field: if duplicated_user.get_str("username")
                .map_err(|e| internal_server_error!(e))? == &request.username {
                "username".into()
            } else { "email".into() }
        });
    }
    let roles = request.roles.iter()
        .map(|role| auth.roles.iter()
            .find(|auth_role| auth_role.name == **role)
            .ok_or_else(|| ApiError::AttemptToElevateRole)
            .map(|role| &role.id))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let current = chrono::Utc::now();
    let password = bcrypt::hash(&request.password, crate::constants::BCRYPT_COST)
        .map_err(|e| internal_server_error!(e))?;
    let mut document = doc! {
        "username": &request.username,
        "password": &password,
        "roles": &roles,
        "createdAt": &current,
        "updatedAt": &current,
        "deleted": false,
    };
    if let Some(ref email) = request.email {
        document.insert("email", email);
    }
    if let Some(ref nickname) = request.nickname {
        document.insert("nickname", nickname);
    }
    let id = app_data.db.collection(crate::constants::USER_COLLECTION)
        .insert_one(document, None)
        .await
        .map_err(|e| internal_server_error!(e))?
        .inserted_id;
    let id = if let bson::Bson::ObjectId(id) = id { id } else {
        return Err(internal_server_error!());
    };
    respond(CreateUserResponse {
        id,
    })
}

async fn index(_req: HttpRequest) -> &'static str {
    "Hello world!"
}

pub fn users_api(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("users")
            .route("/default/permissions", web::get().to(index))
            .service(
                web::scope("/public")
                    .route("/{id}", web::get().to(index))
                    .route("/", web::get().to(index))
            )
            .service(
                web::scope("/me")
                    .route("/password", web::post().to(index))
                    .route("/avatar", web::post().to(index))
                    .route("/permissions", web::get().to(index))
                    .route("", web::get().to(index))
                    .route("", web::patch().to(index))
                    .route("", web::delete().to(index))
            )
            .service(
                web::scope("/{id}")
                    .route("/password", web::post().to(index))
                    .route("/avatar", web::post().to(index))
                    .route("/permissions", web::get().to(index))
                    .route("", web::get().to(index))
                    .route("", web::patch().to(index))
                    .route("", web::delete().to(index))
            )
            .route("", web::post().to(create_user))
            .route("", web::get().to(index))
    );
}