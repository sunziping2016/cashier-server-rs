use crate::config::InitConfig;
use crate::constants::{
    PERMISSION_COLLECTION, ROLE_COLLECTION, USER_COLLECTION, TOKEN_COLLECTION,
    GLOBAL_SETTINGS_COLLECTION,
    JWT_SECRET_LENGTH, BCRYPT_COST};
use super::predefined;
use bson::{doc, bson};
use err_derive::Error;
use log::info;
use mongodb::{Client, options::ClientOptions};

#[derive(Debug, Error)]
pub enum InitError {
    #[error(display = "{}", _0)]
    Db(#[error(source)] #[error(from)] mongodb::error::Error),
    #[error(display = "{}", _0)]
    Bson(#[error(source)] #[error(from)] bson::document::ValueAccessError),
    #[error(display = "failed to create indexes on {}", collection)]
    CreateIndexError {
        collection: String,
    },
    #[error(display = "failed to create role {} with permission {} {}",
            role_name, permission_action, permission_subject)]
    InvalidPermissionInRole {
        role_name: String,
        permission_subject: String,
        permission_action: String,
    },
    #[error(display = "failed to create user {} with role {}", username, role_name)]
    InvalidRoleInUser {
        username: String,
        role_name: String,
    },
    #[error(display = "Failed to prompt password")]
    PromptPasswordError,
    #[error(display = "{}", _0)]
    Bcrypt(#[error(source)] #[error(from)] bcrypt::BcryptError),
}

pub type Result<T> = std::result::Result<T, InitError>;

pub async fn create_index(
    db: &mongodb::Database,
    collection_name: &str,
    indexes: bson::Bson,
) -> Result<i32> {
    let result = db.run_command(doc! {
        "createIndexes": collection_name,
        "indexes": indexes,
    }, None).await?;
    if result.get_f64("ok")? < 0.5 {
        return Err(InitError::CreateIndexError {
            collection: collection_name.into()
        });
    }
    Ok(result.get_i32("numIndexesAfter")? - result.get_i32("numIndexesBefore")?)
}

pub async fn do_init_permission(config: &InitConfig, db: &mongodb::Database) -> Result<()> {
    let permissions = db.collection(PERMISSION_COLLECTION);
    if config.reset {
        permissions.drop(None).await?;
        info!("dropped collection {}", PERMISSION_COLLECTION);
    }
    // Create index
    let result = create_index(db, PERMISSION_COLLECTION, bson!([{
        "key": {
            "subject": 1,
            "action": 1,
        },
        "name": "subject_1_action_1",
        "unique": true,
        "partialFilterExpression": {
            "deleted": false,
        },
    }])).await?;
    if result != 0 {
        info!("create {} index(es) on {}", result, PERMISSION_COLLECTION);
    }
    // Insert permissions
    let mut created = 0;
    let mut modified = 0;
    for item in predefined::PREDEFINED_PERMISSIONS {
        let current_time = chrono::Utc::now();
        let result = permissions.update_one(doc! {
            "subject": item.0,
            "action": item.1,
            "deleted": false,
        }, doc! {
            "$set": {
                "displayName": item.2,
                "description": item.3,
                "updatedAt": current_time,
            },
            "$setOnInsert": {
                "createdAt": current_time,
            },
        }, mongodb::options::UpdateOptions::builder().upsert(true).build()).await?;
        created += if let Some(_) = result.upserted_id {1} else {0};
        modified += result.modified_count;
    }
    if created != 0 || modified != 0 {
        info!("create {} document(s) and modify {} document(s) on {}", created, modified, PERMISSION_COLLECTION);
    }
    Ok(())
}

pub async fn do_init_role(config: &InitConfig, db: &mongodb::Database) -> Result<()> {
    let permissions = db.collection(PERMISSION_COLLECTION);
    let roles = db.collection(ROLE_COLLECTION);
    if config.reset {
        roles.drop(None).await?;
        info!("dropped collection {}", ROLE_COLLECTION);
    }
    // Create index
    let result = create_index(db, ROLE_COLLECTION, bson!([{
        "key": {
            "name": 1,
        },
        "name": "name_1",
        "unique": true,
        "partialFilterExpression": {
            "deleted": false,
        },
    }])).await?;
    if result != 0 {
        info!("create {} index(es) on {}", result, ROLE_COLLECTION);
    }
    // Insert roles
    let mut created = 0;
    let mut modified = 0;
    for item in predefined::PREDEFINED_ROLES {
        let current_time = chrono::Utc::now();
        let mut results = Vec::with_capacity(item.1.len());
        for (subject, action) in item.1 {
            let result = permissions.find_one(doc! {
                "subject": subject,
                "action": action,
            }, None).await?.ok_or_else(|| InitError::InvalidPermissionInRole {
                role_name: item.0.into(),
                permission_subject: (*subject).into(),
                permission_action: (*action).into(),
            })?;
            results.push(result.get_object_id("_id")?.clone());
        }
        let result = roles.update_one(doc! {
            "name": item.0,
        }, doc! {
            "$set": {
                "permissions": results,
                "displayName": item.2,
                "description": item.3,
                "updatedAt": current_time,
            },
            "$setOnInsert": {
                "createdAt": current_time,
            },
        }, mongodb::options::UpdateOptions::builder().upsert(true).build()).await?;
        created += if let Some(_) = result.upserted_id {1} else {0};
        modified += result.modified_count;
    }
    if created != 0 || modified != 0 {
        info!("create {} document(s) and modify {} document(s) on {}", created, modified, ROLE_COLLECTION);
    }
    Ok(())
}

pub async fn do_init_user(config: &InitConfig, db: &mongodb::Database) -> Result<()> {
    let roles = db.collection(ROLE_COLLECTION);
    let users = db.collection(USER_COLLECTION);
    if config.reset {
        users.drop(None).await?;
        info!("dropped collection {}", USER_COLLECTION);
    }
    // Create Indexes
    let result = create_index(db, USER_COLLECTION, bson!([{
        "key": {
            "username": 1,
        },
        "name": "username_1",
        "unique": true,
        "partialFilterExpression": {
            "deleted": false,
        },
    }, {
        "key": {
            "email": 1,
        },
        "name": "email_1",
        "unique": true,
        "partialFilterExpression": {
            "$and": [
                { "email": { "$exists": true } },
                { "deleted": false },
            ],
        },
    }])).await?;
    if result != 0 {
        info!("create {} index(es) on {}", result, USER_COLLECTION);
    }
    if let Some(superuser_username) = &config.superuser_username {
        let superuser_password = if let Some(password) = &config.superuser_password {
            password.clone()
        } else {
            rpassword::read_password_from_tty(Some("Please enter the password for superuser: "))
                .map_err(|_| InitError::PromptPasswordError)?
        };
        let superuser_password = bcrypt::hash(superuser_password, BCRYPT_COST)?;
        let mut results = Vec::with_capacity(predefined::SUPERUSER_ROLES.len());
        for role in predefined::SUPERUSER_ROLES {
            let result = roles.find_one(doc! {
                "name": role,
            }, None).await?.ok_or_else(|| InitError::InvalidRoleInUser {
                username: superuser_username.into(),
                role_name: (*role).into(),
            })?;
            results.push(result.get_object_id("_id")?.clone());
        }
        let current_time = chrono::Utc::now();
        let result = users.update_one(doc! {
            "username": superuser_username,
            "deleted": false,
        }, doc! {
            "$set": {
                "permissions": results,
                "password": superuser_password,
                "updatedAt": current_time,
            },
            "$setOnInsert": {
                "createdAt": current_time,
            },
        }, mongodb::options::UpdateOptions::builder().upsert(true).build()).await?;
        let created = if let Some(_) = result.upserted_id {1} else {0};
        let modified = result.modified_count;
        if created != 0 || modified != 0 {
            info!("create {} document(s) and modify {} document(s) on {}", created, modified, USER_COLLECTION);
        }
    }
    Ok(())
}

pub async fn do_init_token(config: &InitConfig, db: &mongodb::Database) -> Result<()> {
    let tokens = db.collection(TOKEN_COLLECTION);
    if config.reset {
        tokens.drop(None).await?;
        info!("dropped collection {}", TOKEN_COLLECTION);
    };
    let result = create_index(db, TOKEN_COLLECTION, bson!([{
        "key": {
            "user": 1,
        },
        "name": "user_1",
    }])).await?;
    if result != 0 {
        info!("create {} index(es) on {}", result, TOKEN_COLLECTION);
    }
    Ok(())
}

pub async fn do_init_global_settings(config: &InitConfig, db: &mongodb::Database) -> Result<()> {
    let global_settings = db.collection(GLOBAL_SETTINGS_COLLECTION);
    if config.reset {
        global_settings.drop(None).await?;
        info!("dropped collection {}", GLOBAL_SETTINGS_COLLECTION);
    }
    let current_time = chrono::Utc::now();
    let jwt_secret: Vec<u8> = (0..JWT_SECRET_LENGTH).map(|_| { rand::random::<u8>() }).collect();
    let result = global_settings.update_one(doc! {}, doc! {
        "$set": {
            "updatedAt": current_time,
        },
        "$setOnInsert": {
            "jwtSecret": bson::Binary {
                subtype: bson::spec::BinarySubtype::Generic,
                bytes: jwt_secret,
            },
            "createdAt": current_time,
        },
    }, mongodb::options::UpdateOptions::builder().upsert(true).build()).await?;
    let created = if let Some(_) = result.upserted_id {1} else {0};
    let modified = result.modified_count;
    if created != 0 || modified != 0 {
        info!("create {} document(s) and modify {} document(s) on {}", created, modified, GLOBAL_SETTINGS_COLLECTION);
    }
    Ok(())
}

pub async fn do_init(config: &InitConfig) -> Result<()> {
    let mut client_options = ClientOptions::parse(&config.db).await?;
    client_options.app_name = Some("Cashier Server".into());
    let client = Client::with_options(client_options)?;
    let db = client.database(&config.db_name);
    // Now call init function one by one
    do_init_permission(config, &db).await?;
    do_init_role(config, &db).await?;
    do_init_user(config, &db).await?;
    do_init_token(config, &db).await?;
    do_init_global_settings(config, &db).await?;
    Ok(())
}
