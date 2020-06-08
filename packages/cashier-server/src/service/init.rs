use crate::config::InitConfig;
use super::predefined;
use bson::{doc};
use err_derive::Error;
use log::info;
use mongodb::{Client, options::ClientOptions};

#[derive(Debug, Error)]
pub enum InitError {
    #[error(display = "{}", _0)]
    Db(#[error(source)] #[error(from)] mongodb::error::Error),
    #[error(display = "{}", _0)]
    Bson(#[error(source)] #[error(from)] bson::ordered::ValueAccessError),
    #[error(display = "failed to create index {} on {}", index, collection)]
    CreateIndexError {
        collection: String,
        index: String,
    }
}

pub type Result<T> = std::result::Result<T, InitError>;

pub async fn do_init_permission(config: &InitConfig, db: &mongodb::Database) -> Result<()> {
    const COLLECTION_NAME: &str = "permissions";
    const INDEX_NAME: &str = "subject_1_action_1";
    let permissions: mongodb::Collection = db.collection(COLLECTION_NAME);
    if config.reset {
        permissions.drop(None).await?;
        info!("dropped collection {}", COLLECTION_NAME);
    }
    // Create index
    let result = db.run_command(doc! {
        "createIndexes": COLLECTION_NAME,
        "indexes": [{
            "key": {
                "subject": 1,
                "action": 1,
            },
            "name": INDEX_NAME,
            "unique": true,
            "partialFilterExpression": {
                "deleted": false,
            },
        }]
    }, None).await?;
    if result.get_f64("ok")? < 0.5 {
        return Err(InitError::CreateIndexError {
            collection: COLLECTION_NAME.into(),
            index: INDEX_NAME.into(),
        });
    } else if result.get_i32("numIndexesAfter")? > result.get_i32("numIndexesBefore")? {
        info!("create index {} on {}", INDEX_NAME, COLLECTION_NAME);
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
                "name": item.2,
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
        info!("create {} document(s) and modify {} document(s) on {}", created, modified, COLLECTION_NAME);
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
    Ok(())
}