use crate::config::StartConfig;
use crate::api::{app_state::AppState, api_v1};
use actix_web::{web, App, HttpServer, middleware::Logger};
use err_derive::Error;
use mongodb::{Client, options::ClientOptions};

#[derive(Debug, Error)]
pub enum StartError {
    #[error(display = "{}", _0)]
    Db(#[error(source)] #[error(from)] mongodb::error::Error),
    #[error(display = "{}", _0)]
    Io(#[error(source)] #[error(from)] std::io::Error),
}

pub type Result<T> = std::result::Result<T, StartError>;

pub async fn do_start(config: &StartConfig) -> Result<()> {
    let mut client_options = ClientOptions::parse(&config.db).await?;
    client_options.app_name = Some("Cashier Server".into());
    let client = Client::with_options(client_options)?;
    let db = client.database(&config.db_name);
    let app_data = web::Data::new(AppState {
        config: config.clone(),
        db,
    });
    HttpServer::new(move || {
        App::new()
            .app_data(app_data.clone())
            .wrap(Logger::default())
            .configure(api_v1)
    })
        .bind(&config.bind)?
        .run()
        .await?;
    Ok(())
}