pub mod app_state;
pub mod errors;
pub mod auth;
pub mod token;

use actix_web::{web};

pub fn api_v1(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .configure(token::token_api)
    );
}