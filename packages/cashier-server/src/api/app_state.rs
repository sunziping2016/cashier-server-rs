use crate::config::StartConfig;

pub struct AppState {
    pub config: StartConfig,
    pub db: mongodb::Database,
}
