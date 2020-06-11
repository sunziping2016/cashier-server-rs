use lazy_static::lazy_static;
use regex::Regex;

pub const PERMISSION_COLLECTION: &str = "permissions";
pub const ROLE_COLLECTION: &str = "roles";
pub const USER_COLLECTION: &str = "users";
pub const TOKEN_COLLECTION: &str = "tokens";
pub const GLOBAL_SETTINGS_COLLECTION: &str = "globalSettings";

pub const JWT_SECRET_LENGTH: u32 = 256;
pub const JWT_EXPIRE_SECONDS: i64 = 10 * 24 * 60 * 60;
pub const BCRYPT_COST: u32 = 8;

lazy_static! {
    pub static ref USERNAME_REGEX: Regex = Regex::new(r"(?i)^[a-z\d_-]{3,24}$").unwrap();
    pub static ref PASSWORD_REGEX: Regex = Regex::new(r"^[^:&.~\s]{6,24}$").unwrap();
    pub static ref NICKNAME_REGEX: Regex = Regex::new(r".{3,24}").unwrap();
}
