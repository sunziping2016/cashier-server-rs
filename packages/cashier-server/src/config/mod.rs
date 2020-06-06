use clap::{Arg, App};
use serde::{Serialize, Deserialize};
use shell_macro::shell;
use std::ffi::OsString;
use std::{env, fmt};
use std::fs::File;
use std::path::Path;

pub const BUILD_VERSION: &str = shell!("git describe --tags $(git rev-list --tags --max-count=1)");
pub const BUILD_COMMIT_ID: &str = shell!("git log --format=\"%h\" -n 1");
pub const BUILD_TIME: &str = shell!("date +%F");
pub const AUTHORS: &str = shell!("git log --pretty=\"%an <%ae>\" | sort | uniq");

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Json(serde_json::Error),
    UnknownSubCommand,
    MissingDbArgument,
    MissingRedisArgument,
    MissingBindArgument,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Io(ref e) => e.fmt(f),
            Error::Json(ref e) => e.fmt(f),
            Error::UnknownSubCommand => write!(f, "unknown command"),
            Error::MissingDbArgument => write!(f, "missing database argument"),
            Error::MissingRedisArgument => write!(f, "missing redis argument"),
            Error::MissingBindArgument => write!(f, "missing bind argument"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(ref e) => Some(e),
            Error::Json(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

#[derive(Debug)]
pub struct InitConfig {
    db: String,
    redis: String,
    reset: bool,
    superuser_username: Option<String>,
    superuser_password: Option<String>,
}

#[derive(Debug)]
pub struct StartConfig {
    db: String,
    redis: String,
    bind: String,
}

#[derive(Debug)]
pub enum Config {
    Init(InitConfig),
    Start(StartConfig),
}

#[derive(Serialize, Deserialize)]
pub struct ConfigFile {
    db: Option<String>,
    redis: Option<String>,
    bind: Option<String>,
}

impl ConfigFile {
    pub fn new() -> Self {
        ConfigFile {
            db: None,
            redis: None,
            bind: None,
        }
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let json = File::open(path)?;
        Ok(serde_json::from_reader(&json)?)
    }
}

impl Config {
    pub fn from_env() -> Result<Self, Error> {
        Self::from(&mut env::args_os())
    }

    pub fn from<I, T>(itr: I) -> Result<Self, Error>
        where
            I: IntoIterator<Item = T>,
            T: Into<OsString> + Clone,
    {
        let matches = App::new("cashier-server")
            .version(&format!("{} ({} {})", BUILD_VERSION.trim(),
                              BUILD_COMMIT_ID.trim(), BUILD_TIME.trim())[..])
            .author(&AUTHORS.trim().split("\n").collect::<Vec<&str>>().join(", ")[..])
            .about("Rust implementation for cashier server")
            .arg(Arg::with_name("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .about("Sets a custom config file")
                .takes_value(true))
            .arg(Arg::with_name("db")
                .long("db")
                .value_name("URL")
                .about("Sets the MongoDB connection")
                .takes_value(true))
            .arg(Arg::with_name("redis")
                .long("redis")
                .value_name("URL")
                .about("Sets the redis connection")
                .takes_value(true))
            .arg(Arg::with_name("bind")
                .long("bind")
                .value_name("ADDR:PORT")
                .about("Address to bind")
                .takes_value(true))
            .subcommand(App::new("init")
                .about("Initializes all databases")
                .arg(Arg::with_name("reset")
                    .long("reset")
                    .about("Clears all databases before initialization"))
                .arg(Arg::with_name("superuser-username")
                    .long("superuser-username")
                    .value_name("USERNAME")
                    .about("Creates a superuser and sets superuser's username")
                    .takes_value(true))
                .arg(Arg::with_name("superuser-password")
                    .long("superuser-password")
                    .value_name("PASSWORD")
                    .about("Sets superuser's password. Leaves empty to prompt from CLI")
                    .takes_value(true)))
            .subcommand(App::new("start")
                .about("Starts the server"))
            .get_matches_from(itr);
        let mut config_file = ConfigFile::new();
        if let Some(path) = matches.value_of("config") {
            config_file = ConfigFile::load(path)?;
        }
        config_file.db = config_file.db.or(matches.value_of("db").map(String::from));
        config_file.redis = config_file.redis.or(matches.value_of("redis").map(String::from));
        config_file.bind = config_file.bind.or(matches.value_of("bind").map(String::from));
        match matches.subcommand() {
            ("init", Some(sub_matches)) => Ok(Config::Init(InitConfig {
                db: config_file.db.ok_or_else(|| Error::MissingDbArgument)?,
                redis: config_file.redis.ok_or_else(|| Error::MissingRedisArgument)?,
                reset: sub_matches.is_present("reset"),
                superuser_username: sub_matches.value_of("superuser-username").map(String::from),
                superuser_password: sub_matches.value_of("superuser-password").map(String::from),
            })),
            ("start", Some(_)) => Ok(Config::Start(StartConfig {
                db: config_file.db.ok_or_else(|| Error::MissingDbArgument)?,
                redis: config_file.redis.ok_or_else(|| Error::MissingRedisArgument)?,
                bind: config_file.bind.ok_or_else(|| Error::MissingBindArgument)?,
            })),
            _ => panic!("every subcommand is processed. should not reach here")
        }
    }
}

// TODO: Add test for argument parser
