use clap::{Arg, App};
use git_version::git_version;

const VERSION: &str = git_version!();

pub fn parse() {
    let matches = App::new("myapp")
        .version("version")
        .get_matches();
}