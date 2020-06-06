#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    cashier_server::config::parse();
    Ok(())
}