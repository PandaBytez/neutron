use tracing_subscriber::EnvFilter;
use wireguard_manager::app;
use wireguard_manager::nm::CliNmClient;

fn main() {
    init_logging();

    let client = CliNmClient;
    if let Err(error) = app::run(&client) {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}
