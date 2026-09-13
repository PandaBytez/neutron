use neutron::app;
use neutron::nm::CliNmClient;
use tracing_subscriber::EnvFilter;

fn main() {
    init_logging();

    // The root-owned copy is a refresh-only executable, regardless of argv.
    if std::env::current_exe()
        .ok()
        .and_then(|path| path.file_name().map(|name| name.to_owned()))
        .is_some_and(|name| {
            name == neutron::firewall::helper::NAME
                || name == format!("{} (deleted)", neutron::firewall::helper::NAME).as_str()
        })
    {
        if let Err(error) = neutron::firewall::helper::run() {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
        return;
    }

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
