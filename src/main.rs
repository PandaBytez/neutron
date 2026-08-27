use neutron_vpn::app;
use neutron_vpn::nm::CliNmClient;
use tracing_subscriber::EnvFilter;

fn main() {
    init_logging();

    #[cfg(feature = "gui")]
    {
        gtk::glib::set_prgname(Some("io.gitlab.neutron_vpn.neutron"));
        gtk::glib::set_application_name("Neutron VPN");
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
