use std::process::Command;

#[test]
fn version_flags_only_print_the_package_version_without_creating_app_directories() {
    let home = neutron::testing::scratch_dir("cli-version");
    for flag in ["--version", "-V"] {
        let output = Command::new(env!("CARGO_BIN_EXE_neutron"))
            .arg(flag)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_RUNTIME_DIR", home.join("runtime"))
            .env("PATH", "")
            .current_dir(&home)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            concat!("neutron ", env!("CARGO_PKG_VERSION"), "\n")
        );
        assert!(output.stderr.is_empty());
        assert_eq!(std::fs::read_dir(&home).unwrap().count(), 0);
    }
    std::fs::remove_dir_all(home).unwrap();
}
