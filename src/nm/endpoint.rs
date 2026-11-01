//! Temporary NM endpoint resolution. Persistent profiles retain their hostnames.

use std::collections::HashMap;
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Str, Value};

use crate::error::{AppError, AppResult};

type Settings = HashMap<String, HashMap<String, OwnedValue>>;
type Peer = HashMap<String, OwnedValue>;
const NM: &str = "org.freedesktop.NetworkManager";
const INTERFACE: &str = "org.freedesktop.NetworkManager.Settings.Connection";

pub(super) struct EndpointPin {
    proxy: Proxy<'static>,
    endpoints: Vec<(String, String, String)>,
    restored: bool,
}

impl EndpointPin {
    pub(super) fn prepare(
        uuid: &str,
        bootstrap: impl FnOnce() -> AppResult<()>,
    ) -> AppResult<Option<Self>> {
        let connection = Connection::system().map_err(|_| failure("connect to NetworkManager"))?;
        let settings_proxy = Proxy::new(
            &connection,
            NM,
            "/org/freedesktop/NetworkManager/Settings",
            "org.freedesktop.NetworkManager.Settings",
        )
        .map_err(|_| failure("inspect profiles"))?;
        let path: OwnedObjectPath = settings_proxy
            .call("GetConnectionByUuid", &uuid)
            .map_err(|_| failure("find the activation profile"))?;
        drop(settings_proxy);
        let proxy = Proxy::new_owned(connection, NM, path, INTERFACE)
            .map_err(|_| failure("inspect the activation profile"))?;
        let public: Settings = proxy
            .call("GetSettings", &())
            .map_err(|_| failure("read peer settings"))?;
        let has_hostname = peers(&public)?.iter().any(|peer| {
            text(peer, "endpoint")
                .and_then(super::parse_endpoint)
                .is_some_and(|e| e.host.parse::<std::net::IpAddr>().is_err())
        });
        if !has_hostname {
            return Ok(None);
        }
        bootstrap()?;
        let (mut settings, version) = snapshot(&proxy)?;
        let mut entries = peers(&settings)?;
        let mut endpoints = Vec::new();
        for peer in &mut entries {
            let Some(original) = text(peer, "endpoint").map(str::to_owned) else {
                continue;
            };
            let endpoint =
                super::parse_endpoint(&original).ok_or_else(|| failure("parse a peer endpoint"))?;
            if endpoint.host.parse::<std::net::IpAddr>().is_ok() {
                continue;
            }
            let key = text(peer, "public-key")
                .ok_or_else(|| failure("identify a peer"))?
                .to_string();
            let ip = super::split_tunnel::resolve_domain_ips(&endpoint.host)
                .into_iter()
                .next()
                .ok_or_else(|| failure("resolve a peer hostname before activation"))?;
            let pinned = std::net::SocketAddr::new(ip, endpoint.port).to_string();
            peer.insert(
                "endpoint".into(),
                OwnedValue::from(Str::from(pinned.clone())),
            );
            endpoints.push((key, original, pinned));
        }
        if endpoints.is_empty() {
            return Ok(None);
        }
        set_peers(&mut settings, entries)?;
        let mut pin = Self {
            proxy,
            endpoints,
            restored: false,
        };
        if let Err(error) = update(&pin.proxy, &settings, version) {
            if let Err(restore) = pin.restore() {
                return Err(AppError::Config(format!(
                    "{error}; endpoint restoration also failed: {restore}"
                )));
            }
            return Err(error);
        }
        Ok(Some(pin))
    }

    pub(super) fn restore(&mut self) -> AppResult<()> {
        let (mut settings, version) = snapshot(&self.proxy)?;
        let mut entries = peers(&settings)?;
        let changed = restore_endpoints(&mut entries, &self.endpoints);
        if changed {
            set_peers(&mut settings, entries)?;
            update(&self.proxy, &settings, version)?;
        }
        self.restored = true;
        Ok(())
    }
}

impl Drop for EndpointPin {
    fn drop(&mut self) {
        // shortcut: SIGKILL can leave a temporary endpoint in NM memory; reload its stored profile to recover.
        if !self.restored
            && let Err(error) = self.restore()
        {
            tracing::warn!(
                "{error}; reload the NetworkManager profile to recover its stored hostname"
            );
        }
    }
}

fn text<'a>(peer: &'a Peer, key: &str) -> Option<&'a str> {
    <&str>::try_from(peer.get(key)?).ok()
}

fn restore_endpoints(peers: &mut [Peer], endpoints: &[(String, String, String)]) -> bool {
    let mut changed = false;
    for peer in peers {
        for (key, original, pinned) in endpoints {
            if text(peer, "public-key") == Some(key.as_str())
                && text(peer, "endpoint") == Some(pinned.as_str())
            {
                peer.insert(
                    "endpoint".into(),
                    OwnedValue::from(Str::from(original.clone())),
                );
                changed = true;
            }
        }
    }
    changed
}

fn peers(settings: &Settings) -> AppResult<Vec<Peer>> {
    match settings.get("wireguard").and_then(|s| s.get("peers")) {
        Some(value) => Vec::<Peer>::try_from(
            value
                .try_clone()
                .map_err(|_| failure("copy peer settings"))?,
        )
        .map_err(|_| failure("parse peer settings")),
        None => Ok(Vec::new()),
    }
}

fn set_peers(settings: &mut Settings, peers: Vec<Peer>) -> AppResult<()> {
    let value =
        OwnedValue::try_from(Value::new(peers)).map_err(|_| failure("encode peer settings"))?;
    settings
        .get_mut("wireguard")
        .ok_or_else(|| failure("find WireGuard settings"))?
        .insert("peers".into(), value);
    Ok(())
}

fn version(proxy: &Proxy<'_>) -> AppResult<u64> {
    // Read through Properties.Get, not the asynchronous property cache, for compare-and-swap.
    let reply = proxy
        .connection()
        .call_method(
            Some(NM),
            proxy.path(),
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &(INTERFACE, "VersionId"),
        )
        .map_err(|_| failure("read the profile version"))?;
    let value: OwnedValue = reply
        .body()
        .deserialize()
        .map_err(|_| failure("parse the profile version"))?;
    let version = u64::try_from(value).map_err(|_| failure("parse the profile version"))?;
    if version == 0 {
        return Err(failure("verify a nonzero profile version"));
    }
    Ok(version)
}

fn snapshot(proxy: &Proxy<'_>) -> AppResult<(Settings, u64)> {
    for _ in 0..3 {
        let before = version(proxy)?;
        let settings: Settings = proxy
            .call("GetSettings", &())
            .map_err(|_| failure("read endpoint settings"))?;
        if before == version(proxy)? {
            return Ok((settings, before));
        }
    }
    Err(failure(
        "read a stable profile; another writer is changing it",
    ))
}

fn update(proxy: &Proxy<'_>, settings: &Settings, version: u64) -> AppResult<()> {
    let args = HashMap::from([("version-id", OwnedValue::from(version))]);
    // Update2 retains existing secrets when the supplied settings contain none.
    let _: HashMap<String, OwnedValue> = proxy.call("Update2", &(settings, 0x2u32, args)).map_err(
        |_| {
            failure(
                "apply in-memory endpoints; the profile may have changed or permission was denied",
            )
        },
    )?;
    Ok(())
}

fn failure(operation: &str) -> AppError {
    AppError::Config(format!(
        "could not {operation}; endpoint activation refused"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restoration_preserves_peer_metadata_and_external_endpoint_edits() {
        let peer = |key: &str, endpoint: &str| {
            Peer::from([
                (
                    "public-key".into(),
                    OwnedValue::from(Str::from(key.to_string())),
                ),
                (
                    "endpoint".into(),
                    OwnedValue::from(Str::from(endpoint.to_string())),
                ),
                ("persistent-keepalive".into(), OwnedValue::from(25u32)),
            ])
        };
        let mut settings = Settings::from([("wireguard".into(), Peer::new())]);
        set_peers(
            &mut settings,
            vec![peer("A", "192.0.2.1:53"), peer("B", "192.0.2.2:53")],
        )
        .unwrap();
        let mut entries = peers(&settings).unwrap();
        assert_eq!(
            u32::try_from(&entries[0]["persistent-keepalive"]).unwrap(),
            25
        );
        let originals = vec![
            ("A".into(), "a.test:53".into(), "192.0.2.1:53".into()),
            ("B".into(), "b.test:53".into(), "old-ip:53".into()),
        ];
        assert!(restore_endpoints(&mut entries, &originals));
        assert_eq!(text(&entries[0], "endpoint"), Some("a.test:53"));
        assert_eq!(text(&entries[1], "endpoint"), Some("192.0.2.2:53"));
        assert!(!restore_endpoints(&mut entries, &originals));
    }
}
