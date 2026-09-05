//! NAT-PMP (RFC 6886) client used to obtain a forwarded port from the VPN.
//!
//! Providers that support port forwarding (Proton VPN in particular) run a
//! NAT-PMP responder on the tunnel gateway. A client asks it for a public port,
//! and the responder replies with the port it mapped. The lease is short-lived
//! by design, so it must be renewed periodically or the provider reclaims the
//! port -- see [`LIFETIME`] and [`RENEW_INTERVAL`].
//!
//! The forwarded port is therefore *not* the peer `Endpoint` port from the
//! WireGuard config: that is the server's own listening port and is identical
//! for every server. The mapped port is assigned per session and changes.
//!
//! The protocol is a 12-byte request and a 16-byte reply over UDP, so it is
//! implemented directly rather than shelling out to `natpmpc`, which is not
//! installed by default on most distributions. The wire format lives in
//! [`build_map_request`] / [`parse_map_response`], which are pure and unit
//! tested; only [`request_mapping_from`] touches a socket.

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

#[cfg(feature = "qbittorrent")]
pub mod qbittorrent;

use crate::error::{AppError, AppResult};

/// Well-known NAT-PMP port on the gateway (RFC 6886 §3).
const NATPMP_PORT: u16 = 5351;

/// Opcode for "map UDP port" and its TCP counterpart. The reply opcode is the
/// request opcode plus 128.
const OP_MAP_UDP: u8 = 1;
const OP_MAP_TCP: u8 = 2;
const RESPONSE_OPCODE_OFFSET: u8 = 128;

/// A mapping reply is exactly 16 bytes.
const RESPONSE_LEN: usize = 16;

/// Lease length requested for the mapping. Providers cap this (Proton grants
/// 60s regardless of what is asked for), so it is renewed well before expiry.
pub const LIFETIME: u32 = 60;

/// How often the mapping must be renewed to keep the port. Deliberately shorter
/// than [`LIFETIME`] so a slow round trip cannot let the lease lapse.
pub const RENEW_INTERVAL: Duration = Duration::from_secs(45);

/// How long to wait for the gateway to answer before giving up. The gateway is
/// one hop away over the tunnel, so a slow reply means it is not a NAT-PMP
/// responder rather than that it is busy.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

/// Parse the local IPv4 address from a tunnel address string (e.g. "10.2.0.2/32").
pub fn parse_local_address(address: &str) -> Option<Ipv4Addr> {
    let host = address.split('/').next()?.trim();
    host.parse().ok()
}

/// The NAT-PMP gateway for a tunnel whose local address is `address`.
///
/// WireGuard peers are configured with a host address such as `10.2.0.2/32`,
/// which carries no gateway of its own. The responder sits at `.1` of that
/// subnet, so the gateway is derived by replacing the final octet.
pub fn gateway_for_address(address: &str) -> Option<Ipv4Addr> {
    let ip = parse_local_address(address)?;
    let [a, b, c, _] = ip.octets();
    Some(Ipv4Addr::new(a, b, c, 1))
}

/// Ask the gateway derived from a tunnel's local `address` to forward a port.
///
/// Bundles [`gateway_for_address`] and [`request_mapping_from`], which every caller
/// needs together. Note this performs a blocking UDP round trip of up to
/// [`READ_TIMEOUT`], so callers on a UI thread should only invoke it when the
/// tunnel actually changed or the lease is due.
pub fn port_for_tunnel_address(address: &str) -> Option<u16> {
    let gateway = gateway_for_address(address)?;
    let local_ip = parse_local_address(address);
    request_mapping_from(local_ip, gateway).ok()
}

/// Encode a NAT-PMP mapping request.
///
/// Asking for internal and external port `0` means "any port"; the gateway
/// chooses and reports it back. That is how a VPN port-forward is obtained.
fn build_map_request(
    opcode: u8,
    internal_port: u16,
    external_port: u16,
    lifetime: u32,
) -> [u8; 12] {
    let mut request = [0u8; 12];
    request[0] = 0; // protocol version
    request[1] = opcode;
    // bytes 2..4 are reserved and must stay zero
    request[4..6].copy_from_slice(&internal_port.to_be_bytes());
    request[6..8].copy_from_slice(&external_port.to_be_bytes());
    request[8..12].copy_from_slice(&lifetime.to_be_bytes());
    request
}

/// Decode a NAT-PMP mapping reply, returning the port the gateway mapped.
///
/// Rejects replies that are truncated, that answer a different opcode than the
/// one asked for, or that carry a non-zero result code, so a misbehaving
/// responder cannot be mistaken for a successful mapping.
fn parse_map_response(bytes: &[u8], request_opcode: u8) -> AppResult<u16> {
    if bytes.len() < RESPONSE_LEN {
        return Err(AppError::PortForward(format!(
            "short NAT-PMP reply ({} bytes, expected {RESPONSE_LEN})",
            bytes.len()
        )));
    }

    let expected_opcode = request_opcode + RESPONSE_OPCODE_OFFSET;
    if bytes[1] != expected_opcode {
        return Err(AppError::PortForward(format!(
            "unexpected NAT-PMP opcode {} (expected {expected_opcode})",
            bytes[1]
        )));
    }

    let result_code = u16::from_be_bytes([bytes[2], bytes[3]]);
    if result_code != 0 {
        return Err(AppError::PortForward(format!(
            "gateway refused the mapping: {}",
            describe_result_code(result_code)
        )));
    }

    let external_port = u16::from_be_bytes([bytes[10], bytes[11]]);
    if external_port == 0 {
        return Err(AppError::PortForward(
            "gateway mapped port 0, so no port is forwarded".to_string(),
        ));
    }
    Ok(external_port)
}

/// Human-readable form of the RFC 6886 §3.5 result codes.
fn describe_result_code(code: u16) -> String {
    match code {
        1 => "unsupported protocol version".to_string(),
        2 => "not authorized (port forwarding may be off for this server)".to_string(),
        3 => "network failure".to_string(),
        4 => "out of resources".to_string(),
        5 => "unsupported opcode".to_string(),
        other => format!("result code {other}"),
    }
}

/// Ask `gateway` to forward a port, renewing or creating the lease.
///
/// Both UDP and TCP are mapped because providers hand out one port for the
/// pair, and a caller asking for "the forwarded port" expects both protocols to
/// work. The UDP mapping decides the port; the TCP request reuses it.
pub fn request_mapping_from(local_ip: Option<Ipv4Addr>, gateway: Ipv4Addr) -> AppResult<u16> {
    let port = map_protocol(local_ip, gateway, OP_MAP_UDP, 0)?;
    // Best effort: a provider that only forwards UDP still gives a usable port.
    let _ = map_protocol(local_ip, gateway, OP_MAP_TCP, port);
    Ok(port)
}

fn map_protocol(
    local_ip: Option<Ipv4Addr>,
    gateway: Ipv4Addr,
    opcode: u8,
    requested_port: u16,
) -> AppResult<u16> {
    let socket = if let Some(local) = local_ip {
        UdpSocket::bind((local, 0)).or_else(|_| UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)))
    } else {
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
    }
    .map_err(|error| AppError::PortForward(format!("could not open a socket: {error}")))?;
    socket
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(|error| AppError::PortForward(format!("could not set a timeout: {error}")))?;

    let request = build_map_request(opcode, requested_port, requested_port, LIFETIME);
    socket
        .send_to(&request, SocketAddrV4::new(gateway, NATPMP_PORT))
        .map_err(|error| {
            AppError::PortForward(format!("could not reach the gateway {gateway}: {error}"))
        })?;

    let mut reply = [0u8; RESPONSE_LEN];
    let (len, _) = socket.recv_from(&mut reply).map_err(|error| {
        AppError::PortForward(format!(
            "no reply from {gateway}; the server may not offer port forwarding ({error})"
        ))
    })?;

    parse_map_response(&reply[..len], opcode)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a well-formed reply so tests describe intent rather than offsets.
    fn response(opcode: u8, result_code: u16, external_port: u16) -> [u8; RESPONSE_LEN] {
        let mut bytes = [0u8; RESPONSE_LEN];
        bytes[1] = opcode + RESPONSE_OPCODE_OFFSET;
        bytes[2..4].copy_from_slice(&result_code.to_be_bytes());
        bytes[10..12].copy_from_slice(&external_port.to_be_bytes());
        bytes
    }

    #[test]
    fn request_encodes_the_rfc_layout() {
        let request = build_map_request(OP_MAP_UDP, 0, 0, LIFETIME);

        assert_eq!(request[0], 0, "version must be 0");
        assert_eq!(request[1], OP_MAP_UDP);
        assert_eq!(&request[2..4], &[0, 0], "reserved bytes must be zero");
        assert_eq!(&request[8..12], &LIFETIME.to_be_bytes());
    }

    #[test]
    fn request_carries_the_requested_ports() {
        let request = build_map_request(OP_MAP_TCP, 4321, 1234, 60);

        assert_eq!(&request[4..6], &4321u16.to_be_bytes());
        assert_eq!(&request[6..8], &1234u16.to_be_bytes());
    }

    #[test]
    fn parses_the_mapped_port_from_a_success_reply() {
        let reply = response(OP_MAP_UDP, 0, 51234);

        assert_eq!(parse_map_response(&reply, OP_MAP_UDP).unwrap(), 51234);
    }

    #[test]
    fn rejects_a_truncated_reply() {
        let reply = response(OP_MAP_UDP, 0, 51234);

        let result = parse_map_response(&reply[..8], OP_MAP_UDP);

        assert!(matches!(result, Err(AppError::PortForward(message)) if message.contains("short")));
    }

    #[test]
    fn rejects_a_reply_for_a_different_opcode() {
        // A TCP reply must never satisfy a UDP request, otherwise a stray
        // datagram could be read as this request's mapping.
        let reply = response(OP_MAP_TCP, 0, 51234);

        let result = parse_map_response(&reply, OP_MAP_UDP);

        assert!(
            matches!(result, Err(AppError::PortForward(message)) if message.contains("opcode"))
        );
    }

    #[test]
    fn reports_the_gateway_refusal_reason() {
        // Result code 2 is what a server without port forwarding answers.
        let reply = response(OP_MAP_UDP, 2, 0);

        let result = parse_map_response(&reply, OP_MAP_UDP);

        assert!(
            matches!(result, Err(AppError::PortForward(message)) if message.contains("not authorized"))
        );
    }

    #[test]
    fn rejects_a_success_reply_that_mapped_no_port() {
        let reply = response(OP_MAP_UDP, 0, 0);

        let result = parse_map_response(&reply, OP_MAP_UDP);

        assert!(
            matches!(result, Err(AppError::PortForward(message)) if message.contains("port 0"))
        );
    }

    #[test]
    fn derives_the_gateway_from_a_tunnel_address() {
        assert_eq!(
            gateway_for_address("10.2.0.2/32"),
            Some(Ipv4Addr::new(10, 2, 0, 1))
        );
        // The prefix is optional and surrounding whitespace is tolerated.
        assert_eq!(
            gateway_for_address(" 10.2.0.2 "),
            Some(Ipv4Addr::new(10, 2, 0, 1))
        );
        assert_eq!(
            gateway_for_address("192.168.5.44/24"),
            Some(Ipv4Addr::new(192, 168, 5, 1))
        );
    }

    #[test]
    fn parses_local_address_from_tunnel_address() {
        assert_eq!(
            parse_local_address("10.2.0.2/32"),
            Some(Ipv4Addr::new(10, 2, 0, 2))
        );
        assert_eq!(
            parse_local_address("10.2.0.2"),
            Some(Ipv4Addr::new(10, 2, 0, 2))
        );
        assert_eq!(parse_local_address(""), None);
        assert_eq!(parse_local_address("not-an-address"), None);
    }

    #[test]
    fn returns_no_gateway_for_a_non_ipv4_address() {
        // IPv6-only tunnels and empty values have no derivable NAT-PMP gateway.
        assert_eq!(gateway_for_address("2a07:b944::2:2/128"), None);
        assert_eq!(gateway_for_address(""), None);
        assert_eq!(gateway_for_address("not-an-address"), None);
    }

    #[test]
    fn mock_natpmp_responder_mapping_flow() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::thread;

        let responder = UdpSocket::bind(("127.0.0.1", 0)).expect("bind mock responder");
        responder
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let port = responder.local_addr().unwrap().port();

        let done = Arc::new(AtomicBool::new(false));
        let done_clone = done.clone();

        let handle = thread::spawn(move || {
            let mut buf = [0u8; 64];
            while !done_clone.load(Ordering::Relaxed) {
                if let Ok((len, src)) = responder.recv_from(&mut buf)
                    && len >= 12
                {
                    let opcode = buf[1];
                    let reply = response(opcode, 0, 48888);
                    let _ = responder.send_to(&reply, src);
                }
            }
        });

        let request = build_map_request(OP_MAP_UDP, 0, 0, LIFETIME);
        let client_socket = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        client_socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client_socket
            .send_to(&request, ("127.0.0.1", port))
            .unwrap();

        let mut reply = [0u8; RESPONSE_LEN];
        let (len, _) = client_socket.recv_from(&mut reply).unwrap();
        let mapped = parse_map_response(&reply[..len], OP_MAP_UDP).unwrap();
        assert_eq!(mapped, 48888);

        done.store(true, Ordering::Relaxed);
        let _ = handle.join();
    }
}
