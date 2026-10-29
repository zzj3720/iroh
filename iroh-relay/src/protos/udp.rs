//! ember: the relay's datagrams over UDP, beside its WebSocket.
//!
//! The WebSocket carries a relay's datagrams over TCP: a packet lost on the way to the relay holds every one after it
//! until TCP sends it again, under QUIC's own recovery. A relay that binds a UDP socket offers it in the upgrade's answer
//! ([`UDP_HEADER`]: its port and a token for this connection, which only the client that asked sees, over TLS), to a
//! client that asked for it in its request. The WebSocket stays the connection: its handshake says who the client is,
//! and it carries everything but the datagrams (pings, `EndpointGone`, status).
//!
//! - Client to relay, each packet with the token: [`HELLO`] (`flags` bit 0: the client hears the relay over UDP) and
//!   [`DATA`] (a datagram for `dst`).
//! - Relay to client: [`HELLO_ACK`], the answer to each hello, and [`DATA`] (a datagram from `src`).
//!
//! A connection that took the way sends and receives its datagrams over UDP only, never by its WebSocket: a way UDP
//! does not go through shows as lost datagrams instead of being covered by the WebSocket. The relay sends a client's to
//! where its packets last came from; the client says hello every [`UDP_HELLO`], which keeps a NAT's mapping open and
//! tells the relay where it is before it sends anything (and after its NAT moved it).

use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use iroh_base::EndpointId;

/// The header a client asks for UDP with (value `1`) and a relay offers it with (`<port> <token, hex>`).
pub const UDP_HEADER: &str = "x-iroh-relay-udp";

/// The first bytes of every packet.
pub const MAGIC: [u8; 4] = *b"irU1";
/// A token's length.
pub const TOKEN_LEN: usize = 16;
/// A client's hello: magic, kind, token, flags.
pub const HELLO: u8 = 1;
/// The relay's answer to a hello: magic, kind.
pub const HELLO_ACK: u8 = 2;
/// A datagram: magic, kind, then client to relay the token, the destination and the ECN bits, relay to client the
/// source and the ECN bits, then the datagram.
pub const DATA: u8 = 3;

/// Hello flag: the client hears the relay over UDP (for the relay's logs).
pub const FLAG_HEARING: u8 = 1;

/// The largest datagram sent over UDP: with its header (54 bytes) and IPv6 and UDP's (48), it fits a 1492-byte link
/// (PPPoE). A larger one is dropped, as a link with that MTU would: QUIC's MTU discovery stays under it.
pub const MAX_UDP_DATAGRAM: usize = 1390;

/// How often a client says hello: within common NATs' UDP timeouts (30 s and more).
pub const UDP_HELLO: Duration = Duration::from_secs(10);

/// A connection's token.
pub type Token = [u8; TOKEN_LEN];

/// The value of a relay's offer.
pub fn offer_value(port: u16, token: &Token) -> String {
    format!("{port} {}", hex(token))
}

/// A relay's offer read from its header value: the port and the token.
pub fn parse_offer(value: &str) -> Option<(u16, Token)> {
    let (port, token) = value.trim().split_once(' ')?;
    let port: u16 = port.parse().ok()?;
    let token = token.trim();
    if port == 0 || token.len() != TOKEN_LEN * 2 {
        return None;
    }
    let mut out = [0u8; TOKEN_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(token.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some((port, out))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A packet as it is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// Client to relay.
    Hello {
        /// The connection's token.
        token: Token,
        /// [`FLAG_HEARING`].
        flags: u8,
    },
    /// Relay to client.
    HelloAck,
    /// Client to relay.
    ToRelay {
        /// The connection's token.
        token: Token,
        /// Whom it is for.
        dst: [u8; 32],
        /// The ECN bits (0 none).
        ecn: u8,
        /// The datagram.
        contents: Bytes,
    },
    /// Relay to client.
    FromRelay {
        /// Whom it is from.
        src: [u8; 32],
        /// The ECN bits (0 none).
        ecn: u8,
        /// The datagram.
        contents: Bytes,
    },
}

/// Reads a client's packet (as the relay does), `None` for anything else.
pub fn read_to_relay(packet: &Bytes) -> Option<Packet> {
    let (kind, rest) = head(packet)?;
    let token: Token = rest.get(..TOKEN_LEN)?.try_into().ok()?;
    let rest = &rest[TOKEN_LEN..];
    match kind {
        HELLO => Some(Packet::Hello {
            token,
            flags: *rest.first()?,
        }),
        DATA => {
            let dst: [u8; 32] = rest.get(..32)?.try_into().ok()?;
            let ecn = *rest.get(32)?;
            let start = 4 + 1 + TOKEN_LEN + 33;
            if packet.len() <= start {
                return None;
            }
            Some(Packet::ToRelay {
                token,
                dst,
                ecn,
                contents: packet.slice(start..),
            })
        }
        _ => None,
    }
}

/// Reads a relay's packet (as the client does), `None` for anything else.
pub fn read_from_relay(packet: &Bytes) -> Option<Packet> {
    let (kind, rest) = head(packet)?;
    match kind {
        HELLO_ACK => Some(Packet::HelloAck),
        DATA => {
            let src: [u8; 32] = rest.get(..32)?.try_into().ok()?;
            let ecn = *rest.get(32)?;
            let start = 4 + 1 + 33;
            if packet.len() <= start {
                return None;
            }
            Some(Packet::FromRelay {
                src,
                ecn,
                contents: packet.slice(start..),
            })
        }
        _ => None,
    }
}

fn head(packet: &[u8]) -> Option<(u8, &[u8])> {
    if packet.get(..4)? != MAGIC {
        return None;
    }
    Some((*packet.get(4)?, &packet[5..]))
}

/// A client's hello.
pub fn hello(token: &Token, flags: u8) -> Bytes {
    let mut out = BytesMut::with_capacity(4 + 1 + TOKEN_LEN + 1);
    out.put_slice(&MAGIC);
    out.put_u8(HELLO);
    out.put_slice(token);
    out.put_u8(flags);
    out.freeze()
}

/// The relay's answer to a hello.
pub fn hello_ack() -> Bytes {
    let mut out = BytesMut::with_capacity(5);
    out.put_slice(&MAGIC);
    out.put_u8(HELLO_ACK);
    out.freeze()
}

/// A client's datagram for `dst`.
pub fn to_relay(out: &mut BytesMut, token: &Token, dst: &EndpointId, ecn: u8, datagram: &[u8]) {
    out.clear();
    out.reserve(4 + 1 + TOKEN_LEN + 33 + datagram.len());
    out.put_slice(&MAGIC);
    out.put_u8(DATA);
    out.put_slice(token);
    out.put_slice(dst.as_bytes());
    out.put_u8(ecn);
    out.put_slice(datagram);
}

/// The relay's datagram from `src`.
pub fn from_relay(out: &mut BytesMut, src: &EndpointId, ecn: u8, datagram: &[u8]) {
    out.clear();
    out.reserve(4 + 1 + 33 + datagram.len());
    out.put_slice(&MAGIC);
    out.put_u8(DATA);
    out.put_slice(src.as_bytes());
    out.put_u8(ecn);
    out.put_slice(datagram);
}

/// ECN bits as they go in a packet (as the WebSocket's frames have them).
pub fn ecn_byte(ecn: Option<noq_proto::EcnCodepoint>) -> u8 {
    ecn.map_or(0, |ecn| ecn as u8)
}

/// ECN bits as a packet has them.
pub fn ecn_codepoint(byte: u8) -> Option<noq_proto::EcnCodepoint> {
    noq_proto::EcnCodepoint::from_bits(byte)
}

/// Each datagram of a transmit (one, or several of `segment_size`).
pub fn segments(
    contents: &[u8],
    segment_size: Option<std::num::NonZeroU16>,
) -> std::slice::Chunks<'_, u8> {
    let size = segment_size.map_or(contents.len().max(1), |s| usize::from(s.get()));
    contents.chunks(size)
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;

    use super::*;

    #[test]
    fn offer_round_trip() {
        let token = [7u8; TOKEN_LEN];
        assert_eq!(parse_offer(&offer_value(3478, &token)), Some((3478, token)));
        assert_eq!(parse_offer("0 07070707070707070707070707070707"), None);
        assert_eq!(parse_offer("3478 0707"), None);
        assert_eq!(parse_offer("3478 zz070707070707070707070707070707"), None);
    }

    #[test]
    fn packets_round_trip() {
        let token = [3u8; TOKEN_LEN];
        let key = SecretKey::from_bytes(&[9u8; 32]).public();
        assert_eq!(
            read_to_relay(&hello(&token, FLAG_HEARING)),
            Some(Packet::Hello {
                token,
                flags: FLAG_HEARING
            })
        );
        assert_eq!(read_from_relay(&hello_ack()), Some(Packet::HelloAck));
        let mut out = BytesMut::new();
        to_relay(&mut out, &token, &key, 0b10, b"datagram");
        assert_eq!(
            read_to_relay(&out.clone().freeze()),
            Some(Packet::ToRelay {
                token,
                dst: *key.as_bytes(),
                ecn: 0b10,
                contents: Bytes::from_static(b"datagram")
            })
        );
        from_relay(&mut out, &key, 0, b"back");
        assert_eq!(
            read_from_relay(&out.freeze()),
            Some(Packet::FromRelay {
                src: *key.as_bytes(),
                ecn: 0,
                contents: Bytes::from_static(b"back")
            })
        );
        // Wrong magic, a client's packet read as the relay's, nothing after the header.
        assert_eq!(read_to_relay(&Bytes::from_static(b"xxxx\x01")), None);
        assert_eq!(read_from_relay(&hello(&token, 0)), None);
        let mut empty = BytesMut::new();
        from_relay(&mut empty, &key, 0, b"");
        assert_eq!(read_from_relay(&empty.freeze()), None);
    }

    #[test]
    fn segments_split() {
        let contents = [0u8; 10];
        let sizes: Vec<usize> = segments(&contents, std::num::NonZeroU16::new(4))
            .map(<[u8]>::len)
            .collect();
        assert_eq!(sizes, vec![4, 4, 2]);
        assert_eq!(segments(&contents, None).count(), 1);
    }
}
