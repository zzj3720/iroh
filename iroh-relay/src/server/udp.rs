//! ember: the relay's UDP way, beside its WebSocket (protos/udp.rs).
//!
//! One socket for every client. A connection's token is offered in its upgrade's answer and taken here once the
//! connection is authorized; a packet with it is that connection's, from wherever it comes (a NAT that rebinds the
//! client's port is followed). What comes is rate limited as the WebSocket's reads are, and forwarded to the
//! destination as a datagram read from its WebSocket would be; what goes to a client goes over UDP only, to where its
//! packets last came from (dropped until its first one comes).

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use iroh_base::EndpointId;
use n0_future::task::AbortOnDropHandle;
use tokio::{net::UdpSocket, sync::watch, time::Instant};
use tracing::{Instrument, debug, info_span, trace};

use super::{ClientRateLimit, clients::Clients, metrics::Metrics};
use crate::{
    KeyCache,
    protos::{
        relay::Datagrams,
        udp::{self, Packet, Token},
    },
};

/// The relay's UDP socket and the connections that took its way.
#[derive(Debug)]
pub(crate) struct UdpRelay {
    socket: Arc<UdpSocket>,
    local: SocketAddr,
    peers: Arc<DashMap<Token, Arc<Peer>>>,
    _task: AbortOnDropHandle<()>,
}

#[derive(Debug)]
struct Peer {
    endpoint_id: EndpointId,
    state: Mutex<PeerState>,
}

#[derive(Debug)]
struct PeerState {
    /// Where the client's packets last came from.
    addr: Option<SocketAddr>,
    bucket: Bucket,
}

/// The WebSocket's rate limit (`ClientRateLimit`) for what a connection sends over UDP.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn take(&mut self, limit: Option<ClientRateLimit>, len: usize, now: Instant) -> bool {
        let Some(limit) = limit else {
            return true;
        };
        let rate = f64::from(limit.bytes_per_second.get());
        let burst = limit
            .max_burst_bytes
            .map_or(rate, |b| f64::from(b.get()))
            .max(udp::MAX_UDP_DATAGRAM as f64);
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * rate).min(burst);
        self.at = now;
        if self.tokens < len as f64 {
            return false;
        }
        self.tokens -= len as f64;
        true
    }
}

/// A connection's hold on the way, given back when the connection ends.
#[derive(Debug)]
pub(crate) struct UdpRegistration {
    socket: Arc<UdpSocket>,
    peers: Arc<DashMap<Token, Arc<Peer>>>,
    token: Token,
    peer: Arc<Peer>,
    buf: BytesMut,
}

impl Drop for UdpRegistration {
    fn drop(&mut self) {
        self.peers.remove(&self.token);
    }
}

impl UdpRegistration {
    /// Sends `datagrams` from `src` to the client over UDP, never by its WebSocket.
    pub(crate) fn send(&mut self, src: &EndpointId, datagrams: &Datagrams, metrics: &Metrics) {
        let Some(addr) = self.peer.state.lock().expect("poisoned").addr else {
            metrics.send_packets_dropped.inc();
            return;
        };
        let ecn = udp::ecn_byte(datagrams.ecn);
        for segment in udp::segments(&datagrams.contents, datagrams.segment_size) {
            if segment.len() > udp::MAX_UDP_DATAGRAM {
                metrics.send_packets_dropped.inc();
                continue;
            }
            udp::from_relay(&mut self.buf, src, ecn, segment);
            match self.socket.try_send_to(&self.buf, addr) {
                Ok(_) => {
                    metrics.bytes_sent.inc_by(segment.len() as u64);
                    metrics.udp_bytes_sent.inc_by(segment.len() as u64);
                    metrics.send_packets_sent.inc();
                }
                Err(err) => {
                    trace!("udp send: {err}");
                    metrics.send_packets_dropped.inc();
                }
            }
        }
    }
}

impl UdpRelay {
    /// Binds the socket and starts reading it.
    pub(crate) async fn bind(
        addr: SocketAddr,
        clients: Clients,
        key_cache: KeyCache,
        rate_limit: watch::Receiver<Option<ClientRateLimit>>,
        metrics: Arc<Metrics>,
    ) -> std::io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let local = socket.local_addr()?;
        let peers: Arc<DashMap<Token, Arc<Peer>>> = Default::default();
        let task = tokio::task::spawn(
            read(
                socket.clone(),
                peers.clone(),
                clients,
                key_cache,
                rate_limit,
                metrics,
            )
            .instrument(info_span!("relay-udp", %local)),
        );
        debug!(%local, "relay: udp on");
        Ok(Self {
            socket,
            local,
            peers,
            _task: AbortOnDropHandle::new(task),
        })
    }

    /// The port it is on.
    pub(crate) fn port(&self) -> u16 {
        self.local.port()
    }

    /// The address it is on.
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// A token for a connection to be offered.
    pub(crate) fn new_token() -> Token {
        rand::random()
    }

    /// Gives the way to an authorized connection.
    pub(crate) fn register(&self, token: Token, endpoint_id: EndpointId) -> UdpRegistration {
        let peer = Arc::new(Peer {
            endpoint_id,
            state: Mutex::new(PeerState {
                addr: None,
                bucket: Bucket {
                    tokens: f64::MAX,
                    at: Instant::now(),
                },
            }),
        });
        self.peers.insert(token, peer.clone());
        UdpRegistration {
            socket: self.socket.clone(),
            peers: self.peers.clone(),
            token,
            peer,
            buf: BytesMut::new(),
        }
    }
}

async fn read(
    socket: Arc<UdpSocket>,
    peers: Arc<DashMap<Token, Arc<Peer>>>,
    clients: Clients,
    key_cache: KeyCache,
    rate_limit: watch::Receiver<Option<ClientRateLimit>>,
    metrics: Arc<Metrics>,
) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let (len, from) = match socket.recv_from(&mut buf).await {
            Ok(read) => read,
            Err(err) => {
                // An ICMP unreachable from an earlier send, on some systems.
                trace!("udp recv: {err}");
                continue;
            }
        };
        let packet = Bytes::copy_from_slice(&buf[..len]);
        let now = Instant::now();
        match udp::read_to_relay(&packet) {
            Some(Packet::Hello { token, flags }) => {
                let Some(peer) = peers.get(&token).map(|p| p.clone()) else {
                    continue;
                };
                let moved = peer.state.lock().expect("poisoned").addr.replace(from) != Some(from);
                if moved {
                    debug!(endpoint = %peer.endpoint_id.fmt_short(), %from, hearing = flags & udp::FLAG_HEARING != 0, "udp from");
                }
                // Smaller than the hello: answering it sends nobody more than they sent.
                if let Err(err) = socket.try_send_to(&udp::hello_ack(), from) {
                    trace!("udp hello ack: {err}");
                }
            }
            Some(Packet::ToRelay {
                token,
                dst,
                ecn,
                contents,
            }) => {
                let Some(peer) = peers.get(&token).map(|p| p.clone()) else {
                    continue;
                };
                let Ok(dst) = key_cache.key_from_slice(&dst) else {
                    continue;
                };
                let limit = *rate_limit.borrow();
                {
                    let mut state = peer.state.lock().expect("poisoned");
                    state.addr = Some(from);
                    if !state.bucket.take(limit, contents.len(), now) {
                        metrics
                            .bytes_rx_ratelimited_total
                            .inc_by(contents.len() as u64);
                        continue;
                    }
                }
                metrics.bytes_recv.inc_by(contents.len() as u64);
                metrics.udp_bytes_recv.inc_by(contents.len() as u64);
                metrics.send_packets_recv.inc();
                let datagrams = Datagrams {
                    ecn: udp::ecn_codepoint(ecn),
                    segment_size: None,
                    contents,
                };
                if let Err(err) = clients.send_packet(dst, datagrams, peer.endpoint_id, &metrics) {
                    trace!("udp forward: {err:#}");
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroU32, time::Duration};

    use super::*;

    #[test]
    fn bucket_limits_like_the_websocket() {
        let start = Instant::now();
        let mut bucket = Bucket {
            tokens: f64::MAX,
            at: start,
        };
        let limit = ClientRateLimit {
            bytes_per_second: NonZeroU32::new(10_000).unwrap(),
            max_burst_bytes: NonZeroU32::new(3_000),
        };
        // Filled to the burst at first.
        assert!(bucket.take(Some(limit), 1_390, start));
        assert!(bucket.take(Some(limit), 1_390, start));
        assert!(!bucket.take(Some(limit), 1_390, start));
        // 10 000 a second: 1 390 more after 139 ms.
        assert!(bucket.take(Some(limit), 1_390, start + Duration::from_millis(140)));
        assert!(bucket.take(None, 1_000_000, start));
    }
}
