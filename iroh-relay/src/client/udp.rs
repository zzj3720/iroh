//! ember: a client's UDP way to its relay, beside the WebSocket (protos/udp.rs).

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use bytes::{Bytes, BytesMut};
use iroh_base::EndpointId;
use n0_future::task::AbortOnDropHandle;
use tokio::{net::UdpSocket, sync::mpsc, time::Instant};
use tracing::{Instrument, debug, info_span, trace};

use crate::{
    KeyCache,
    protos::{
        relay::{Datagrams, RelayToClientMsg},
        udp::{self, Packet, Token},
    },
};

/// The way, shared by a client's two halves.
#[derive(Debug)]
pub(crate) struct UdpLink {
    socket: UdpSocket,
    relay: SocketAddr,
    token: Token,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    /// When the relay was last heard over UDP.
    heard: Option<Instant>,
}

/// What each half holds: the way, and the task that reads it and says hello.
#[derive(Debug, Clone)]
pub(crate) struct UdpHalf {
    pub(crate) link: Arc<UdpLink>,
    _task: Arc<AbortOnDropHandle<()>>,
}

impl UdpLink {
    /// Opens the way to `relay` and starts saying hello; the datagrams it brings come on the receiver.
    pub(crate) async fn start(
        relay: SocketAddr,
        token: Token,
        key_cache: KeyCache,
    ) -> std::io::Result<(UdpHalf, mpsc::Receiver<RelayToClientMsg>)> {
        let any = match relay {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let socket = UdpSocket::bind(any).await?;
        let link = Arc::new(UdpLink {
            socket,
            relay,
            token,
            state: Mutex::new(State::default()),
        });
        let (tx, rx) = mpsc::channel(512);
        let task = n0_future::task::spawn(
            link.clone()
                .run(tx, key_cache)
                .instrument(info_span!("relay-udp", %relay)),
        );
        Ok((
            UdpHalf {
                link,
                _task: Arc::new(AbortOnDropHandle::new(task)),
            },
            rx,
        ))
    }

    /// Sends `datagrams` for `dst` over UDP: never by the WebSocket, so a way UDP does not go through shows as lost
    /// datagrams (what the relay's offer was asked for to find out).
    pub(crate) fn send(&self, dst: &EndpointId, datagrams: &Datagrams) {
        let ecn = udp::ecn_byte(datagrams.ecn);
        let mut out = BytesMut::new();
        for segment in udp::segments(&datagrams.contents, datagrams.segment_size) {
            if segment.len() > udp::MAX_UDP_DATAGRAM {
                trace!(
                    len = segment.len(),
                    "datagram larger than UDP takes, dropped"
                );
                continue;
            }
            udp::to_relay(&mut out, &self.token, dst, ecn, segment);
            // As a UDP socket would: a full send buffer drops the datagram.
            if let Err(err) = self.socket.try_send_to(&out, self.relay) {
                trace!("udp send: {err}");
            }
        }
    }

    fn hello(&self) {
        let now = Instant::now();
        let hearing = self
            .state
            .lock()
            .expect("poisoned")
            .heard
            .is_some_and(|t| now.duration_since(t) < udp::UDP_HELLO * 2);
        let flags = if hearing { udp::FLAG_HEARING } else { 0 };
        if let Err(err) = self
            .socket
            .try_send_to(&udp::hello(&self.token, flags), self.relay)
        {
            trace!("udp hello: {err}");
        }
    }

    async fn run(self: Arc<Self>, tx: mpsc::Sender<RelayToClientMsg>, key_cache: KeyCache) {
        let mut buf = vec![0u8; 64 * 1024];
        // The first at once: the relay learns where to send this client's datagrams.
        let mut hello = tokio::time::interval(udp::UDP_HELLO);
        hello.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                read = self.socket.recv_from(&mut buf) => {
                    let (len, from) = match read {
                        Ok(read) => read,
                        Err(err) => {
                            // An ICMP unreachable from an earlier send, on some systems; the next hello tries again.
                            trace!("udp recv: {err}");
                            continue;
                        }
                    };
                    if from != self.relay {
                        continue;
                    }
                    let packet = Bytes::copy_from_slice(&buf[..len]);
                    match udp::read_from_relay(&packet) {
                        Some(Packet::HelloAck) => {
                            let mut state = self.state.lock().expect("poisoned");
                            if state.heard.is_none() {
                                debug!("relay heard over udp");
                            }
                            state.heard = Some(Instant::now());
                        }
                        Some(Packet::FromRelay { src, ecn, contents }) => {
                            let Ok(src) = key_cache.key_from_slice(&src) else {
                                continue;
                            };
                            self.state.lock().expect("poisoned").heard = Some(Instant::now());
                            let msg = RelayToClientMsg::Datagrams {
                                remote_endpoint_id: src,
                                datagrams: Datagrams {
                                    ecn: udp::ecn_codepoint(ecn),
                                    segment_size: None,
                                    contents,
                                },
                            };
                            match tx.try_send(msg) {
                                Ok(()) => {}
                                // As a UDP socket's receive buffer would.
                                Err(mpsc::error::TrySendError::Full(_)) => trace!("udp receive queue full, dropped"),
                                Err(mpsc::error::TrySendError::Closed(_)) => return,
                            }
                        }
                        _ => {}
                    }
                }
                _ = hello.tick() => self.hello(),
            }
            if tx.is_closed() {
                return;
            }
        }
    }
}
