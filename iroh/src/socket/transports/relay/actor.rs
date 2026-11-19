//! The relay actor.
//!
//! The [`RelayActor`] handles all the relay connections.  It is helped by the
//! [`ActiveRelayActor`] which handles a single relay connection.
//!
//! - The [`RelayActor`] manages all connections to relay servers.
//!   - It starts a new [`ActiveRelayActor`] for each relay server needed.
//!   - The [`ActiveRelayActor`] will exit when unused.
//!     - Unless it is for the home relay, this one never exits.
//!   - Each [`ActiveRelayActor`] uses a relay [`Client`].
//!     - The relay [`Client`] is a `Stream` and `Sink` directly connected to the
//!       `TcpStream` connected to the relay server.
//!   - Each [`ActiveRelayActor`] will try and maintain a connection with the relay server.
//!     - If connections fail, exponential backoff is used for reconnections.
//! - When `AsyncUdpSocket` needs to send datagrams:
//!   - It puts them on a queue to the [`RelayActor`].
//!   - The [`RelayActor`] ensures the correct [`ActiveRelayActor`] is running and
//!     forwards datagrams to it.
//!   - The ActiveRelayActor sends datagrams directly to the relay server.
//! - The relay receive path is:
//!   - Whenever [`ActiveRelayActor`] is connected it reads from the underlying `TcpStream`.
//!   - Received datagrams are placed on an mpsc channel that now bypasses the
//!     [`RelayActor`] and goes straight to the `AsyncUpdSocket` interface.
//!
//! [`Client`]: iroh_relay::client::Client

#[cfg(test)]
use std::net::SocketAddr;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    net::IpAddr,
    pin::{Pin, pin},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use backon::{Backoff, BackoffBuilder, ExponentialBuilder};
use iroh_base::{EndpointId, RelayUrl, SecretKey};
use iroh_relay::{
    self as relay, PingTracker, RelayConfig, RelayMap,
    client::{Client, ConnectError, RecvError, SendError},
    protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg, Status},
};
use n0_error::{AnyError, e, stack_error};
use n0_future::{
    FuturesUnorderedBounded, MaybeFuture, SinkExt, StreamExt,
    task::{self, AbortOnDropHandle, JoinSet},
    time::{self, Duration, Instant, MissedTickBehavior},
};
use n0_watcher::Watchable;
use netwatch::interfaces;
use tokio::sync::mpsc;
#[cfg(test)]
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, Level, debug, error, event, info, info_span, instrument, trace, warn};
use url::Url;

#[cfg(not(wasm_browser))]
use crate::dns::DnsResolver;
use crate::{endpoint::RelayStatus, net_report::Report, socket::Metrics as SocketMetrics};

/// How long a non-home relay connection needs to be idle (last written to) before we close it.
const RELAY_INACTIVE_CLEANUP_TIME: Duration = Duration::from_secs(60);

/// Interval in which we ping the relay server to ensure the connection is alive.
///
/// The default QUIC max_idle_timeout is 30s, so setting that to half this time gives some
/// chance of recovering.
const PING_INTERVAL: Duration = Duration::from_secs(15);

/// Number of datagrams which can be sent to the relay server in one batch.
///
/// This means while this batch is sending to the server no other relay protocol frames can
/// be sent to the server, e.g. no Ping frames or so.  While the maximum packet size is
/// rather large, each item can typically be expected to up to 1500 or the max GSO size.
const SEND_DATAGRAM_BATCH_SIZE: usize = 64;

/// ember: the longest a datagram waits to be sent to the relay server before it is dropped instead.
///
/// The relay server drops what waits longer than its `MAX_PACKET_WAIT` for a slow client; this is the same on the
/// client's side. Queued behind a slow uplink or a relay connection being dialed again, a datagram sent seconds late is
/// no use to QUIC and makes its round trip seconds long (2.5–3.9 s seen, still.fail's devices on one self-hosted relay).
/// Dropped, the sender's congestion control slows to what the link takes.
const MAX_SEND_DATAGRAM_WAIT: Duration = Duration::from_millis(500);

/// Timeout for establishing the relay connection.
///
/// This includes DNS, dialing the server, upgrading the connection, and completing the
/// handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Recheck alternate entrances to one relay without registering the endpoint's key on it twice.
const ENTRY_PROBE_INTERVAL: Duration = Duration::from_secs(30);

/// ember: how long closing a relay connection gracefully may take; a dead one would otherwise hold its actor.
const CLIENT_SINK_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

/// Time after which the [`ActiveRelayActor`] will drop undeliverable datagrams.
///
/// When the [`ActiveRelayActor`] is not connected it can not deliver datagrams.  However it
/// will still receive datagrams to send from the [`RelayActor`].  If connecting takes
/// longer than this timeout datagrams will be dropped.
///
/// This value is set to 3 times the QUIC initial Probe Timeout (PTO).
const UNDELIVERABLE_DATAGRAM_TIMEOUT: Duration = Duration::from_secs(3);

/// An actor which handles the connection to a single relay server.
///
/// It is responsible for maintaining the connection to the relay server and handling all
/// communication with it.
///
/// The actor shuts down itself on inactivity: inactivity is determined when no more
/// datagrams are being queued to send.
///
/// This actor has 3 main states it can be in, each has it's dedicated run loop:
///
/// - Dialing the relay server.
///
///   This will continuously dial the server until connected, using exponential backoff if
///   it can not connect.  See [`ActiveRelayActor::run_dialing`].
///
/// - Connected to the relay server.
///
///   This state allows receiving from the relay server, though sending is idle in this
///   state.  See [`ActiveRelayActor::run_connected`].
///
/// - Sending to the relay server.
///
///   This is a sub-state of `connected` so the actor can still be receiving from the relay
///   server at this time.  However it is actively sending data to the server so can not
///   consume any further items from inboxes which will result in sending more data to the
///   server until the actor goes back to the `connected` state.
///
/// All these are driven from the top-level [`ActiveRelayActor::run`] loop.
#[derive(Debug)]
struct ActiveRelayActor {
    // The inboxes and channels this actor communicates over.
    /// ember: the endpoints reachable through this relay while connected, read by the [`RelayActor`] without asking
    /// this actor (`ActiveRelayHandle::endpoints_present`).
    endpoints_present: EndpointsPresent,
    /// Inbox for messages which involve sending to the relay server.
    inbox: mpsc::Receiver<ActiveRelayMessage>,
    /// Queue for received relay datagrams.
    relay_datagrams_recv: mpsc::Sender<RelayRecvDatagram>,
    /// Channel on which we queue packets to send to the relay.
    relay_datagrams_send: mpsc::Receiver<RelaySendItem>,

    // Other actor state.
    /// The relay server for this actor.
    url: RelayUrl,
    /// Builder which can repeatedly build a relay client.
    relay_client_builder: relay::client::ClientBuilder,
    /// The address the existing relay connection uses, and the options for dialing another entrance.
    access: RelayUrl,
    connection_opts: RelayConnectionOptions,
    entries: Vec<RelayUrl>,
    candidate: Option<(RelayUrl, u8)>,
    has_compared: bool,
    last_samples: Vec<(RelayUrl, Duration)>,
    probe_now: Arc<tokio::sync::Notify>,
    _entry_probes: Option<AbortOnDropHandle<()>>,
    /// ember: whether the relay's UDP way is asked for, read at each dial.
    udp: Arc<AtomicBool>,
    /// Whether or not this is the home relay server.
    ///
    /// The home relay server needs to maintain it's connection to the relay server, even if
    /// the relay actor is otherwise idle.
    is_home_relay: bool,
    /// When this expires the actor has been idle and should shut down.
    ///
    /// Unless it is managing the home relay connection.  Inactivity is only tracked on the
    /// last datagram sent to the relay, received datagrams will trigger QUIC ACKs which is
    /// sufficient to keep active connections open.
    inactive_timeout: Pin<Box<time::Sleep>>,
    /// Token indicating the [`ActiveRelayActor`] should stop.
    stop_token: CancellationToken,
    metrics: Arc<SocketMetrics>,
    my_relay: HomeRelayWatch,
}

#[derive(Debug)]
enum ActiveRelayMessage {
    /// Triggers a connection check to the relay server.
    ///
    /// Sometimes it is known the local network interfaces have changed in which case it
    /// might be prudent to check if the relay connection is still working.  `Vec<IpAddr>`
    /// should contain the current local IP addresses.  If the connection uses a local
    /// socket with an IP address in this list the relay server will be pinged.  If the
    /// connection uses a local socket with an IP address not in this list the server will
    /// always re-connect.
    CheckConnection { local_ips: Vec<IpAddr> },
    /// Sets this relay as the home relay, or not.
    SetHomeRelay(bool),
    /// Recent round trips to this relay over each of its possible entrances.
    EntrySamples(Vec<(RelayUrl, Duration)>),
    /// Entrances changed while the relay connection is already running.
    UpdateEntries(Vec<RelayUrl>, mpsc::Sender<ActiveRelayMessage>),
    /// ember: the link dialed again (`Endpoint::set_relay_udp`); none is dialed while not connected.
    Reconnect,
    #[cfg(test)]
    GetLocalAddr(oneshot::Sender<Option<SocketAddr>>),
    #[cfg(test)]
    PingServer(oneshot::Sender<()>),
}

/// ember: the endpoints reachable through one relay connection, written by its [`ActiveRelayActor`] and read by the
/// [`RelayActor`] when it looks for a relay that reaches an endpoint. Upstream the [`RelayActor`] asked each actor
/// (`HasEndpointRoute`) and waited for every answer; one actor dialing again, backing off or closing a dead connection
/// held every datagram of the transport, to every relay, until it answered.
type EndpointsPresent = Arc<std::sync::RwLock<BTreeSet<EndpointId>>>;

/// ember: empties [`EndpointsPresent`] as a connection ends, however it ends (returned, failed, or cancelled).
struct ClearOnDrop(EndpointsPresent);

impl Drop for ClearOnDrop {
    fn drop(&mut self) {
        self.0.write().expect("poisoned").clear();
    }
}

/// Configuration needed to start an [`ActiveRelayActor`].
#[derive(Debug)]
struct ActiveRelayActorOptions {
    url: RelayUrl,
    endpoints_present: EndpointsPresent,
    inbox: mpsc::Receiver<ActiveRelayMessage>,
    relay_datagrams_send: mpsc::Receiver<RelaySendItem>,
    relay_datagrams_recv: mpsc::Sender<RelayRecvDatagram>,
    connection_opts: RelayConnectionOptions,
    entries: Vec<RelayUrl>,
    stop_token: CancellationToken,
    metrics: Arc<SocketMetrics>,
    my_relay: HomeRelayWatch,
}

/// Configuration needed to create a connection to a relay server.
#[derive(Debug, Clone)]
struct RelayConnectionOptions {
    secret_key: SecretKey,
    #[cfg(not(wasm_browser))]
    dns_resolver: DnsResolver,
    proxy_url: Option<Url>,
    prefer_ipv6: Arc<AtomicBool>,
    tls_config: rustls::ClientConfig,
    auth_token: Option<String>,
    /// ember: whether to ask the relay for its UDP way, read at each dial.
    udp: Arc<AtomicBool>,
}

/// Possible reasons for a failed relay connection.
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
enum RelayConnectionError {
    #[error("Failed to connect to relay server")]
    Dial { source: DialError },
    #[error("Failed to handshake with relay server")]
    Handshake { source: RunError },
    #[error("Lost connection to relay server")]
    Established { source: RunError },
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
enum RunError {
    #[error("Send timeout")]
    SendTimeout,
    #[error("Ping timeout")]
    PingTimeout,
    #[error("Local IP no longer valid")]
    LocalIpInvalid,
    #[error("No local address")]
    LocalAddrMissing,
    #[error("Stream closed by server.")]
    StreamClosedServer,
    #[error("Dialed again, as asked")]
    Reconnect,
    #[error("Client stream read failed")]
    ClientStreamRead {
        #[error(std_err)]
        source: RecvError,
    },
    #[error("Client stream write failed")]
    ClientStreamWrite {
        #[error(std_err)]
        source: SendError,
    },
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
enum DialError {
    #[error("timeout (>{timeout:?}) trying to establish a connection")]
    Timeout { timeout: Duration },
    #[error("unable to connect")]
    Connect { source: ConnectError },
}

impl ActiveRelayActor {
    fn new(opts: ActiveRelayActorOptions) -> Self {
        let ActiveRelayActorOptions {
            url,
            endpoints_present,
            inbox,
            relay_datagrams_send,
            relay_datagrams_recv,
            connection_opts,
            entries,
            stop_token,
            metrics,
            my_relay,
        } = opts;
        let udp = connection_opts.udp.clone();
        let relay_client_builder = Self::create_relay_builder(url.clone(), connection_opts.clone());
        ActiveRelayActor {
            endpoints_present,
            inbox,
            relay_datagrams_recv,
            relay_datagrams_send,
            access: url.clone(),
            url,
            relay_client_builder,
            connection_opts,
            entries,
            candidate: None,
            has_compared: false,
            last_samples: Vec::new(),
            probe_now: Arc::new(tokio::sync::Notify::new()),
            _entry_probes: None,
            udp,
            is_home_relay: false,
            inactive_timeout: Box::pin(time::sleep(RELAY_INACTIVE_CLEANUP_TIME)),
            stop_token,
            metrics,
            my_relay,
        }
    }

    fn create_relay_builder(
        url: RelayUrl,
        opts: RelayConnectionOptions,
    ) -> relay::client::ClientBuilder {
        let RelayConnectionOptions {
            secret_key,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            proxy_url,
            prefer_ipv6,
            tls_config,
            auth_token,
            udp,
        } = opts;

        let mut builder = relay::client::ClientBuilder::new(
            url,
            secret_key,
            #[cfg(not(wasm_browser))]
            dns_resolver,
        )
        .tls_client_config(tls_config)
        .address_family_selector(move || prefer_ipv6.load(Ordering::Relaxed));
        let _ = udp;
        if let Some(proxy_url) = proxy_url {
            builder = builder.proxy_url(proxy_url);
        }

        if let Some(token) = auth_token {
            builder = builder.auth_token(token);
        }
        builder
    }

    /// Compare entrances using short-lived, distinct identities. A probe using our endpoint's identity would make the
    /// relay deactivate its live connection, even though the entrance and the relay have different URLs.
    fn start_entry_probes(&mut self, sender: mpsc::Sender<ActiveRelayMessage>) {
        self._entry_probes = None;
        if self.entries.is_empty() {
            return;
        }
        let mut urls = vec![self.url.clone()];
        for entry in &self.entries {
            if !urls.contains(entry) {
                urls.push(entry.clone());
            }
        }
        let opts = self.connection_opts.clone();
        let probe_now = self.probe_now.clone();
        self._entry_probes = Some(AbortOnDropHandle::new(task::spawn(async move {
            loop {
                let attempts = urls.iter().cloned().map(|url| {
                    let opts = opts.clone();
                    async move { Self::probe_entry(url, opts).await }
                });
                let mut pending = FuturesUnorderedBounded::from_iter(attempts);
                let mut samples = Vec::new();
                while let Some(sample) = pending.next().await {
                    if let Some(sample) = sample {
                        samples.push(sample);
                    }
                }
                if sender
                    .send(ActiveRelayMessage::EntrySamples(samples))
                    .await
                    .is_err()
                {
                    break;
                }
                tokio::select! {
                    _ = time::sleep(ENTRY_PROBE_INTERVAL) => {},
                    _ = probe_now.notified() => {},
                }
            }
        })));
    }

    async fn probe_entry(
        url: RelayUrl,
        mut opts: RelayConnectionOptions,
    ) -> Option<(RelayUrl, Duration)> {
        opts.secret_key = SecretKey::generate();
        let builder = Self::create_relay_builder(url.clone(), opts);
        time::timeout(CONNECT_TIMEOUT, async move {
            let client = builder.connect().await.ok()?;
            let (mut stream, mut sink) = client.split();
            let mut samples = Vec::new();
            for _ in 0..3 {
                let ping: [u8; 8] = rand::random();
                let started = Instant::now();
                sink.send(ClientToRelayMsg::Ping(ping)).await.ok()?;
                loop {
                    match stream.next().await? {
                        Ok(RelayToClientMsg::Pong(got)) if got == ping => {
                            samples.push(started.elapsed());
                            break;
                        }
                        Ok(_) => {}
                        Err(_) => return None,
                    }
                }
            }
            samples.sort();
            let _ = sink.close().await;
            Some((url, samples[1]))
        })
        .await
        .ok()
        .flatten()
    }

    /// Keep a working entrance unless another is consistently better. A missing probe is not evidence that the
    /// existing connection has failed; `run` chooses a measured alternate if the connection itself fails.
    /// This is per relay, not per station: both entrances arrive at the same relay and share its station leg.
    fn choose_entry(&mut self, samples: &[(RelayUrl, Duration)]) -> Option<RelayUrl> {
        let Some(current) = samples
            .iter()
            .find(|(url, _)| *url == self.access)
            .map(|(_, rtt)| *rtt)
        else {
            self.candidate = None;
            return None;
        };
        let (best, best_rtt) = samples
            .iter()
            .filter(|(url, _)| *url == self.url || self.entries.contains(url))
            .min_by_key(|(_, rtt)| *rtt)?;
        let first_comparison = !self.has_compared;
        self.has_compared = true;
        if *best == self.access {
            self.candidate = None;
            return None;
        }
        if *best_rtt * 5 >= current * 4 {
            self.candidate = None;
            return None;
        }
        let count = match &self.candidate {
            Some((url, count)) if url == best => count.saturating_add(1),
            _ => 1,
        };
        self.candidate = Some((best.clone(), count));
        if count < 2 && !first_comparison {
            return None;
        }
        self.candidate = None;
        Some(best.clone())
    }

    fn set_access(&mut self, access: RelayUrl) {
        self.relay_client_builder =
            Self::create_relay_builder(access.clone(), self.connection_opts.clone());
        self.my_relay.set_access(&self.url, access.clone());
        self.access = access;
    }

    fn update_entries(
        &mut self,
        entries: Vec<RelayUrl>,
        sender: mpsc::Sender<ActiveRelayMessage>,
    ) -> bool {
        self.entries = entries;
        self.candidate = None;
        self.has_compared = false;
        self.last_samples
            .retain(|(url, _)| *url == self.url || self.entries.contains(url));
        self.start_entry_probes(sender);
        self.access != self.url && !self.entries.contains(&self.access)
    }

    /// The main actor run loop.
    ///
    /// Primarily switches between the dialing and connected states.
    async fn run(mut self) {
        let mut backoff = Self::build_backoff();

        while let Err(err) = self.run_once().await {
            warn!("{err:#}");
            let was_established = matches!(err, RelayConnectionError::Established { .. });
            let last_error = Some(Arc::new(AnyError::from(err)));
            self.my_relay
                .set_status(&self.url, RelayConnectionState::Disconnected { last_error });
            // A dead entrance should not hold the connection until the next periodic measurement. Try an entrance
            // that answered the last measurement and start a fresh comparison in case the network has changed.
            let alternate = if self.access != self.url && !self.entries.contains(&self.access) {
                Some(self.url.clone())
            } else {
                self.last_samples
                    .iter()
                    .filter(|(url, _)| {
                        *url != self.access && (*url == self.url || self.entries.contains(url))
                    })
                    .min_by_key(|(_, rtt)| *rtt)
                    .map(|(url, _)| url.clone())
            };
            if let Some(access) = alternate {
                self.set_access(access);
            }
            self.probe_now.notify_one();
            if !was_established {
                // If dialing failed, or if the relay connection failed before we received a pong,
                // we wait an exponentially increasing time until we attempt to reconnect again.
                let Some(delay) = backoff.next() else {
                    warn!("retries exceeded");
                    break;
                };
                debug!("retry in {delay:?}");
                if !self.sleep_backoff(delay).await {
                    break;
                }
            } else {
                // If the relay connection remained established long enough so that we received a pong
                // from the relay server, we reset the backoff and attempt to reconnect immediately.
                backoff = Self::build_backoff();
            }
        }
        debug!("exiting");
    }

    /// ember: waits `delay` before dialing again, while still taking its inbox and stopping when told. Upstream slept
    /// through it (up to 16 s): it neither stopped nor took a message meanwhile. Returns `false` if the actor is to
    /// exit.
    async fn sleep_backoff(&mut self, delay: Duration) -> bool {
        let sleep = time::sleep(delay);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                biased;
                _ = self.stop_token.cancelled() => {
                    debug!("Shutdown.");
                    return false;
                }
                msg = self.inbox.recv() => {
                    let Some(msg) = msg else {
                        debug!("Inbox closed, shutdown.");
                        return false;
                    };
                    // As `run_dialing` takes them; the next dial uses the entrance chosen.
                    match msg {
                        ActiveRelayMessage::SetHomeRelay(is_home) => {
                            self.set_home_relay(is_home);
                        }
                        ActiveRelayMessage::EntrySamples(samples) => {
                            self.last_samples = samples.clone();
                            if let Some(access) = self.choose_entry(&samples) {
                                self.set_access(access);
                            }
                        }
                        ActiveRelayMessage::UpdateEntries(entries, sender) => {
                            if self.update_entries(entries, sender) {
                                self.set_access(self.url.clone());
                            }
                        }
                        ActiveRelayMessage::CheckConnection { .. } | ActiveRelayMessage::Reconnect => {}
                        #[cfg(test)]
                        ActiveRelayMessage::GetLocalAddr(sender) => {
                            sender.send(None).ok();
                        }
                        #[cfg(test)]
                        ActiveRelayMessage::PingServer(sender) => {
                            drop(sender);
                        }
                    }
                }
                _ = &mut sleep => return true,
            }
        }
    }

    fn build_backoff() -> impl Backoff {
        ExponentialBuilder::new()
            .with_min_delay(Duration::from_millis(10))
            .with_max_delay(Duration::from_secs(16))
            .with_jitter()
            .without_max_times()
            .build()
    }

    /// Attempt to connect to the relay, and run the connected actor loop.
    ///
    /// Returns `Ok(())` if the actor loop should shut down. Returns an error if dialing failed,
    /// or if the relay connection failed while connected. In both cases, the connection should
    /// be retried with a backoff.
    async fn run_once(&mut self) -> Result<(), RelayConnectionError> {
        self.my_relay
            .set_status(&self.url, RelayConnectionState::Connecting);
        let mut client = match self.run_dialing().instrument(info_span!("dialing")).await {
            Some(client_res) => client_res.map_err(|err| e!(RelayConnectionError::Dial, err))?,
            None => return Ok(()),
        };
        self.my_relay
            .set_status(&self.url, RelayConnectionState::Connected);
        loop {
            match self
                .run_connected(client)
                .instrument(info_span!("connected"))
                .await?
            {
                Some(next) => {
                    // A connection made anew (another entrance): the relay takes it as the active one.
                    self.my_relay.set_same_endpoint_id_connected(&self.url, false);
                    client = next
                }
                None => return Ok(()),
            }
        }
    }

    fn reset_inactive_timeout(&mut self) {
        self.inactive_timeout
            .as_mut()
            .reset(Instant::now() + RELAY_INACTIVE_CLEANUP_TIME);
    }

    fn set_home_relay(&mut self, is_home: bool) {
        let prev = std::mem::replace(&mut self.is_home_relay, is_home);
        if self.is_home_relay != prev {
            event!(
                target: "iroh::_events::relay::home_changed",
                Level::DEBUG,
                url = %self.url,
                home_relay = self.is_home_relay,
            );
        }
    }

    /// Actor loop when connecting to the relay server.
    ///
    /// Returns `None` if the actor needs to shut down.  Returns `Some(Ok(client))` when the
    /// connection is established, and `Some(Err(err))` if dialing the relay failed.
    async fn run_dialing(&mut self) -> Option<Result<iroh_relay::client::Client, DialError>> {
        trace!("Actor loop: connecting to relay.");

        // We regularly flush the relay_datagrams_send queue so it is not full of stale
        // packets while reconnecting.  Those datagrams are dropped and the QUIC congestion
        // controller will have to handle this (DISCO packets do not yet have retry).  This
        // is not an ideal mechanism, an alternative approach would be to use
        // e.g. ConcurrentQueue with force_push, though now you might still send very stale
        // packets when eventually connected.  So perhaps this is a reasonable compromise.
        let mut send_datagram_flush = time::interval(UNDELIVERABLE_DATAGRAM_TIMEOUT);
        send_datagram_flush.set_missed_tick_behavior(MissedTickBehavior::Delay);
        send_datagram_flush.reset(); // Skip the immediate interval

        let dialing_fut = self.dial_relay();
        tokio::pin!(dialing_fut);
        loop {
            tokio::select! {
                biased;
                _ = self.stop_token.cancelled() => {
                    debug!("Shutdown.");
                    break None;
                }
                res = &mut dialing_fut => {
                    match res {
                        Ok(client) => {
                            break Some(Ok(client));
                        }
                        Err(err) => {
                            break Some(Err(err));
                        }
                    }
                }
                msg = self.inbox.recv() => {
                    let Some(msg) = msg else {
                        debug!("Inbox closed, shutdown.");
                        break None;
                    };
                    match msg {
                        ActiveRelayMessage::SetHomeRelay(is_home) => {
                            self.set_home_relay(is_home);
                        }
                        ActiveRelayMessage::EntrySamples(samples) => {
                            self.last_samples = samples.clone();
                            if let Some(access) = self.choose_entry(&samples) {
                                self.set_access(access);
                                dialing_fut.set(self.dial_relay());
                            }
                        }
                        ActiveRelayMessage::UpdateEntries(entries, sender) => {
                            if self.update_entries(entries, sender) {
                                self.set_access(self.url.clone());
                                dialing_fut.set(self.dial_relay());
                            }
                        }
                        ActiveRelayMessage::CheckConnection { .. } | ActiveRelayMessage::Reconnect => {}
                        #[cfg(test)]
                        ActiveRelayMessage::GetLocalAddr(sender) => {
                            sender.send(None).ok();
                        }
                        #[cfg(test)]
                        ActiveRelayMessage::PingServer(sender) => {
                            drop(sender);
                        }
                    }
                }
                _ = send_datagram_flush.tick() => {
                    self.reset_inactive_timeout();
                    let mut logged = false;
                    while self.relay_datagrams_send.try_recv().is_ok() {
                        if !logged {
                            debug!(?UNDELIVERABLE_DATAGRAM_TIMEOUT, "Dropping datagrams to send.");
                            logged = true;
                        }
                    }
                }
                _ = &mut self.inactive_timeout, if !self.is_home_relay => {
                    debug!(?RELAY_INACTIVE_CLEANUP_TIME, "Inactive, exiting.");
                    break None;
                }
            }
        }
    }

    /// Returns a future which will complete once connected to the relay server.
    ///
    /// The future only completes once the connection is established and retries
    /// connections.  It currently does not ever return `Err` as the retries continue
    /// forever.
    // This is using `impl Future` to return a future without a reference to self.
    fn dial_relay(&self) -> impl Future<Output = Result<Client, DialError>> + use<> {
        let client_builder = self.relay_client_builder.clone();
        // ember: the UDP way asked for as the endpoint says now (`Endpoint::set_relay_udp`).
        #[cfg(not(wasm_browser))]
        let client_builder = client_builder.udp(self.udp.load(Ordering::Relaxed));
        async move {
            match time::timeout(CONNECT_TIMEOUT, client_builder.connect()).await {
                Ok(Ok(client)) => Ok(client),
                Ok(Err(err)) => Err(e!(DialError::Connect, err)),
                Err(_) => Err(e!(DialError::Timeout {
                    timeout: CONNECT_TIMEOUT
                })),
            }
        }
    }

    /// Connect another entrance before releasing the current socket. The relay makes the new socket active only once
    /// it authenticates; the old one is then closed, so the same identity does not keep displacing itself.
    fn dial_entry(
        &self,
        access: RelayUrl,
    ) -> impl Future<Output = Result<Client, DialError>> + use<> {
        let builder = Self::create_relay_builder(access, self.connection_opts.clone());
        #[cfg(not(wasm_browser))]
        let builder = builder.udp(self.udp.load(Ordering::Relaxed));
        async move {
            match time::timeout(CONNECT_TIMEOUT, builder.connect()).await {
                Ok(Ok(client)) => Ok(client),
                Ok(Err(err)) => Err(e!(DialError::Connect, err)),
                Err(_) => Err(e!(DialError::Timeout {
                    timeout: CONNECT_TIMEOUT
                })),
            }
        }
    }

    /// Runs the actor loop when connected to a relay server.
    ///
    /// Returns `Ok` if the actor needs to shut down.  `Err` is returned if the connection
    /// to the relay server is lost.
    async fn run_connected(
        &mut self,
        client: iroh_relay::client::Client,
    ) -> Result<Option<Client>, RelayConnectionError> {
        trace!("Actor loop: connected to relay");
        event!(
            target: "iroh::_events::relay::connected",
            Level::DEBUG,
            url = %self.url,
            home_relay = self.is_home_relay,
        );

        let (mut client_stream, client_sink) = client.split();
        let mut client_sink = client_sink.sink_map_err(|e| e!(RunError::ClientStreamWrite, e));

        let _endpoints_present = ClearOnDrop(self.endpoints_present.clone());
        let mut state = ConnectedRelayState {
            ping_tracker: PingTracker::default(),
            last_packet_src: None,
            pong_pending: None,
            established: false,
            same_endpoint_id_connected: false,
            #[cfg(test)]
            test_pong: None,
        };

        // A buffer to pass through multiple datagrams at once as an optimisation.
        let mut send_datagrams_buf = Vec::with_capacity(SEND_DATAGRAM_BATCH_SIZE);

        // Regularly send pings so we know the connection is healthy.
        // The first ping will be sent immediately.
        let mut ping_interval = time::interval(PING_INTERVAL);
        ping_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut replacement = std::pin::pin!(MaybeFuture::None);
        let mut replacement_access: Option<RelayUrl> = None;

        let res = loop {
            if let Some(data) = state.pong_pending.take() {
                let fut = client_sink.send(ClientToRelayMsg::Pong(data));
                self.run_sending(fut, &mut state, &mut client_stream)
                    .await?;
            }
            tokio::select! {
                biased;
                _ = self.stop_token.cancelled() => {
                    debug!("Shutdown.");
                    break Ok(None);
                }
                _ = state.ping_tracker.timeout() => {
                    break Err(e!(RunError::PingTimeout));
                }
                _ = ping_interval.tick() => {
                    let data = state.ping_tracker.new_ping();
                    let fut = client_sink.send(ClientToRelayMsg::Ping(data));
                    self.run_sending(fut, &mut state, &mut client_stream).await?;
                }
                msg = self.inbox.recv() => {
                    let Some(msg) = msg else {
                        warn!("Inbox closed, shutdown.");
                        break Ok(None);
                    };
                    match msg {
                        ActiveRelayMessage::SetHomeRelay(is_home) => {
                            self.set_home_relay(is_home);
                            // We are in `run_connected`, so if we just became the home
                            // relay, publish `Connected` (the `RelayActor` only sets
                            // `Connecting` on the URL change since it cannot know our
                            // actual state).
                            if is_home {
                                self.my_relay
                                    .set_status(&self.url, RelayConnectionState::Connected);
                                self.my_relay.set_access(&self.url, self.access.clone());
                                // What the relay said of this connection before it was home.
                                self.my_relay.set_same_endpoint_id_connected(
                                    &self.url,
                                    state.same_endpoint_id_connected,
                                );
                            }
                        }
                        ActiveRelayMessage::EntrySamples(samples) => {
                            self.last_samples = samples.clone();
                            if replacement.is_none() {
                                if let Some(access) = self.choose_entry(&samples) {
                                    replacement.as_mut().set_future(self.dial_entry(access.clone()));
                                    replacement_access = Some(access);
                                }
                            }
                        }
                        ActiveRelayMessage::UpdateEntries(entries, sender) => {
                            let needs_default = self.update_entries(entries, sender);
                            if replacement_access.as_ref().is_some_and(|access| *access != self.url && !self.entries.contains(access)) {
                                replacement.as_mut().set_none();
                                replacement_access = None;
                            }
                            if needs_default && replacement.is_none() {
                                let access = self.url.clone();
                                replacement.as_mut().set_future(self.dial_entry(access.clone()));
                                replacement_access = Some(access);
                            }
                        }
                        ActiveRelayMessage::Reconnect => break Err(e!(RunError::Reconnect)),
                        ActiveRelayMessage::CheckConnection { local_ips } => {
                            match client_stream.local_addr() {
                                Some(addr) if local_ips.contains(&addr.ip()) => {
                                    let data = state.ping_tracker.new_ping();
                                    let fut = client_sink.send(ClientToRelayMsg::Ping(data));
                                    self.run_sending(fut, &mut state, &mut client_stream).await?;
                                }
                                Some(_) => break Err(e!(RunError::LocalIpInvalid)),
                                None => break Err(e!(RunError::LocalAddrMissing)),
                            }
                        }
                        #[cfg(test)]
                        ActiveRelayMessage::GetLocalAddr(sender) => {
                            let addr = client_stream.local_addr();
                            sender.send(addr).ok();
                        }
                        #[cfg(test)]
                        ActiveRelayMessage::PingServer(sender) => {
                            let data = rand::random();
                            state.test_pong = Some((data, sender));
                            let fut = client_sink.send(ClientToRelayMsg::Ping(data));
                            self.run_sending(fut, &mut state, &mut client_stream).await?;
                        }
                    }
                }
                result = &mut replacement, if replacement.is_some() => {
                    replacement.as_mut().set_none();
                    match result {
                        Ok(client) => {
                            self.set_access(replacement_access.take().expect("entry dial has an address"));
                            break Ok(Some(client));
                        }
                        Err(err) => {
                            debug!("alternate relay entrance failed: {err:#}");
                            replacement_access = None;
                        }
                    }
                }
                count = self.relay_datagrams_send.recv_many(
                    &mut send_datagrams_buf,
                    SEND_DATAGRAM_BATCH_SIZE,
                ) => {
                    if count == 0 {
                        warn!("Datagram inbox closed, shutdown");
                        break Ok(None);
                    };
                    self.reset_inactive_timeout();
                    // ember: what waited too long is dropped, not sent late (`MAX_SEND_DATAGRAM_WAIT`).
                    let now = Instant::now();
                    send_datagrams_buf.retain(|item| {
                        let stale = item
                            .queued
                            .is_some_and(|queued| now.duration_since(queued) > MAX_SEND_DATAGRAM_WAIT);
                        if stale {
                            trace!(?MAX_SEND_DATAGRAM_WAIT, "datagram waited too long, dropping");
                        }
                        !stale
                    });
                    if send_datagrams_buf.is_empty() {
                        continue;
                    }
                    // TODO(frando): can we avoid the clone here?
                    let metrics = self.metrics.clone();
                    let packet_iter = send_datagrams_buf.drain(..).map(|item| {
                        metrics.send_relay.inc_by(item.datagrams.contents.len() as _);
                        Ok(ClientToRelayMsg::Datagrams {
                            dst_endpoint_id: item.remote_endpoint,
                            datagrams: item.datagrams,
                        })
                    });
                    let mut packet_stream = n0_future::stream::iter(packet_iter);
                    let fut = client_sink.send_all(&mut packet_stream);
                    self.run_sending(fut, &mut state, &mut client_stream).await?;
                }
                msg = client_stream.next() => {
                    let Some(msg) = msg else {
                        break Err(e!(RunError::StreamClosedServer));
                    };
                    match msg {
                        Ok(msg) => {
                            self.handle_relay_msg(msg, &mut state);
                            // reset the ping timer, we have just received a message
                            ping_interval.reset();
                        },
                        Err(err) => break Err(e!(RunError::ClientStreamRead, err)),
                    }
                }
                _ = &mut self.inactive_timeout, if !self.is_home_relay => {
                    debug!("Inactive for {RELAY_INACTIVE_CLEANUP_TIME:?}, exiting (running).");
                    break Ok(None);
                }
            }
        };

        // ember: bounded, a dead connection does not hold the actor (and its inboxes) up.
        if matches!(res, Ok(None)) {
            match time::timeout(CLIENT_SINK_CLOSE_TIMEOUT, client_sink.close()).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => debug!("Failed to close client sink gracefully: {err:#}"),
                Err(_) => debug!(?CLIENT_SINK_CLOSE_TIMEOUT, "Timed out closing client sink"),
            }
        }

        res.map_err(|err| state.map_err(err))
    }

    fn handle_relay_msg(&mut self, msg: RelayToClientMsg, state: &mut ConnectedRelayState) {
        match msg {
            RelayToClientMsg::Datagrams {
                remote_endpoint_id,
                datagrams,
            } => {
                trace!(len = datagrams.contents.len(), "received msg");
                // If this is a new sender, register a route for this peer.
                if state
                    .last_packet_src
                    .as_ref()
                    .map(|p| *p != remote_endpoint_id)
                    .unwrap_or(true)
                {
                    // Avoid map lookup (and its lock) with high throughput single peer.
                    state.last_packet_src = Some(remote_endpoint_id);
                    self.endpoints_present
                        .write()
                        .expect("poisoned")
                        .insert(remote_endpoint_id);
                }

                if let Err(err) = self.relay_datagrams_recv.try_send(RelayRecvDatagram {
                    url: self.url.clone(),
                    src: remote_endpoint_id,
                    datagrams,
                }) {
                    warn!("Dropping received relay packet: {err:#}");
                }
            }
            RelayToClientMsg::EndpointGone(endpoint_id) => {
                self.endpoints_present
                    .write()
                    .expect("poisoned")
                    .remove(&endpoint_id);
                // The next datagram from it registers it again.
                if state.last_packet_src == Some(endpoint_id) {
                    state.last_packet_src = None;
                }
            }
            RelayToClientMsg::Ping(data) => state.pong_pending = Some(data),
            RelayToClientMsg::Pong(data) => {
                #[cfg(test)]
                {
                    if let Some((expected_data, sender)) = state.test_pong.take() {
                        if data == expected_data {
                            sender.send(()).ok();
                        } else {
                            state.test_pong = Some((expected_data, sender));
                        }
                    }
                }
                state.ping_tracker.pong_received(data);
                state.established = true;
            }
            RelayToClientMsg::Status(status) => match status {
                Status::Healthy => {
                    info!("Relay server reports: {status}");
                    state.same_endpoint_id_connected = false;
                    self.my_relay.set_same_endpoint_id_connected(&self.url, false);
                }
                Status::SameEndpointIdConnected => {
                    warn!(
                        relay = %self.url,
                        "Relay server reports problem: {status}: another endpoint with this endpoint's id (its secret key) connected; this connection is inactive"
                    );
                    state.same_endpoint_id_connected = true;
                    self.my_relay.set_same_endpoint_id_connected(&self.url, true);
                }
                _ => warn!("Relay server reports problem: {status}"),
            },
            RelayToClientMsg::Restarting { .. } => {
                trace!("Ignoring {msg:?}")
            }
            // Deprecated variants, kept for backwards compatibility with older relay protocol versions.
            RelayToClientMsg::Health { problem } => {
                warn!("Relay server reports problem: {problem}");
            }
            _ => unreachable!(
                "got unknown RelayToClientMsg but iroh is released in sync with iroh-relay"
            ),
        }
    }

    /// Run the actor main loop while sending to the relay server.
    ///
    /// While sending the actor should not read any inboxes which will give it more things
    /// to send to the relay server.
    ///
    /// # Returns
    ///
    /// On `Err` the relay connection should be disconnected.  An `Ok` return means either
    /// the actor should shut down, consult the [`ActiveRelayActor::stop_token`] and
    /// [`ActiveRelayActor::inactive_timeout`] for this, or the send was successful.
    #[instrument(name = "tx", skip_all)]
    async fn run_sending<T>(
        &mut self,
        sending_fut: impl Future<Output = Result<T, RunError>>,
        state: &mut ConnectedRelayState,
        client_stream: &mut iroh_relay::client::ClientStream,
    ) -> Result<(), RelayConnectionError> {
        // we use the same time as for our ping interval
        let send_timeout = PING_INTERVAL;

        let mut timeout = pin!(time::sleep(send_timeout));
        let mut sending_fut = pin!(sending_fut);
        let res = loop {
            tokio::select! {
                biased;
                _ = self.stop_token.cancelled() => {
                    break Ok(());
                }
                _ = &mut timeout => {
                    break Err(e!(RunError::SendTimeout));
                }
                res = &mut sending_fut => {
                    match res {
                        Ok(_) => break Ok(()),
                        Err(err) => break Err(err),
                    }
                }
                _ = state.ping_tracker.timeout() => {
                    break Err(e!(RunError::PingTimeout));
                }
                // No need to read the inbox or datagrams to send.
                msg = client_stream.next() => {
                    let Some(msg) = msg else {
                        break Err(e!(RunError::StreamClosedServer));
                    };
                    match msg {
                        Ok(msg) => self.handle_relay_msg(msg, state),
                        Err(err) => break Err(e!(RunError::ClientStreamRead, err)),
                    }
                }
                _ = &mut self.inactive_timeout, if !self.is_home_relay => {
                    debug!("Inactive for {RELAY_INACTIVE_CLEANUP_TIME:?}, exiting (sending).");
                    break Ok(());
                }
            }
        };
        res.map_err(|err| state.map_err(err))
    }
}

/// Shared state when the [`ActiveRelayActor`] is connected to a relay server.
///
/// Common state between [`ActiveRelayActor::run_connected`] and
/// [`ActiveRelayActor::run_sending`].
#[derive(Debug)]
struct ConnectedRelayState {
    /// Tracks pings we have sent, awaits pong replies.
    ping_tracker: PingTracker,
    /// The [`EndpointId`] from whom we received the last packet.
    ///
    /// This is to avoid a slower lookup in [`ActiveRelayActor::endpoints_present`]
    /// when we are only communicating to a single remote endpoint.
    last_packet_src: Option<EndpointId>,
    /// A pong we need to send ASAP.
    pong_pending: Option<[u8; 8]>,
    /// Whether the connection is to be considered established.
    ///
    /// This is set to `true` once a pong was received from the server.
    established: bool,
    /// ember: the relay said it holds this connection inactive for another of the same endpoint id
    /// (`Status::SameEndpointIdConnected`), until it said `Healthy`. Kept here as well as in the home relay status,
    /// which takes it only while this relay is home: one that becomes home later says it then (`SetHomeRelay`).
    same_endpoint_id_connected: bool,
    #[cfg(test)]
    test_pong: Option<([u8; 8], oneshot::Sender<()>)>,
}

impl ConnectedRelayState {
    fn map_err(&self, error: RunError) -> RelayConnectionError {
        if self.established {
            e!(RelayConnectionError::Established, error)
        } else {
            e!(RelayConnectionError::Handshake, error)
        }
    }
}

pub(super) enum RelayActorMessage {
    MaybeCloseRelaysOnRebind,
    /// ember: every active relay's link dialed again.
    Reconnect,
    SetEntries(Vec<(RelayUrl, Vec<RelayUrl>)>),
    NetworkChange {
        report: Report,
    },
    /// ember: the relay removed from the endpoint (`Endpoint::remove_relay`): out of this actor's map and its excludes,
    /// its connection to it ended at once, and its home chosen again where it was that relay.
    RemoveRelay(RelayUrl),
    /// ember: a relay inserted into the endpoint (`Endpoint::insert_relay`): the one this actor was bound to be home on
    /// is its again (or another transport's excluded again), and an actor with no home takes it as its home.
    InsertRelay(RelayUrl, Arc<RelayConfig>),
    /// Trigger an immediate health check on all relay connections.
    ///
    /// Sent after a major network change to detect broken connections faster
    /// using RTT-based timeouts instead of the default 5s ping timeout.
    CheckConnectionAfterNetworkChange,
}

#[derive(Debug, Clone)]
pub(crate) struct RelaySendItem {
    /// The destination for the datagrams.
    pub(crate) remote_endpoint: EndpointId,
    /// The home relay of the remote endpoint.
    pub(crate) url: RelayUrl,
    /// One or more datagrams to send.
    pub(crate) datagrams: Datagrams,
    /// ember: when it was queued to be sent, if it is to be dropped after waiting `MAX_SEND_DATAGRAM_WAIT`.
    pub(crate) queued: Option<Instant>,
}

pub(super) struct RelayActor {
    config: Config,
    /// Queue on which to put received datagrams.
    relay_datagram_recv_queue: mpsc::Sender<RelayRecvDatagram>,
    /// The actors managing each currently used relay server.
    ///
    /// These actors will exit when they have any inactivity.  Otherwise they will keep
    /// trying to maintain a connection to the relay server as needed.
    active_relays: BTreeMap<RelayUrl, ActiveRelayHandle>,
    /// The tasks for the [`ActiveRelayActor`]s in `active_relays` above.
    active_relay_tasks: JoinSet<()>,
    entry_overrides: Option<BTreeMap<RelayUrl, Vec<RelayUrl>>>,
    cancel_token: CancellationToken,
}

#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub my_relay: HomeRelayWatch,
    pub secret_key: SecretKey,
    #[cfg(not(wasm_browser))]
    pub dns_resolver: DnsResolver,
    /// Proxy
    pub proxy_url: Option<Url>,
    /// ember: whether relays are asked for their UDP way, read at each dial.
    pub relay_udp: Arc<AtomicBool>,
    /// If the last net_report report, reports IPv6 to be available.
    pub ipv6_reported: Arc<AtomicBool>,
    pub tls_config: rustls::ClientConfig,
    pub metrics: Arc<SocketMetrics>,
    /// Per-relay configuration. Consulted when starting a connection to
    /// look up the auth token and any future per-relay options.
    pub relay_map: RelayMap,
    pub relay_allowlist: crate::socket::relay_policy::RelayAllowlist,
    /// ember: relays of `relay_map` this actor is not home on, another relay transport's
    /// (`Builder::home_on_every_relay`: the first transport has the endpoint's whole map, relays inserted later with it,
    /// the others one relay each). Shared with the transport's sender (`RelaySender::owns`): a relay removed from the
    /// endpoint is taken out of it, and put back as it is inserted again (`RelayActorMessage::InsertRelay`).
    pub excludes: Excludes,
    /// ember: the relay this actor was bound to be home on, where it is one of `Builder::home_on_every_relay`'s
    /// transports but the first: inserted again after it was removed, it is this actor's again.
    pub own: Option<RelayUrl>,
    /// ember: the relays the other transports were bound to be home on (the first transport's): inserted again after
    /// they were removed, they are excluded here again.
    pub others: Vec<RelayUrl>,
}

/// ember: the relays a relay transport is not home on (`Config::excludes`), as its actor and its sender share them.
pub(crate) type Excludes = Arc<std::sync::RwLock<Vec<RelayUrl>>>;

/// Connection state of the home relay.
///
/// Published via [`HomeRelayWatch`] so that [`Endpoint::online`] and the public
/// [`Endpoint::home_relay_status`] watcher can observe the connection state.
/// This type is `pub(crate)`; the public surface lives on
/// [`crate::endpoint::RelayStatus`], and this enum is intentionally free to
/// evolve without affecting the public API.
///
/// [`Endpoint::online`]: crate::Endpoint::online
/// [`Endpoint::home_relay_status`]: crate::Endpoint::home_relay_status
#[derive(Debug, Clone)]
pub(crate) enum RelayConnectionState {
    /// Dialing or performing the relay handshake.
    Connecting,
    /// Connected and handshaked.
    Connected,
    /// Not connected. Either the connection was lost after having been
    /// established, or an attempt to connect failed.
    ///
    /// `last_error` carries the most recent connection error, if any. The
    /// initial transition into this state (before any attempt has produced
    /// an error) carries `None`.
    ///
    /// The `Arc` is compared by pointer identity: each new failure produces
    /// a fresh allocation, so the watcher fires on every new error.
    Disconnected { last_error: Option<Arc<AnyError>> },
}

impl RelayConnectionState {
    pub(crate) fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }

    pub(crate) fn last_error(&self) -> Option<&Arc<AnyError>> {
        match self {
            Self::Disconnected { last_error } => last_error.as_ref(),
            _ => None,
        }
    }
}

impl PartialEq for RelayConnectionState {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Connecting, Self::Connecting) | (Self::Connected, Self::Connected) => true,
            (Self::Disconnected { last_error: a }, Self::Disconnected { last_error: b }) => {
                match (a, b) {
                    (None, None) => true,
                    (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                    _ => false,
                }
            }
            _ => false,
        }
    }
}

impl Eq for RelayConnectionState {}

/// Shared watchable for the home relay URL and connection status.
///
/// Owned by [`RelayActor`] and cloned into each [`ActiveRelayActor`].
///
/// # Write discipline
///
/// The [`RelayActor`] writes the URL (via [`Self::set`] and [`Self::clear`]).
/// Each [`ActiveRelayActor`] updates only the status (via [`Self::set_status`]),
/// which guards against stale writes: if another relay has become home since this actor
/// was designated, the write is silently dropped.
#[derive(Debug, Clone)]
pub(crate) struct HomeRelayWatch {
    inner: Watchable<Option<RelayStatus>>,
}

impl Default for HomeRelayWatch {
    fn default() -> Self {
        Self {
            inner: Watchable::new(None),
        }
    }
}

impl HomeRelayWatch {
    /// Set the home relay URL and status. Used by [`RelayActor`] on relay changes.
    fn set(&self, url: RelayUrl, state: RelayConnectionState) {
        let _ = self.inner.set(Some(RelayStatus::new(url, state)));
    }

    /// Clear the home relay (no preferred relay). Used by [`RelayActor`].
    fn clear(&self) {
        let _ = self.inner.set(None);
    }

    /// Update the status, but only if `url` is still the current home relay.
    ///
    /// This is the only write method [`ActiveRelayActor`] should use. It prevents a
    /// demoted actor from overwriting a newer home relay's status: the [`RelayActor`]
    /// updates the URL in the watchable *before* sending `SetHomeRelay(false)`, so by
    /// the time the old actor tries to write, the URL no longer matches.
    fn set_status(&self, url: &RelayUrl, state: RelayConnectionState) {
        if let Some(current) = self.inner.get().filter(|s| s.url() == url) {
            let _ = self.inner.set(Some(
                RelayStatus::new(url.clone(), state).with_access(current.access_url().clone()),
            ));
        }
    }

    /// The address carrying this relay connection, while this relay is still the home one.
    fn set_access(&self, url: &RelayUrl, access: RelayUrl) {
        if let Some(current) = self.inner.get().filter(|s| s.url() == url) {
            let _ = self.inner.set(Some(current.with_access(access)));
        }
    }

    /// ember: whether the relay holds this connection inactive for another of the same endpoint id, while `url` is
    /// still the home relay (as `set_status`).
    fn set_same_endpoint_id_connected(&self, url: &RelayUrl, same: bool) {
        if let Some(current) = self
            .inner
            .get()
            .filter(|s| s.url() == url && s.same_endpoint_id_connected() != same)
        {
            let _ = self
                .inner
                .set(Some(current.with_same_endpoint_id_connected(same)));
        }
    }

    fn get(&self) -> Option<RelayStatus> {
        self.inner.get()
    }

    pub(crate) fn watch(&self) -> n0_watcher::Direct<Option<RelayStatus>> {
        self.inner.watch()
    }
}

impl RelayActor {
    pub(super) fn new(
        config: Config,
        relay_datagram_recv_queue: mpsc::Sender<RelayRecvDatagram>,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            config,
            relay_datagram_recv_queue,
            active_relays: Default::default(),
            active_relay_tasks: JoinSet::new(),
            entry_overrides: None,
            cancel_token,
        }
    }

    pub(super) async fn run(
        mut self,
        mut receiver: mpsc::Receiver<RelayActorMessage>,
        mut datagram_send_channel: mpsc::Receiver<RelaySendItem>,
    ) {
        // ember: home on its one relay at once, not after net_report's first report.
        if let Some(url) = self.only_relay() {
            self.config
                .my_relay
                .set(url.clone(), RelayConnectionState::Connecting);
            self.set_home_relay(url).await;
        }

        loop {
            tokio::select! {
                biased;
                _ = self.cancel_token.cancelled() => {
                    debug!("shutting down");
                    break;
                }
                Some(res) = self.active_relay_tasks.join_next() => {
                    match res {
                        Ok(()) => (),
                        Err(err) if err.is_panic() => {
                            error!("ActiveRelayActor task panicked: {err:#?}");
                        }
                        Err(err) if err.is_cancelled() => {
                            error!("ActiveRelayActor cancelled: {err:#?}");
                        }
                        Err(err) => error!("ActiveRelayActor failed: {err:#?}"),
                    }
                    self.reap_active_relays();
                }
                msg = receiver.recv() => {
                    let Some(msg) = msg else {
                        debug!("Inbox dropped, shutting down.");
                        break;
                    };
                    let cancel_token = self.cancel_token.child_token();
                    cancel_token.run_until_cancelled(self.handle_msg(msg)).await;
                }
                item = datagram_send_channel.recv() => {
                    let Some(item) = item else {
                        debug!("Datagram send channel dropped, shutting down.");
                        break;
                    };
                    let token = self.cancel_token.child_token();
                    token.run_until_cancelled(self.try_send_datagram(item)).await;
                }
            }
        }

        // try shutdown
        if time::timeout(Duration::from_secs(3), self.close_all_active_relays())
            .await
            .is_err()
        {
            warn!("Failed to shut down all ActiveRelayActors");
        }
    }

    async fn handle_msg(&mut self, msg: RelayActorMessage) {
        match msg {
            RelayActorMessage::NetworkChange { report } => {
                self.on_network_change(report).await;
            }
            RelayActorMessage::MaybeCloseRelaysOnRebind => {
                self.maybe_close_relays_on_rebind().await;
            }
            RelayActorMessage::Reconnect => {
                for handle in self.active_relays.values() {
                    handle
                        .inbox_addr
                        .send(ActiveRelayMessage::Reconnect)
                        .await
                        .ok();
                }
            }
            RelayActorMessage::SetEntries(entries) => {
                let entries: BTreeMap<_, _> = entries.into_iter()
                    .filter(|(url, _)| self.config.relay_allowlist.allows(url))
                    .map(|(url, list)| (url, list.into_iter().filter(|entry| self.config.relay_allowlist.allows(entry)).collect::<Vec<_>>()))
                    .collect();
                for (url, handle) in &self.active_relays {
                    let list = entries.get(url).cloned().unwrap_or_default();
                    handle
                        .inbox_addr
                        .send(ActiveRelayMessage::UpdateEntries(
                            list,
                            handle.inbox_addr.clone(),
                        ))
                        .await
                        .ok();
                }
                self.entry_overrides = Some(entries);
            }
            RelayActorMessage::CheckConnectionAfterNetworkChange => {
                self.check_connection_after_network_change().await;
            }
            RelayActorMessage::RemoveRelay(url) => {
                self.remove_relay(url).await;
            }
            RelayActorMessage::InsertRelay(url, config) => {
                self.insert_relay(url, config).await;
            }
        }
    }

    /// ember: `url` removed from the endpoint. Upstream only took it out of the endpoint's map, which the relay
    /// transports of `Builder::home_on_every_relay` but the first do not share: they stayed connected to it, home on
    /// it, and the endpoint's address went on naming it. Here every actor takes it out of its map and its excludes,
    /// ends its connection to it at once, and chooses its home again where it was that relay.
    async fn remove_relay(&mut self, url: RelayUrl) {
        self.config.relay_map.remove(&url);
        self.config
            .excludes
            .write()
            .expect("poisoned")
            .retain(|u| u != &url);
        if let Some(handle) = self.active_relays.remove(&url) {
            info!(%url, "relay removed: its connection ended");
            handle.stop.cancel();
        }
        let was_home = self
            .config
            .my_relay
            .get()
            .is_some_and(|status| status.url() == &url);
        if was_home {
            self.config.my_relay.clear();
            if let Some(next) = self.homes().into_iter().next() {
                info!(home = %next, removed = %url, "home relay removed: home is now another");
                self.config
                    .my_relay
                    .set(next.clone(), RelayConnectionState::Connecting);
                self.set_home_relay(next).await;
            }
        }
        self.log_active_relay();
    }

    /// ember: `url` inserted into the endpoint (its map has it already, the first transport's being the endpoint's):
    /// the relay this actor was bound to be home on is its again, one another transport was is excluded again, and an
    /// actor home on none takes one it may be home on.
    async fn insert_relay(&mut self, url: RelayUrl, config: Arc<RelayConfig>) {
        if self.config.own.as_ref() == Some(&url) {
            self.config.relay_map.insert(url.clone(), config);
        } else if self.config.others.contains(&url) {
            {
                let mut excludes = self.config.excludes.write().expect("poisoned");
                if !excludes.contains(&url) {
                    excludes.push(url.clone());
                }
            }
            // ember: the first transport's map had `url` before this message, so it may have connected to it, even be
            // home on it; another transport is home on it now, and two connections of one endpoint id to one relay
            // displace each other (`SameEndpointIdConnected`). As `remove_relay`: its connection here ends, and home is
            // chosen again below.
            if let Some(handle) = self.active_relays.remove(&url) {
                info!(%url, "relay inserted for another transport: its connection here ended");
                handle.stop.cancel();
                self.log_active_relay();
            }
            if self
                .config
                .my_relay
                .get()
                .is_some_and(|status| status.url() == &url)
            {
                info!(%url, "relay inserted for another transport: home here is chosen again");
                self.config.my_relay.clear();
            }
        }
        if self.config.my_relay.get().is_none()
            && let Some(home) = self.homes().into_iter().next()
        {
            info!(%home, "relay inserted: home on it");
            self.config
                .my_relay
                .set(home.clone(), RelayConnectionState::Connecting);
            self.set_home_relay(home).await;
        }
    }

    /// Sends datagrams to the correct [`ActiveRelayActor`].
    ///
    /// ember: if that actor's queue is full the datagrams are dropped, as a socket drops what it has no room for.
    /// Upstream waited for room, and while it waited no datagram went to any other relay: one relay being dialed (or
    /// not answering) held every relay of this transport up to `UNDELIVERABLE_DATAGRAM_TIMEOUT`, 3 s, at a time.
    async fn try_send_datagram(&mut self, item: RelaySendItem) {
        let url = item.url.clone();
        let handle = self.active_relay_handle_for_endpoint(&item.url, &item.remote_endpoint);
        let Some(handle) = handle else { return; };
        match handle.datagrams_send_queue.try_send(item) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!(?url, "Dropped datagram(s): ActiveRelayActor closed.");
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                trace!(?url, "Dropped datagram(s): ActiveRelayActor's queue is full.");
            }
        }
    }

    /// ember: the relays this actor may be home on: its map's, but those another relay transport is home on
    /// (`Config::excludes`).
    fn homes(&self) -> Vec<RelayUrl> {
        let mut urls = self.config.relay_map.urls::<Vec<RelayUrl>>();
        let excludes = self.config.excludes.read().expect("poisoned");
        urls.retain(|u| !excludes.contains(u) && self.config.relay_allowlist.allows(u));
        urls
    }

    /// ember: the one relay this actor may be home on, if it is one alone.
    fn only_relay(&self) -> Option<RelayUrl> {
        let mut urls = self.homes();
        if urls.len() == 1 { urls.pop() } else { None }
    }

    async fn on_network_change(&mut self, report: Report) {
        let prev = self.config.my_relay.get();
        let prev_url = prev.as_ref().map(RelayStatus::url);
        // ember: net_report's choice if this actor may be home on it, else the nearest of those it may be (its one
        // relay, as a relay transport of `Builder::home_on_every_relay` has).
        let homes = self.homes();
        let preferred = match report.preferred_relay {
            Some(url) if homes.contains(&url) => Some(url),
            _ if homes.len() == 1 => homes.first().cloned(),
            _ => report
                .relay_latency
                .iter()
                .filter(|(_, url, _)| homes.contains(url))
                .min_by_key(|(_, _, latency)| *latency)
                .map(|(_, url, _)| url.clone()),
        };
        if preferred.as_ref() == prev_url {
            // No change.
            return;
        }

        if let Some(relay_url) = preferred {
            self.config.metrics.relay_home_change.inc();

            // On change, notify all currently connected relay servers and
            // start connecting to our home relay if we are not already.
            info!("home is now relay {}, was {:?}", relay_url, prev_url);
            // Publish `Connecting` initially. If an `ActiveRelayActor` already
            // exists for this URL it will republish its actual status (e.g.
            // `Connected`) when it receives the `SetHomeRelay(true)` message
            // sent below.
            self.config
                .my_relay
                .set(relay_url.clone(), RelayConnectionState::Connecting);
            self.set_home_relay(relay_url).await;
        } else {
            self.config.my_relay.clear();
        }
    }

    async fn set_home_relay(&mut self, home_url: RelayUrl) {
        let home_url_ref = &home_url;
        n0_future::join_all(self.active_relays.iter().map(|(url, handle)| async move {
            let is_preferred = url == home_url_ref;
            handle
                .inbox_addr
                .send(ActiveRelayMessage::SetHomeRelay(is_preferred))
                .await
                .ok()
        }))
        .await;
        // Ensure we have an ActiveRelayActor for the current home relay.
        let _ = self.active_relay_handle(home_url);
    }

    /// Returns the handle for the [`ActiveRelayActor`] to reach `remote_endpoint`.
    ///
    /// The endpoint is expected to be reachable on `url`, but if no [`ActiveRelayActor`] for
    /// `url` exists but another existing [`ActiveRelayActor`] already knows about the endpoint,
    /// that other endpoint is used.
    fn active_relay_handle_for_endpoint(
        &mut self,
        url: &RelayUrl,
        remote_endpoint: &EndpointId,
    ) -> Option<ActiveRelayHandle> {
        if !self.config.relay_allowlist.allows(url) { return None; }
        if let Some(handle) = self.active_relays.get(url) {
            return Some(handle.clone());
        }

        // If we don't have an open connection to the remote endpoint's home relay, see if
        // we have an open connection to a relay endpoint where we'd heard from that peer
        // already.  E.g. maybe they dialed our home relay recently.
        // ember: read from each connection's `endpoints_present`, asking no actor and waiting for none.
        let found_relay = self
            .active_relays
            .iter()
            .find(|(_, handle)| {
                handle
                    .endpoints_present
                    .read()
                    .expect("poisoned")
                    .contains(remote_endpoint)
            })
            .map(|(url, _)| url.clone());
        let url = found_relay.unwrap_or(url.clone());
        self.active_relay_handle(url)
    }

    /// Returns the handle of the [`ActiveRelayActor`].
    fn active_relay_handle(&mut self, url: RelayUrl) -> Option<ActiveRelayHandle> {
        if !self.config.relay_allowlist.allows(&url) { return None; }
        Some(match self.active_relays.get(&url) {
            Some(e) => e.clone(),
            None => {
                let handle = self.start_active_relay(url.clone());
                if Some(&url) == self.config.my_relay.get().as_ref().map(RelayStatus::url)
                    && let Err(err) = handle
                        .inbox_addr
                        .try_send(ActiveRelayMessage::SetHomeRelay(true))
                {
                    error!("Home relay not set, send to new actor failed: {err:#}.");
                }
                self.active_relays.insert(url, handle.clone());
                self.log_active_relay();
                handle
            }
        })
    }

    fn start_active_relay(&mut self, url: RelayUrl) -> ActiveRelayHandle {
        debug!(?url, "Adding relay connection");

        let relay_config = self.config.relay_map.get(&url);
        let auth_token = relay_config.as_ref().and_then(|cfg| cfg.auth_token.clone());
        let entries = match &self.entry_overrides {
            Some(overrides) => overrides.get(&url).cloned().unwrap_or_default(),
            None => relay_config
                .as_ref()
                .map(|cfg| cfg.entries.clone())
                .unwrap_or_default(),
        };
        let connection_opts = RelayConnectionOptions {
            secret_key: self.config.secret_key.clone(),
            #[cfg(not(wasm_browser))]
            dns_resolver: self.config.dns_resolver.clone(),
            proxy_url: self.config.proxy_url.clone(),
            prefer_ipv6: self.config.ipv6_reported.clone(),
            tls_config: self.config.tls_config.clone(),
            auth_token,
            udp: self.config.relay_udp.clone(),
        };

        // ember: as many as the transport's queue holds, all of them maybe for this relay.
        let (send_datagram_tx, send_datagram_rx) = mpsc::channel(super::RELAY_DATAGRAM_QUEUE);
        let endpoints_present = EndpointsPresent::default();
        let (inbox_tx, inbox_rx) = mpsc::channel(64);
        let span = info_span!("active-relay", %url);
        let stop = self.cancel_token.child_token();
        let opts = ActiveRelayActorOptions {
            url,
            endpoints_present: endpoints_present.clone(),
            inbox: inbox_rx,
            relay_datagrams_send: send_datagram_rx,
            relay_datagrams_recv: self.relay_datagram_recv_queue.clone(),
            connection_opts,
            entries,
            stop_token: stop.clone(),
            metrics: self.config.metrics.clone(),
            my_relay: self.config.my_relay.clone(),
        };
        let mut actor = ActiveRelayActor::new(opts);
        actor.start_entry_probes(inbox_tx.clone());
        self.active_relay_tasks.spawn(
            async move {
                actor.run().await;
            }
            .instrument(span),
        );
        let handle = ActiveRelayHandle {
            stop,
            endpoints_present,
            inbox_addr: inbox_tx,
            datagrams_send_queue: send_datagram_tx,
        };
        self.log_active_relay();
        handle
    }

    /// Triggers an immediate health check on all relay connections after a network change.
    async fn check_connection_after_network_change(&mut self) {
        self.send_check_connection().await;
    }

    /// Closes the relay connections not originating from a local IP address.
    ///
    /// Called in response to a rebind, any relay connection originating from an address
    /// that's not known to be currently a local IP address should be closed.  All the other
    /// relay connections are pinged.
    async fn maybe_close_relays_on_rebind(&mut self) {
        self.send_check_connection().await;
        self.log_active_relay();
    }

    /// Sends a [`ActiveRelayMessage::CheckConnection`] to all active relays with current
    /// local IPs.
    async fn send_check_connection(&self) {
        #[cfg(not(wasm_browser))]
        let ifs = interfaces::State::new().await;
        #[cfg(not(wasm_browser))]
        let local_ips: Vec<_> = ifs
            .interfaces
            .values()
            .flat_map(|netif| netif.addrs())
            .map(|ipnet| ipnet.addr())
            .collect();
        // In browsers, we don't have this information. This will do the right thing
        // in the ActiveRelayActor, though.
        #[cfg(wasm_browser)]
        let local_ips = Vec::new();
        let send_futs = self.active_relays.values().map(|handle| {
            let local_ips = local_ips.clone();
            async move {
                handle
                    .inbox_addr
                    .send(ActiveRelayMessage::CheckConnection { local_ips })
                    .await
                    .ok();
            }
        });
        n0_future::join_all(send_futs).await;
    }

    /// Cleans up [`ActiveRelayActor`]s which have stopped running.
    fn reap_active_relays(&mut self) {
        self.active_relays
            .retain(|_url, handle| !handle.inbox_addr.is_closed());

        // Make sure home relay exists
        if let Some(status) = self.config.my_relay.get() {
            let _ = self.active_relay_handle(status.url().clone());
        }
        self.log_active_relay();
    }

    /// Stops all [`ActiveRelayActor`]s and awaits for them to finish.
    async fn close_all_active_relays(&mut self) {
        self.cancel_token.cancel();
        let tasks = std::mem::take(&mut self.active_relay_tasks);
        tasks.join_all().await;

        self.log_active_relay();
    }

    fn log_active_relay(&self) {
        debug!("{} active relay conns{}", self.active_relays.len(), {
            let mut s = String::new();
            if !self.active_relays.is_empty() {
                s += ":";
                for endpoint in self.active_relay_sorted() {
                    s += &format!(" relay-{endpoint}");
                }
            }
            s
        });
    }

    fn active_relay_sorted(&self) -> impl Iterator<Item = RelayUrl> + use<> {
        let mut ids: Vec<_> = self.active_relays.keys().cloned().collect();
        ids.sort();

        ids.into_iter()
    }
}

/// Handle to one [`ActiveRelayActor`].
#[derive(Debug, Clone)]
struct ActiveRelayHandle {
    /// ember: ends its actor (its relay removed: `RelayActor::remove_relay`).
    stop: CancellationToken,
    /// ember: the endpoints its connection reaches (`EndpointsPresent`).
    endpoints_present: EndpointsPresent,
    inbox_addr: mpsc::Sender<ActiveRelayMessage>,
    datagrams_send_queue: mpsc::Sender<RelaySendItem>,
}

/// A single datagram received from a relay server.
///
/// This could be either a QUIC or DISCO packet.
#[derive(Debug)]
pub(crate) struct RelayRecvDatagram {
    pub(crate) url: RelayUrl,
    pub(crate) src: EndpointId,
    pub(crate) datagrams: Datagrams,
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, atomic::AtomicBool},
        time::Duration,
    };

    use iroh_base::{EndpointId, RelayUrl, SecretKey};
    use iroh_relay::{
        PingTracker,
        protos::relay::Datagrams,
        tls::{CaTlsConfig, default_provider},
    };
    use n0_error::{AnyError as Error, Result, StackResultExt, StdResultExt};
    use n0_tracing_test::traced_test;
    use n0_watcher::Watcher;
    use tokio::sync::{mpsc, oneshot};
    use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
    use tracing::{Instrument, info, info_span};

    use super::{
        ActiveRelayActor, ActiveRelayActorOptions, ActiveRelayHandle, ActiveRelayMessage,
        Config, HomeRelayWatch, MAX_SEND_DATAGRAM_WAIT, RELAY_INACTIVE_CLEANUP_TIME, RelayActor,
        RelayConnectionOptions, RelayConnectionState, RelayRecvDatagram, RelaySendItem,
        UNDELIVERABLE_DATAGRAM_TIMEOUT,
    };
    use crate::socket::transports::relay::RELAY_DATAGRAM_QUEUE;
    use crate::{dns::DnsResolver, test_utils};

    #[tokio::test]
    async fn relay_allowlist_prevents_unlisted_actor_and_home_connections() {
        let allowed: RelayUrl = "http://127.0.0.1:12340".parse().unwrap();
        let forbidden: RelayUrl = "http://127.0.0.1:12341".parse().unwrap();
        let allowlist = crate::socket::relay_policy::RelayAllowlist::new(Some([allowed.clone()].into()));
        let original: iroh_relay::RelayMap = [allowed.clone(), forbidden.clone()].into_iter().collect();
        let config = Config {
            my_relay: HomeRelayWatch::default(), secret_key: SecretKey::generate(),
            dns_resolver: DnsResolver::new(), proxy_url: None, relay_udp: Default::default(),
            ipv6_reported: Arc::new(AtomicBool::new(false)),
            tls_config: CaTlsConfig::insecure_skip_verify().client_config(default_provider()).unwrap(),
            metrics: Default::default(), relay_map: original,
            relay_allowlist: allowlist, excludes: Default::default(), own: None, others: vec![],
        };
        let (received, _rx) = mpsc::channel(8);
        let mut actor = RelayActor::new(config, received, CancellationToken::new());
        assert!(actor.active_relay_handle(forbidden.clone()).is_none());
        assert!(actor.active_relay_handle_for_endpoint(&forbidden, &SecretKey::generate().public()).is_none());
        assert!(actor.active_relays.is_empty(), "unlisted URL created a relay connection actor");
        assert!(actor.active_relay_tasks.is_empty());
        assert_eq!(actor.homes(), vec![allowed]);
    }

    /// Starts a new [`ActiveRelayActor`].
    #[allow(clippy::too_many_arguments)]
    fn start_active_relay_actor(
        secret_key: SecretKey,
        stop_token: CancellationToken,
        url: RelayUrl,
        inbox_rx: mpsc::Receiver<ActiveRelayMessage>,
        relay_datagrams_send: mpsc::Receiver<RelaySendItem>,
        relay_datagrams_recv: mpsc::Sender<RelayRecvDatagram>,
        span: tracing::Span,
    ) -> AbortOnDropHandle<()> {
        start_active_relay_actor_watched(
            secret_key,
            stop_token,
            url,
            inbox_rx,
            relay_datagrams_send,
            relay_datagrams_recv,
            span,
            Default::default(),
        )
    }

    /// One whose home relay status is `my_relay`'s.
    #[allow(clippy::too_many_arguments)]
    fn start_active_relay_actor_watched(
        secret_key: SecretKey,
        stop_token: CancellationToken,
        url: RelayUrl,
        inbox_rx: mpsc::Receiver<ActiveRelayMessage>,
        relay_datagrams_send: mpsc::Receiver<RelaySendItem>,
        relay_datagrams_recv: mpsc::Sender<RelayRecvDatagram>,
        span: tracing::Span,
        my_relay: HomeRelayWatch,
    ) -> AbortOnDropHandle<()> {
        let opts = ActiveRelayActorOptions {
            url,
            entries: Vec::new(),
            endpoints_present: Default::default(),
            inbox: inbox_rx,
            relay_datagrams_send,
            relay_datagrams_recv,
            connection_opts: RelayConnectionOptions {
                secret_key,
                dns_resolver: DnsResolver::new(),
                proxy_url: None,
                prefer_ipv6: Arc::new(AtomicBool::new(true)),
                tls_config: CaTlsConfig::insecure_skip_verify()
                    .client_config(default_provider())
                    .expect("infallible"),
                auth_token: None,
                udp: Default::default(),
            },
            stop_token,
            metrics: Default::default(),
            my_relay,
        };
        let task = tokio::spawn(ActiveRelayActor::new(opts).run().instrument(span));
        AbortOnDropHandle::new(task)
    }

    /// Starts an [`ActiveRelayActor`] as an "iroh echo endpoint".
    ///
    /// This actor will connect to the relay server, pretending to be an iroh endpoint, and echo
    /// back any datagram it receives from the relay.  This is used by the
    /// [`ActiveRelayActor`] under test to check connectivity works.
    fn start_echo_endpoint(relay_url: RelayUrl) -> (EndpointId, AbortOnDropHandle<()>) {
        let secret_key = SecretKey::from_bytes(&[8u8; 32]);
        let (recv_datagram_tx, mut recv_datagram_rx) = mpsc::channel(16);
        let (send_datagram_tx, send_datagram_rx) = mpsc::channel(16);
        let (inbox_tx, inbox_rx) = mpsc::channel(16);
        let cancel_token = CancellationToken::new();
        let actor_task = start_active_relay_actor(
            secret_key.clone(),
            cancel_token.clone(),
            relay_url.clone(),
            inbox_rx,
            send_datagram_rx,
            recv_datagram_tx,
            info_span!("echo-endpoint"),
        );
        let echo_task = tokio::spawn({
            let relay_url = relay_url.clone();
            async move {
                loop {
                    let datagram = recv_datagram_rx.recv().await;
                    if let Some(recv) = datagram {
                        let RelayRecvDatagram {
                            url: _,
                            src,
                            datagrams,
                        } = recv;
                        info!(from = %src.fmt_short(), "Received datagram");
                        let send = RelaySendItem {
                            remote_endpoint: src,
                            url: relay_url.clone(),
                            datagrams,
                            queued: None,
                        };
                        send_datagram_tx.send(send).await.ok();
                    }
                }
            }
            .instrument(info_span!("echo-task"))
        });
        let echo_task = AbortOnDropHandle::new(echo_task);
        let supervisor_task = tokio::spawn(async move {
            let _guard = cancel_token.drop_guard();
            // move the inboxes here so it is not dropped, as this stops the actor.
            let _inbox_tx = inbox_tx;
            tokio::select! {
                biased;
                _ = actor_task => (),
                _ = echo_task => (),
            };
        });
        let supervisor_task = AbortOnDropHandle::new(supervisor_task);
        (secret_key.public(), supervisor_task)
    }

    /// Sends a message to the echo endpoint, receives the response.
    ///
    /// This takes care of retry and timeout.  Because we don't know when both the
    /// endpoint-under-test and the echo endpoint will be ready and datagrams aren't queued to send
    /// forever, we have to retry a few times.
    async fn send_recv_echo(
        item: RelaySendItem,
        tx: &mpsc::Sender<RelaySendItem>,
        rx: &mut mpsc::Receiver<RelayRecvDatagram>,
    ) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(10), async move {
            loop {
                let res = tokio::time::timeout(UNDELIVERABLE_DATAGRAM_TIMEOUT, async {
                    tx.send(item.clone()).await.std_context("send item")?;
                    let RelayRecvDatagram {
                        url: _,
                        src: _,
                        datagrams,
                    } = rx.recv().await.unwrap();

                    assert_eq!(datagrams, item.datagrams);

                    Ok::<_, Error>(())
                })
                .await;
                if res.is_ok() {
                    break;
                }
            }
        })
        .await
        .expect("overall timeout exceeded");
        Ok(())
    }

    /// A separate probe can fail even while the relay connection still carries traffic.  A measurement of only the
    /// alternate entrance does not show that it is faster than the connection already in use.
    #[tokio::test]
    async fn missing_current_entry_sample_does_not_replace_it() {
        let relay: RelayUrl = "https://relay.example.com".parse().unwrap();
        let entry: RelayUrl = "https://entry.example.com".parse().unwrap();
        let (_inbox_tx, inbox) = mpsc::channel(1);
        let (_send_tx, relay_datagrams_send) = mpsc::channel(1);
        let (relay_datagrams_recv, _recv_rx) = mpsc::channel(1);
        let mut actor = ActiveRelayActor::new(ActiveRelayActorOptions {
            url: relay.clone(),
            entries: vec![entry.clone()],
            endpoints_present: Default::default(),
            inbox,
            relay_datagrams_send,
            relay_datagrams_recv,
            connection_opts: RelayConnectionOptions {
                secret_key: SecretKey::generate(),
                dns_resolver: DnsResolver::new(),
                proxy_url: None,
                prefer_ipv6: Arc::new(AtomicBool::new(false)),
                tls_config: CaTlsConfig::insecure_skip_verify()
                    .client_config(default_provider())
                    .expect("infallible"),
                auth_token: None,
                udp: Default::default(),
            },
            stop_token: CancellationToken::new(),
            metrics: Default::default(),
            my_relay: Default::default(),
        });

        assert_eq!(
            actor.choose_entry(&[(entry.clone(), Duration::from_millis(200))]),
            None,
            "a failed probe of the current entrance must not make the alternate win"
        );
        assert_eq!(actor.access, relay);
        assert_eq!(
            actor.choose_entry(&[
                (relay.clone(), Duration::from_millis(50)),
                (entry, Duration::from_millis(200))
            ]),
            None,
            "a later comparison must keep the faster current entrance"
        );
    }

    /// Two addresses really do lead to the same relay. Changing the entrance must preserve packet delivery, and
    /// closing the superseded socket must not leave it fighting the replacement for the endpoint's identity.
    #[tokio::test]
    #[traced_test]
    async fn relay_entry_handover_keeps_forwarding() -> Result {
        let (_map, relay, _server) = test_utils::run_relay_server().await?;
        let target = format!(
            "{}:{}",
            relay.host_str().unwrap(),
            relay.port_or_known_default().unwrap()
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .std_context("bind forwarding entry")?;
        let entry: RelayUrl = format!(
            "https://{}",
            listener.local_addr().std_context("entry address")?
        )
        .parse()
        .std_context("entry URL")?;
        let proxy = tokio::spawn(async move {
            while let Ok((mut incoming, _)) = listener.accept().await {
                let target = target.clone();
                tokio::spawn(async move {
                    if let Ok(mut upstream) = tokio::net::TcpStream::connect(target).await {
                        let _ = tokio::io::copy_bidirectional(&mut incoming, &mut upstream).await;
                    }
                });
            }
        });
        let _proxy = AbortOnDropHandle::new(proxy);
        let (peer, _echo) = start_echo_endpoint(relay.clone());
        let (recv_tx, mut recv_rx) = mpsc::channel(16);
        let (send_tx, send_rx) = mpsc::channel(16);
        let (inbox_tx, inbox_rx) = mpsc::channel(16);
        let watch = HomeRelayWatch::default();
        watch.set(relay.clone(), RelayConnectionState::Connecting);
        let opts = ActiveRelayActorOptions {
            url: relay.clone(),
            entries: vec![entry.clone()],
            endpoints_present: Default::default(),
            inbox: inbox_rx,
            relay_datagrams_send: send_rx,
            relay_datagrams_recv: recv_tx,
            connection_opts: RelayConnectionOptions {
                secret_key: SecretKey::generate(),
                dns_resolver: DnsResolver::new(),
                proxy_url: None,
                prefer_ipv6: Arc::new(AtomicBool::new(false)),
                tls_config: CaTlsConfig::insecure_skip_verify()
                    .client_config(default_provider())
                    .expect("infallible"),
                auth_token: None,
                udp: Default::default(),
            },
            stop_token: CancellationToken::new(),
            metrics: Default::default(),
            my_relay: watch.clone(),
        };
        let _actor = AbortOnDropHandle::new(tokio::spawn(ActiveRelayActor::new(opts).run()));
        let packet = RelaySendItem {
            remote_endpoint: peer,
            url: relay.clone(),
            datagrams: Datagrams::from(b"still connected"),
            queued: None,
        };
        send_recv_echo(packet.clone(), &send_tx, &mut recv_rx).await?;
        let mut updates = watch.watch();
        inbox_tx
            .send(ActiveRelayMessage::EntrySamples(vec![
                (relay.clone(), Duration::from_millis(200)),
                (entry.clone(), Duration::from_millis(20)),
            ]))
            .await
            .std_context("send entry measurements")?;
        tokio::time::timeout(Duration::from_secs(10), async {
            while updates.get().as_ref().map(|s| s.access_url()) != Some(&entry) {
                updates.updated().await.expect("watch remains open");
            }
        })
        .await
        .std_context("entry was selected")?;
        for _ in 0..3 {
            send_recv_echo(packet.clone(), &send_tx, &mut recv_rx).await?;
        }
        for _ in 0..2 {
            inbox_tx
                .send(ActiveRelayMessage::EntrySamples(vec![
                    (relay.clone(), Duration::from_millis(20)),
                    (entry.clone(), Duration::from_millis(200)),
                ]))
                .await
                .std_context("send direct measurements")?;
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            while updates.get().as_ref().map(|s| s.access_url()) != Some(&relay) {
                updates.updated().await.expect("watch remains open");
            }
        })
        .await
        .std_context("direct entrance was selected")?;
        for _ in 0..3 {
            send_recv_echo(packet.clone(), &send_tx, &mut recv_rx).await?;
        }
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_active_relay_reconnect() -> Result {
        let (_relay_map, relay_url, _server) = test_utils::run_relay_server().await?;
        let (peer_endpoint, _echo_endpoint_task) = start_echo_endpoint(relay_url.clone());

        let secret_key = SecretKey::from_bytes(&[1u8; 32]);
        let (datagram_recv_tx, mut datagram_recv_rx) = mpsc::channel(16);
        let (send_datagram_tx, send_datagram_rx) = mpsc::channel(16);
        let (inbox_tx, inbox_rx) = mpsc::channel(16);
        let cancel_token = CancellationToken::new();
        let task = start_active_relay_actor(
            secret_key,
            cancel_token.clone(),
            relay_url.clone(),
            inbox_rx,
            send_datagram_rx,
            datagram_recv_tx.clone(),
            info_span!("actor-under-test"),
        );

        // Send a datagram to our echo endpoint.
        info!("first echo");
        let hello_send_item = RelaySendItem {
            remote_endpoint: peer_endpoint,
            url: relay_url.clone(),
            datagrams: Datagrams::from(b"hello"),
            queued: None,
        };
        send_recv_echo(
            hello_send_item.clone(),
            &send_datagram_tx,
            &mut datagram_recv_rx,
        )
        .await?;

        // Now ask to check the connection, triggering a ping but no reconnect.
        let (tx, rx) = oneshot::channel();
        inbox_tx
            .send(ActiveRelayMessage::GetLocalAddr(tx))
            .await
            .std_context("send get local addr msg")?;

        let local_addr = rx
            .await
            .std_context("wait for local addr msg")?
            .context("no local addr")?;
        info!(?local_addr, "check connection with addr");
        inbox_tx
            .send(ActiveRelayMessage::CheckConnection {
                local_ips: vec![local_addr.ip()],
            })
            .await
            .std_context("send check connection message")?;

        // Sync the ActiveRelayActor. Ping blocks it and we want to be sure it has handled
        // another inbox message before continuing.
        let (tx, rx) = oneshot::channel();
        inbox_tx
            .send(ActiveRelayMessage::GetLocalAddr(tx))
            .await
            .std_context("send get local addr msg")?;
        rx.await.std_context("recv send local addr msg")?;

        // Echo should still work.
        info!("second echo");
        send_recv_echo(
            hello_send_item.clone(),
            &send_datagram_tx,
            &mut datagram_recv_rx,
        )
        .await?;

        // Now ask to check the connection, this will reconnect without pinging because we
        // do not supply any "valid" local IP addresses.
        info!("check connection");
        inbox_tx
            .send(ActiveRelayMessage::CheckConnection {
                local_ips: Vec::new(),
            })
            .await
            .std_context("send check connection msg")?;

        // Give some time to reconnect, mostly to sort logs rather than functional.
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Echo should still work.
        info!("third echo");
        send_recv_echo(
            hello_send_item.clone(),
            &send_datagram_tx,
            &mut datagram_recv_rx,
        )
        .await?;

        // Shut down the actor.
        cancel_token.cancel();
        task.await.std_context("wait for task to finish")?;

        Ok(())
    }

    /// ember: the relay says this connection is inactive (another of its endpoint id connected) before it is the home
    /// relay (with several relays, home is chosen after the net report): said in the home relay status once it is
    /// home, not lost with the write the URL guard dropped. The relay says it once.
    #[tokio::test]
    #[traced_test]
    async fn test_same_endpoint_id_connected_before_home_is_said_once_home() -> Result {
        let (_relay_map, relay_url, _server) = test_utils::run_relay_server().await?;
        let secret_key = SecretKey::from_bytes(&[3u8; 32]);
        let watch = HomeRelayWatch::default();
        let (datagram_recv_tx, _datagram_recv_rx) = mpsc::channel(16);
        let (_send_datagram_tx, send_datagram_rx) = mpsc::channel(16);
        let (inbox_tx, inbox_rx) = mpsc::channel(16);
        let cancel_token = CancellationToken::new();
        let _task = start_active_relay_actor_watched(
            secret_key.clone(),
            cancel_token.clone(),
            relay_url.clone(),
            inbox_rx,
            send_datagram_rx,
            datagram_recv_tx,
            info_span!("first"),
            watch.clone(),
        );
        // Connected: it has a local address.
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let (tx, rx) = oneshot::channel();
                inbox_tx
                    .send(ActiveRelayMessage::GetLocalAddr(tx))
                    .await
                    .unwrap();
                if rx.await.unwrap().is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .std_context("first connected")?;

        // Another of the same endpoint id: the relay holds the first inactive and tells it, while it is no home relay.
        let (other_recv_tx, _other_recv_rx) = mpsc::channel(16);
        let (_other_send_tx, other_send_rx) = mpsc::channel(16);
        let (_other_inbox_tx, other_inbox_rx) = mpsc::channel(16);
        let _other = start_active_relay_actor(
            secret_key,
            cancel_token.clone(),
            relay_url.clone(),
            other_inbox_rx,
            other_send_rx,
            other_recv_tx,
            info_span!("second"),
        );
        tokio::time::timeout(Duration::from_secs(10), async {
            while !logs_contain("this connection is inactive") {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .std_context("the relay said the first is inactive")?;
        assert_eq!(watch.get(), None);

        // Made home now, as the RelayActor does: the URL first, then the actor told.
        watch.set(relay_url.clone(), RelayConnectionState::Connecting);
        inbox_tx
            .send(ActiveRelayMessage::SetHomeRelay(true))
            .await
            .std_context("set home")?;
        tokio::time::timeout(Duration::from_secs(10), async {
            while !watch
                .get()
                .is_some_and(|s| s.is_connected() && s.same_endpoint_id_connected())
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .std_context("said in the home relay status once home")?;
        cancel_token.cancel();
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_active_relay_inactive() -> Result {
        let (_relay_map, relay_url, _server) = test_utils::run_relay_server().await?;

        let secret_key = SecretKey::from_bytes(&[1u8; 32]);
        let (datagram_recv_tx, _datagram_recv_rx) = mpsc::channel(16);
        let (_send_datagram_tx, send_datagram_rx) = mpsc::channel(16);
        let (inbox_tx, inbox_rx) = mpsc::channel(16);
        let cancel_token = CancellationToken::new();
        let mut task = start_active_relay_actor(
            secret_key,
            cancel_token.clone(),
            relay_url,
            inbox_rx,
            send_datagram_rx,
            datagram_recv_tx,
            info_span!("actor-under-test"),
        );

        // Wait until the actor is connected to the relay server.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let (tx, rx) = oneshot::channel();
                inbox_tx.send(ActiveRelayMessage::PingServer(tx)).await.ok();
                if tokio::time::timeout(Duration::from_millis(200), rx)
                    .await
                    .map(|resp| resp.is_ok())
                    .unwrap_or_default()
                {
                    break;
                }
            }
        })
        .await
        .std_context("timeout")?;

        // We now have an idling ActiveRelayActor.  If we advance time just a little it
        // should stay alive.
        info!("Stepping time forwards by RELAY_INACTIVE_CLEANUP_TIME / 2");
        tokio::time::pause();
        tokio::time::advance(RELAY_INACTIVE_CLEANUP_TIME / 2).await;
        tokio::time::resume();

        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut task)
                .await
                .is_err(),
            "actor task terminated"
        );

        // If we advance time a lot it should finish.
        info!("Stepping time forwards by RELAY_INACTIVE_CLEANUP_TIME");
        tokio::time::pause();
        tokio::time::advance(RELAY_INACTIVE_CLEANUP_TIME).await;
        tokio::time::resume();

        // We resume time for these timeouts, as there's actual I/O happening,
        // for example closing the TCP stream, so we actually need the tokio
        // runtime to idle a bit while the kernel is doing its thing.
        assert!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .is_ok(),
            "actor task still running"
        );

        cancel_token.cancel();
        Ok(())
    }

    /// ember: a relay that does not answer (here one that takes the TCP connection and never its handshake: dialed
    /// for seconds) holds no datagram for another relay of the same transport. Upstream the transport's actor waited
    /// for room in the unanswering relay's queue, and while it waited sent nothing to any relay, until that queue was
    /// emptied as undeliverable (`UNDELIVERABLE_DATAGRAM_TIMEOUT`, 3 s): one unreachable self-hosted relay held the
    /// devices' connections to every station through a healthy one for seconds. The bound is that timeout: an echo
    /// through the local relay takes milliseconds, and upstream could not answer before it.
    #[tokio::test]
    #[traced_test]
    async fn test_unreachable_relay_does_not_hold_up_another() -> Result {
        let (relay_map, relay_url, _server) = test_utils::run_relay_server().await?;
        let (peer, _echo) = start_echo_endpoint(relay_url.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .std_context("bind unanswering relay")?;
        let unanswering: RelayUrl = format!(
            "https://{}",
            listener.local_addr().std_context("unanswering relay address")?
        )
        .parse()
        .std_context("unanswering relay URL")?;
        let _unanswering = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        }));

        let config = Config {
            my_relay: HomeRelayWatch::default(),
            secret_key: SecretKey::generate(),
            dns_resolver: DnsResolver::new(),
            proxy_url: None,
            relay_udp: Default::default(),
            ipv6_reported: Arc::new(AtomicBool::new(false)),
            tls_config: CaTlsConfig::insecure_skip_verify()
                .client_config(default_provider())
                .expect("infallible"),
            metrics: Default::default(),
            relay_map,
            relay_allowlist: Default::default(),
            excludes: Default::default(),
            own: None,
            others: Vec::new(),
        };
        let (recv_tx, mut recv_rx) = mpsc::channel(RELAY_DATAGRAM_QUEUE);
        // Room for all this test sends: it never waits on the actor.
        let (send_tx, send_rx) = mpsc::channel(2 * RELAY_DATAGRAM_QUEUE);
        let (_msg_tx, msg_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();
        let actor = RelayActor::new(config, recv_tx, cancel.clone());
        let _actor = AbortOnDropHandle::new(tokio::spawn(
            actor.run(msg_rx, send_rx).instrument(info_span!("relay-actor")),
        ));

        let packet = RelaySendItem {
            remote_endpoint: peer,
            url: relay_url.clone(),
            datagrams: Datagrams::from(b"through the healthy relay"),
            queued: None,
        };
        // Connected to the healthy relay, its echo answering.
        send_recv_echo(packet.clone(), &send_tx, &mut recv_rx).await?;
        while tokio::time::timeout(Duration::from_millis(100), recv_rx.recv())
            .await
            .is_ok()
        {}

        // More than any relay's queue holds for the unanswering relay, then one for the healthy relay.
        let nobody = SecretKey::generate().public();
        let start = tokio::time::Instant::now();
        for i in 0..RELAY_DATAGRAM_QUEUE + 200 {
            send_tx
                .try_send(RelaySendItem {
                    remote_endpoint: nobody,
                    url: unanswering.clone(),
                    datagrams: Datagrams::from(&(i as u64).to_le_bytes()),
                    queued: None,
                })
                .expect("room in the transport's queue");
        }
        send_tx
            .try_send(packet.clone())
            .expect("room in the transport's queue");
        let echoed = tokio::time::timeout(UNDELIVERABLE_DATAGRAM_TIMEOUT, recv_rx.recv()).await;
        let took = start.elapsed();
        info!(?took, "echo through the healthy relay");
        let echoed = echoed.unwrap_or_else(|_| {
            panic!("the healthy relay's datagram was held behind the unanswering relay's ({took:?})")
        });
        assert_eq!(echoed.expect("receive queue open").datagrams, packet.datagrams);

        cancel.cancel();
        Ok(())
    }

    /// ember: a datagram that waited longer than `MAX_SEND_DATAGRAM_WAIT` to be sent is dropped, not sent late; one
    /// that did not is sent. Upstream sent both: behind a slow uplink or a relay connection dialed again, datagrams
    /// seconds old reached the peer and made the connection's round trip seconds long.
    #[tokio::test]
    #[traced_test]
    async fn test_stale_send_datagrams_are_dropped() -> Result {
        let (_relay_map, relay_url, _server) = test_utils::run_relay_server().await?;
        let (peer, _echo) = start_echo_endpoint(relay_url.clone());

        let (datagram_recv_tx, mut datagram_recv_rx) = mpsc::channel(16);
        let (send_datagram_tx, send_datagram_rx) = mpsc::channel(16);
        let (_inbox_tx, inbox_rx) = mpsc::channel(16);
        let cancel_token = CancellationToken::new();
        let _task = start_active_relay_actor(
            SecretKey::from_bytes(&[5u8; 32]),
            cancel_token.clone(),
            relay_url.clone(),
            inbox_rx,
            send_datagram_rx,
            datagram_recv_tx,
            info_span!("actor-under-test"),
        );
        let item = |data: &'static [u8], queued| RelaySendItem {
            remote_endpoint: peer,
            url: relay_url.clone(),
            datagrams: Datagrams::from(data),
            queued,
        };

        // Connected, the echo answering; no echo left over.
        send_recv_echo(item(b"connected", None), &send_datagram_tx, &mut datagram_recv_rx).await?;
        while tokio::time::timeout(Duration::from_millis(100), datagram_recv_rx.recv())
            .await
            .is_ok()
        {}

        let now = n0_future::time::Instant::now();
        let stale = now
            .checked_sub(MAX_SEND_DATAGRAM_WAIT * 2)
            .expect("an instant a second ago");
        send_datagram_tx
            .send(item(b"stale", Some(stale)))
            .await
            .std_context("send stale")?;
        send_datagram_tx
            .send(item(b"fresh", Some(now)))
            .await
            .std_context("send fresh")?;
        let first = tokio::time::timeout(Duration::from_secs(10), datagram_recv_rx.recv())
            .await
            .std_context("an echo")?
            .expect("receive queue open");
        assert_eq!(
            first.datagrams,
            Datagrams::from(b"fresh"),
            "the stale datagram was sent"
        );
        // Nor sent later: the next echo is of what is sent next.
        send_datagram_tx
            .send(item(b"after", Some(n0_future::time::Instant::now())))
            .await
            .std_context("send after")?;
        let next = tokio::time::timeout(Duration::from_secs(10), datagram_recv_rx.recv())
            .await
            .std_context("an echo")?
            .expect("receive queue open");
        assert_eq!(next.datagrams, Datagrams::from(b"after"));

        cancel_token.cancel();
        Ok(())
    }

    fn test_config(relay_map: iroh_relay::RelayMap, others: Vec<RelayUrl>) -> Config {
        Config {
            my_relay: HomeRelayWatch::default(),
            secret_key: SecretKey::generate(),
            dns_resolver: DnsResolver::new(),
            proxy_url: None,
            relay_udp: Default::default(),
            ipv6_reported: Arc::new(AtomicBool::new(false)),
            tls_config: CaTlsConfig::insecure_skip_verify()
                .client_config(default_provider())
                .expect("infallible"),
            metrics: Default::default(),
            relay_map,
            relay_allowlist: Default::default(),
            excludes: Default::default(),
            own: None,
            others,
        }
    }

    /// A handle whose actor never reads its inboxes, as one held up would not; the receivers are returned to be kept
    /// open.
    fn silent_handle() -> (
        ActiveRelayHandle,
        mpsc::Receiver<ActiveRelayMessage>,
        mpsc::Receiver<RelaySendItem>,
    ) {
        let (inbox_addr, inbox_rx) = mpsc::channel(8);
        let (datagrams_send_queue, send_rx) = mpsc::channel(8);
        let handle = ActiveRelayHandle {
            stop: CancellationToken::new(),
            endpoints_present: Default::default(),
            inbox_addr,
            datagrams_send_queue,
        };
        (handle, inbox_rx, send_rx)
    }

    /// ember: with `Builder::home_on_every_relay` the first transport shares the endpoint's map, which has an inserted
    /// relay before this actor is told of it (`RelayActorMessage::InsertRelay`); in between this transport may have
    /// connected to it, even be home on it. Once it is another transport's relay again, this transport's connection to
    /// it ends and its home is another, as on `remove_relay`: two connections of one endpoint id to one relay displace
    /// each other (`SameEndpointIdConnected`).
    #[tokio::test]
    #[traced_test]
    async fn inserted_relay_of_another_transport_ends_connection_and_home_here() {
        let excluded: RelayUrl = "http://127.0.0.1:1".parse().unwrap();
        let other: RelayUrl = "http://127.0.0.1:2".parse().unwrap();
        let map: iroh_relay::RelayMap = [excluded.clone(), other.clone()].into_iter().collect();
        let (received, _rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let mut actor = RelayActor::new(
            test_config(map, vec![excluded.clone()]),
            received,
            cancel.clone(),
        );
        let (handle, _inbox, _send) = silent_handle();
        let stop = handle.stop.clone();
        actor.active_relays.insert(excluded.clone(), handle);
        actor
            .config
            .my_relay
            .set(excluded.clone(), RelayConnectionState::Connected);

        let relay_config = actor.config.relay_map.get(&excluded).expect("in the map");
        actor.insert_relay(excluded.clone(), relay_config).await;

        assert!(
            actor.config.excludes.read().unwrap().contains(&excluded),
            "the relay is excluded again"
        );
        assert!(
            !actor.active_relays.contains_key(&excluded),
            "the excluded relay's actor is still active"
        );
        assert!(stop.is_cancelled(), "the excluded relay's actor was not stopped");
        assert_eq!(
            actor.config.my_relay.get().map(|status| status.url().clone()),
            Some(other.clone()),
            "home is still the excluded relay"
        );
        assert!(actor.active_relays.contains_key(&other), "no actor for the new home");
        cancel.cancel();
    }

    /// Backing off before dialing again (up to 16 s) the actor still takes its messages and stops when told. Upstream
    /// it slept through them.
    #[tokio::test]
    #[traced_test]
    async fn backing_off_takes_its_inbox_and_stops() {
        let (inbox_tx, inbox) = mpsc::channel(8);
        let (_send_tx, relay_datagrams_send) = mpsc::channel(1);
        let (relay_datagrams_recv, _recv_rx) = mpsc::channel(1);
        let stop = CancellationToken::new();
        let mut actor = ActiveRelayActor::new(ActiveRelayActorOptions {
            url: "http://127.0.0.1:1".parse().unwrap(),
            entries: Vec::new(),
            endpoints_present: Default::default(),
            inbox,
            relay_datagrams_send,
            relay_datagrams_recv,
            connection_opts: RelayConnectionOptions {
                secret_key: SecretKey::generate(),
                dns_resolver: DnsResolver::new(),
                proxy_url: None,
                prefer_ipv6: Arc::new(AtomicBool::new(false)),
                tls_config: CaTlsConfig::insecure_skip_verify()
                    .client_config(default_provider())
                    .expect("infallible"),
                auth_token: None,
                udp: Default::default(),
            },
            stop_token: stop.clone(),
            metrics: Default::default(),
            my_relay: Default::default(),
        });
        let task = AbortOnDropHandle::new(tokio::spawn(async move {
            let go_on = actor.sleep_backoff(Duration::from_secs(10)).await;
            (go_on, actor)
        }));

        inbox_tx
            .send(ActiveRelayMessage::SetHomeRelay(true))
            .await
            .unwrap();
        // The inbox is read in order: once this is answered, `SetHomeRelay` was taken.
        let (tx, rx) = oneshot::channel();
        inbox_tx
            .send(ActiveRelayMessage::GetLocalAddr(tx))
            .await
            .unwrap();
        let local = tokio::time::timeout(Duration::from_millis(200), rx)
            .await
            .expect("inbox not read within 200 ms while backing off");
        assert_eq!(local.expect("answered"), None);

        stop.cancel();
        let (go_on, actor) = tokio::time::timeout(Duration::from_millis(200), task)
            .await
            .expect("did not stop within 200 ms while backing off")
            .expect("task");
        assert!(!go_on, "stopped, the actor must exit");
        assert!(actor.is_home_relay, "SetHomeRelay taken while backing off");
    }

    /// ember: finding the relay that reaches an endpoint reads each connection's `endpoints_present` and asks no actor,
    /// so an actor that does not answer (backing off, closing a dead connection, its inbox full) holds up no datagram.
    /// Upstream it asked each actor and waited for every answer, sending no datagram meanwhile.
    #[tokio::test]
    #[traced_test]
    async fn route_lookup_reads_endpoints_present_and_asks_no_actor() {
        let silent: RelayUrl = "http://127.0.0.1:1".parse().unwrap();
        let knows: RelayUrl = "http://127.0.0.1:2".parse().unwrap();
        let home: RelayUrl = "http://127.0.0.1:3".parse().unwrap();
        let map: iroh_relay::RelayMap = [silent.clone(), knows.clone(), home.clone()]
            .into_iter()
            .collect();
        let (received, _rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let mut actor = RelayActor::new(test_config(map, Vec::new()), received, cancel.clone());
        let peer = SecretKey::generate().public();
        // Neither actor reads its inbox; one's connection has heard from `peer`.
        let (silent_handle_, _i1, _s1) = silent_handle();
        let (knows_handle, _i2, _s2) = silent_handle();
        knows_handle.endpoints_present.write().unwrap().insert(peer);
        actor.active_relays.insert(silent.clone(), silent_handle_);
        actor.active_relays.insert(knows.clone(), knows_handle.clone());

        let found = actor
            .active_relay_handle_for_endpoint(&home, &peer)
            .expect("a handle");
        assert!(
            Arc::ptr_eq(&found.endpoints_present, &knows_handle.endpoints_present),
            "not the relay whose connection reaches the endpoint"
        );
        assert!(!actor.active_relays.contains_key(&home), "dialed the remote's relay instead");

        // An endpoint no connection has heard from: its own relay.
        let other = SecretKey::generate().public();
        let found = actor
            .active_relay_handle_for_endpoint(&home, &other)
            .expect("a handle");
        assert!(actor.active_relays.contains_key(&home));
        assert!(Arc::ptr_eq(
            &found.endpoints_present,
            &actor.active_relays[&home].endpoints_present
        ));
        cancel.cancel();
    }

    /// ember: a connection's `endpoints_present` has each endpoint a datagram came from, loses one the relay says is
    /// gone (and takes it again from its next datagram, its last-sender shortcut reset), and is emptied as the
    /// connection ends.
    #[tokio::test]
    async fn endpoints_present_follows_the_connection() {
        let (_inbox_tx, inbox) = mpsc::channel(1);
        let (_send_tx, relay_datagrams_send) = mpsc::channel(1);
        let (relay_datagrams_recv, _recv_rx) = mpsc::channel(8);
        let endpoints_present = super::EndpointsPresent::default();
        let mut actor = ActiveRelayActor::new(ActiveRelayActorOptions {
            url: "http://127.0.0.1:1".parse().unwrap(),
            entries: Vec::new(),
            endpoints_present: endpoints_present.clone(),
            inbox,
            relay_datagrams_send,
            relay_datagrams_recv,
            connection_opts: RelayConnectionOptions {
                secret_key: SecretKey::generate(),
                dns_resolver: DnsResolver::new(),
                proxy_url: None,
                prefer_ipv6: Arc::new(AtomicBool::new(false)),
                tls_config: CaTlsConfig::insecure_skip_verify()
                    .client_config(default_provider())
                    .expect("infallible"),
                auth_token: None,
                udp: Default::default(),
            },
            stop_token: CancellationToken::new(),
            metrics: Default::default(),
            my_relay: Default::default(),
        });
        let mut state = super::ConnectedRelayState {
            ping_tracker: PingTracker::default(),
            last_packet_src: None,
            pong_pending: None,
            established: false,
            same_endpoint_id_connected: false,
            test_pong: None,
        };
        let (a, b) = (SecretKey::generate().public(), SecretKey::generate().public());
        let datagram = |from| super::RelayToClientMsg::Datagrams {
            remote_endpoint_id: from,
            datagrams: Datagrams::from(b"hi"),
        };
        let present = || endpoints_present.read().unwrap().clone();
        let guard = super::ClearOnDrop(endpoints_present.clone());

        actor.handle_relay_msg(datagram(a), &mut state);
        actor.handle_relay_msg(datagram(b), &mut state);
        actor.handle_relay_msg(datagram(b), &mut state);
        assert_eq!(present(), [a, b].into_iter().collect());

        actor.handle_relay_msg(super::RelayToClientMsg::EndpointGone(b), &mut state);
        assert_eq!(present(), [a].into_iter().collect());
        actor.handle_relay_msg(datagram(b), &mut state);
        assert_eq!(present(), [a, b].into_iter().collect(), "b back with its next datagram");

        drop(guard);
        assert!(present().is_empty(), "the connection ended");
    }

    #[tokio::test]
    async fn test_ping_tracker() {
        tokio::time::pause();
        let mut tracker = PingTracker::default();

        let ping0 = tracker.new_ping();

        let res = tokio::time::timeout(Duration::from_secs(1), tracker.timeout()).await;
        assert!(res.is_err(), "no ping timeout has elapsed yet");

        tracker.pong_received(ping0);
        let res = tokio::time::timeout(Duration::from_secs(10), tracker.timeout()).await;
        assert!(res.is_err(), "ping completed before timeout");

        let _ping1 = tracker.new_ping();

        let res = tokio::time::timeout(Duration::from_secs(10), tracker.timeout()).await;
        assert!(res.is_ok(), "ping timeout should have happened");

        let _ping2 = tracker.new_ping();

        tokio::time::sleep(Duration::from_secs(10)).await;
        let res = tokio::time::timeout(Duration::from_millis(1), tracker.timeout()).await;
        assert!(res.is_ok(), "ping timeout happened in the past");

        let res = tokio::time::timeout(Duration::from_secs(10), tracker.timeout()).await;
        assert!(res.is_err(), "ping timeout should only happen once");
    }

    #[test]
    fn test_home_relay_watch_url_guard() {
        use super::{HomeRelayWatch, RelayConnectionState};
        use crate::endpoint::RelayStatus;

        let watch = HomeRelayWatch::default();
        let a: RelayUrl = "https://a.example.com".parse().unwrap();
        let b: RelayUrl = "https://b.example.com".parse().unwrap();

        // Actor A becomes home and connects
        watch.set(a.clone(), RelayConnectionState::Connecting);
        watch.set_status(&a, RelayConnectionState::Connected);
        assert_eq!(
            watch.get(),
            Some(RelayStatus::new(a.clone(), RelayConnectionState::Connected)),
        );

        // RelayActor migrates home to B
        watch.set(b.clone(), RelayConnectionState::Connecting);

        // Old actor A tries to write -- rejected because URL changed
        watch.set_status(&a, RelayConnectionState::Disconnected { last_error: None });
        assert_eq!(
            watch.get(),
            Some(RelayStatus::new(
                b.clone(),
                RelayConnectionState::Connecting
            )),
        );

        // Actor B writes normally
        watch.set_status(&b, RelayConnectionState::Connected);
        assert_eq!(
            watch.get(),
            Some(RelayStatus::new(b, RelayConnectionState::Connected)),
        );
    }

    #[test]
    fn test_home_relay_watch_same_endpoint_id_connected() {
        use super::{HomeRelayWatch, RelayConnectionState};

        let watch = HomeRelayWatch::default();
        let a: RelayUrl = "https://a.example.com".parse().unwrap();
        let b: RelayUrl = "https://b.example.com".parse().unwrap();
        watch.set(a.clone(), RelayConnectionState::Connecting);
        watch.set_status(&a, RelayConnectionState::Connected);
        assert!(!watch.get().unwrap().same_endpoint_id_connected());

        // The relay holds this connection inactive: said, the state kept.
        watch.set_same_endpoint_id_connected(&a, true);
        let status = watch.get().unwrap();
        assert!(status.same_endpoint_id_connected());
        assert!(status.is_connected());
        // Not for a relay that is no longer home.
        watch.set_same_endpoint_id_connected(&b, false);
        assert!(watch.get().unwrap().same_endpoint_id_connected());
        // Healthy again: cleared.
        watch.set_same_endpoint_id_connected(&a, false);
        assert!(!watch.get().unwrap().same_endpoint_id_connected());
        // A connection made anew clears it too.
        watch.set_same_endpoint_id_connected(&a, true);
        watch.set_status(&a, RelayConnectionState::Disconnected { last_error: None });
        assert!(!watch.get().unwrap().same_endpoint_id_connected());
    }
}
