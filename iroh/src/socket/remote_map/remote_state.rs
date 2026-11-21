use std::{
    collections::{BTreeSet, VecDeque},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::Poll,
};

use iroh_base::{CustomAddr, EndpointId, RelayUrl, TransportAddr};
use n0_error::StackResultExt;
use n0_future::{
    FuturesUnordered, FuturesUnorderedBounded, MaybeFuture, MergeUnbounded, Stream, StreamExt,
    boxed::BoxStream,
    future::Boxed,
    task::JoinSet,
    time::{self, Duration, Instant},
};
use n0_watcher::Watcher;
use noq::{Closed, PathStats, PathStatus, WeakConnectionHandle};
use noq_proto::{PathError, PathEvent as NoqPathEvent, PathId, n0_nat_traversal};
use rustc_hash::FxHashMap;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, Level, Span, debug, error, event, info_span, instrument, trace, warn};

use self::path_state::RemotePathState;
pub(crate) use self::path_watcher::PathStateReceiver;
pub use self::{
    path_watcher::{Path, PathEvent, PathEventStream, PathList, PathListIter, PathListStream},
    remote_info::{RemoteInfo, TransportAddrInfo, TransportAddrUsage},
};
use super::Source;
use crate::{
    address_lookup::{AddressLookupFailed, AddressLookupServices, Item as AddressLookupItem},
    endpoint::DirectAddr,
    socket::{
        Metrics as SocketMetrics, RELAY_PATH_MAX_IDLE_TIMEOUT,
        mapped_addrs::{AddrMap, CustomMappedAddr, RelayMappedAddr},
        relay_policy::RelayPolicies,
        remote_map::remote_state::path_watcher::PathStateSender,
        transports::{self, OwnedTransmit, TransportsSender},
    },
};

mod path_state;
mod path_watcher;
mod remote_info;

/// How often to attempt holepunching.
///
/// If there have been no changes to the NAT address candidates, holepunching will not be
/// attempted more frequently than at this interval.
const HOLEPUNCH_ATTEMPTS_INTERVAL: Duration = Duration::from_secs(5);

/// The latency at or under which we don't try to upgrade to a better path.
const GOOD_ENOUGH_LATENCY: Duration = Duration::from_millis(10);

// TODO: use this
// /// How long since the last activity we try to keep an established endpoint peering alive.
// ///
// /// It's also the idle time at which we stop doing QAD queries to keep NAT mappings alive.
// pub(super) const SESSION_ACTIVE_TIMEOUT: Duration = Duration::from_secs(45);

/// How often we try to upgrade to a better path.
///
/// Even if we have some non-relay route that works.
const UPGRADE_INTERVAL: Duration = Duration::from_secs(60);

/// ember: how many times a client connection tries again to open a path to a custom transport address it lacks one
/// to, after its first try (`RemoteStateActor::open_custom_paths`), before it stops until a custom path opens on it or
/// the remote's custom addresses change. A try is a new path id taken; one already in flight is no new try.
/// A remote with several custom addresses missing uses one try per address in the same round, so it gets fewer rounds
/// (two custom addresses: tries at about 0 and 11 s); Comma's mesh gives each remote a single Salix address.
const CUSTOM_PATH_TRIES: u32 = 2;
/// ember: how long after a try starts the next may: whatever asks for one sooner (an address lookup, another dial)
/// waits, so the tries keep this pace however often they are asked for. A try that fails is given up after about
/// 3.1 s (measured with paths given up 3 s after they go quiet, as in Comma's mesh), so a transport that starts to
/// carry up to about 17 s after the first try is found: the tries start at about 0, 3 and 14 s.
const CUSTOM_PATH_RETRY_AFTER: [Duration; CUSTOM_PATH_TRIES as usize] =
    [Duration::from_secs(3), Duration::from_secs(11)];
/// ember: how soon a try due while the last is still in flight is looked at again.
const CUSTOM_PATH_RECHECK: Duration = Duration::from_secs(1);
/// ember: how many path ids a connection may lose to custom paths that never open, whatever asks for the tries (the
/// timer, a network change), until a custom path opens on it or the remote's custom addresses change. A path the remote
/// never saw (each failed try) keeps its id for good: the remote raises its path id limit by one only when it receives
/// the abandon of a path it has (noq-proto `Connection`, on PATH_ABANDON), so a path that worked and was given up
/// returns its id and one that never did does not. A connection starts with 8 (`MAX_MULTIPATH_PATHS`, ids 0 to 7); with
/// no limit a Salix that never answered took 7 of them in a test (ids 2, 3, 5 to 9, the limit 9 after two IP paths were
/// closed), and then no path of any kind could open. 4 leaves the first path, a relay, a direct path and one more.
const CUSTOM_PATH_LOST_MAX: u32 = 4;

/// ember: how many path ids a connection may lose to each relay whose path is given up before it opens
/// (`RemoteStateActor::reopen_relay_paths`), and across all relays on the connection, before it stops trying that relay
/// until a path through it opens or the network changes (major). A relay that does not answer never sees the path on
/// the remote, so each failed validation keeps its path id for good, just as for custom paths (`CUSTOM_PATH_LOST_MAX`).
const RELAY_PATH_LOST_MAX: u32 = 2;
const RELAY_CONN_LOST_MAX: u32 = 6;

/// ember: how often the path is chosen again from its connections' paths' RTTs. Chosen only as a path opened, was
/// established or was given up, a connection stayed on a relay whose path had gone seconds slow (its queue to a phone
/// growing) while another relay's answered in a few hundred milliseconds (2026-10-30, minutes long).
const PATH_RESELECT_INTERVAL: Duration = Duration::from_secs(1);

/// The time after which an idle [`RemoteStateActor`] stops.
///
/// The actor only enters the idle state if no connections are active and no inbox senders exist
/// apart from the one stored in the endpoint map. Stopping and restarting the actor in this state
/// is not an issue; a timeout here serves the purpose of not stopping-and-recreating actors
/// in a high frequency, and to keep data about previous path around for subsequent connections.
const ACTOR_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

// ember: backport upstream #4512. A blocked relay must not hold the peer actor or
// other Initial destinations; QUIC retransmits packets not admitted or expired.
const DATAGRAM_SEND_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_DATAGRAM_SEND_TASKS: usize = 16;
type DatagramSends = FuturesUnorderedBounded<Boxed<()>>;

/// A stream of events from all paths for all connections.
///
/// The connection is identified using [`ConnId`].  The event `Err` variant happens when the
/// actor has lagged processing the events, which is rather critical for us.
type PathEvents = MergeUnbounded<
    Pin<Box<dyn Stream<Item = (ConnId, Result<NoqPathEvent, noq::Lagged>)> + Send + Sync>>,
>;

/// A stream of events of announced NAT traversal candidate addresses for all connections.
///
/// The connection is identified using [`ConnId`].
type AddrEvents = MergeUnbounded<
    Pin<
        Box<
            dyn Stream<Item = (ConnId, Result<n0_nat_traversal::Event, noq::Lagged>)> + Send + Sync,
        >,
    >,
>;

/// The state we need to know about a single remote endpoint.
///
/// This actor manages all connections to the remote endpoint.  It will trigger holepunching
/// and select the best path etc.
pub(super) struct RemoteStateActor {
    /// All connections we have to this remote endpoint.
    connections: FxHashMap<ConnId, ConnectionState>,
    /// State of the actor and hooks into the rest of the remote endpoint.
    ///
    /// This is on a separate struct so that we can have parallel mutable borrows to `connections` and `state`.
    state: State,
}

/// State of the [`RemoteStateActor`] and hooks into the rest of the remote endpoint.
struct State {
    /// The endpoint ID of the remote endpoint.
    endpoint_id: EndpointId,

    // Hooks into the rest of the Socket.
    //
    /// Metrics.
    metrics: Arc<SocketMetrics>,
    /// Our local addresses.
    ///
    /// These are our local addresses and any reflexive transport addresses.
    local_direct_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
    /// The mapping between endpoints via a relay and their [`RelayMappedAddr`]s.
    relay_mapped_addrs: AddrMap<(RelayUrl, EndpointId), RelayMappedAddr>,
    /// The mapping between custom transport addresses and their [`CustomMappedAddr`]s.
    custom_mapped_addrs: AddrMap<CustomAddr, CustomMappedAddr>,
    /// Address lookup service, cloned from the socket.
    address_lookup: AddressLookupServices,

    // Internal state - Noq Connections we are managing.
    //
    /// Notifications when connections are closed.
    connections_close: FuturesUnordered<OnClosed>,
    /// Events emitted by Noq about path changes, for all paths, all connections.
    path_events: PathEvents,
    /// A stream of events of announced NAT traversal candidate addresses for all connections.
    addr_events: AddrEvents,

    // Internal state - Holepunching and path state.
    //
    /// All possible paths we are aware of.
    ///
    /// These paths might be entirely impossible to use, since they are added by Address Lookup
    /// mechanisms.  The are only potentially usable.
    paths: RemotePathState,
    /// Information about the last holepunching attempt.
    last_holepunch: Option<HolepunchAttempt>,

    /// The path we currently consider the preferred path to the remote endpoint.
    ///
    /// **We expect this path to work.** If we become aware this path is broken then it is
    /// set back to `None`.  Having a selected path does not mean we may not be able to get
    /// a better path: e.g. when the selected path is a relay path we still need to trigger
    /// holepunching regularly.
    ///
    /// We only select a path once the path is functional in Noq.
    selected_path: Option<transports::FourTuple>,
    /// Time at which we should schedule the next holepunch attempt.
    scheduled_holepunch: Option<Instant>,
    /// When to next attempt opening paths in [`Self::pending_open_paths`].
    scheduled_open_path: Option<Instant>,
    /// Paths which we still need to open.
    ///
    /// They failed to open because we did not have enough CIDs issued by the remote.
    ///
    /// ember: each address at most once (n0-computer/iroh#4390, upstream's fix #4551 is in no release yet).
    pending_open_paths: VecDeque<transports::FourTuple>,

    // Internal state - address lookup
    //
    /// Stream of Address Lookup results, or always pending if Address Lookup is not running.
    address_lookup_stream: Option<BoxStream<Result<AddressLookupItem, AddressLookupFailed>>>,

    /// The path selector used to pick the preferred path among the candidates.
    path_selector: Arc<dyn PathSelector>,

    /// ember: the datagrams last sent to every known path while none was selected (a connection's Initial
    /// packets), and how to send them. Addresses that Address Lookup finds afterwards get them at once, rather than
    /// only with QUIC's next retransmit (1 s, then 3 s, after the first). A copy the remote has had already is a
    /// duplicate packet, which it drops.
    unanswered: Option<(Box<TransportsSender>, Vec<OwnedTransmit>)>,
    /// ember: whether the endpoint is home on several relays (`Builder::home_on_every_relay`).
    several_relays: bool,
    /// ember: when the relay paths missing are opened again (`RemoteStateActor::reopen_relay_paths`).
    relay_reopen_at: Option<Instant>,
    /// ember: when to next try opening paths to the custom transport addresses a client connection lacks.
    scheduled_custom_open: Option<Instant>,
    /// ember: the remote's custom addresses at the last try.
    known_custom: BTreeSet<transports::Addr>,
    /// ember: the relays each remote is not to be reached through (`Endpoint::set_disabled_relays`), read as they are used.
    relay_policies: RelayPolicies,
}

/// ember: how many of the last datagrams sent before a path was selected are kept for [`State::unanswered`].
const UNANSWERED_KEPT: usize = 4;

/// ember: how long after a relay's path is given up it is opened again (`reopen_relay_paths`).
const RELAY_REOPEN: Duration = Duration::from_secs(2);

impl RemoteStateActor {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        endpoint_id: EndpointId,
        local_direct_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
        relay_mapped_addrs: AddrMap<(RelayUrl, EndpointId), RelayMappedAddr>,
        custom_mapped_addrs: AddrMap<CustomAddr, CustomMappedAddr>,
        metrics: Arc<SocketMetrics>,
        address_lookup: AddressLookupServices,
        path_selector: Arc<dyn PathSelector>,
        several_relays: bool,
        relay_policies: RelayPolicies,
    ) -> Self {
        let mut actor = Self {
            connections: FxHashMap::default(),
            state: State {
                endpoint_id,
                metrics: metrics.clone(),
                local_direct_addrs,
                relay_mapped_addrs,
                custom_mapped_addrs,
                address_lookup,
                connections_close: Default::default(),
                path_events: Default::default(),
                addr_events: Default::default(),
                paths: RemotePathState::new(metrics, relay_policies.allowlist.clone()),
                last_holepunch: None,
                selected_path: Default::default(),
                scheduled_holepunch: None,
                scheduled_open_path: None,
                pending_open_paths: VecDeque::new(),
                address_lookup_stream: None,
                path_selector,
                unanswered: None,
                several_relays,
                relay_reopen_at: None,
                scheduled_custom_open: None,
                known_custom: BTreeSet::new(),
                relay_policies,
            },
        };
        // ember: an actor started anew goes by the remote's disabled relays as they are.
        let disabled = actor.state.relay_policies.disabled(&endpoint_id);
        let _ = actor.state.paths.set_disabled_relays(disabled);
        actor
    }

    pub(super) fn start(
        self,
        initial_msgs: Vec<RemoteStateMessage>,
        tasks: &mut JoinSet<(EndpointId, Vec<RemoteStateMessage>)>,
        shutdown_token: CancellationToken,
        parent_span: Span,
    ) -> mpsc::Sender<RemoteStateMessage> {
        let (tx, rx) = mpsc::channel(16);
        let endpoint_id = self.state.endpoint_id;

        // Ideally we'd use the endpoint span as parent.  We'd have to plug that span into
        // here somehow.  Instead we have no parent and explicitly set the me attribute.  If
        // we don't explicitly set a span we get the spans from whatever call happens to
        // first create the actor, which is often very confusing as it then keeps those
        // spans for all logging of the actor.
        tasks.spawn(
            self.run(initial_msgs, rx, shutdown_token)
                .instrument(info_span!(
                    parent: parent_span,
                    "RemoteStateActor",
                    remote = %endpoint_id.fmt_short(),
                )),
        );
        tx
    }

    /// Runs the actor without waiting on any transport's send queue.
    async fn run(
        mut self,
        initial_msgs: Vec<RemoteStateMessage>,
        mut inbox: mpsc::Receiver<RemoteStateMessage>,
        shutdown_token: CancellationToken,
    ) -> (EndpointId, Vec<RemoteStateMessage>) {
        trace!("actor started");
        let mut send_tasks = DatagramSends::new(MAX_DATAGRAM_SEND_TASKS);
        for msg in initial_msgs {
            self.handle_message(msg, &mut send_tasks);
        }
        let idle_timeout = time::sleep(ACTOR_MAX_IDLE_TIMEOUT);
        n0_future::pin!(idle_timeout);

        let check_connections = time::interval(UPGRADE_INTERVAL);
        n0_future::pin!(check_connections);
        let reselect = time::interval(PATH_RESELECT_INTERVAL);
        n0_future::pin!(reselect);

        loop {
            let scheduled_path_open = match self.state.scheduled_open_path {
                Some(when) => MaybeFuture::Some(time::sleep_until(when)),
                None => MaybeFuture::None,
            };
            n0_future::pin!(scheduled_path_open);
            let scheduled_hp = match self.state.scheduled_holepunch {
                Some(when) => MaybeFuture::Some(time::sleep_until(when)),
                None => MaybeFuture::None,
            };
            n0_future::pin!(scheduled_hp);
            let relay_reopen = match self.state.relay_reopen_at {
                Some(when) => MaybeFuture::Some(time::sleep_until(when)),
                None => MaybeFuture::None,
            };
            n0_future::pin!(relay_reopen);
            let scheduled_custom_open = match self.state.scheduled_custom_open {
                Some(when) => MaybeFuture::Some(time::sleep_until(when)),
                None => MaybeFuture::None,
            };
            n0_future::pin!(scheduled_custom_open);
            if !self.is_idle(&inbox) {
                idle_timeout
                    .as_mut()
                    .reset(Instant::now() + ACTOR_MAX_IDLE_TIMEOUT);
            }

            tokio::select! {
                biased;

                _ = shutdown_token.cancelled() => {
                    trace!("actor cancelled");
                    break;
                }
                Some(()) = send_tasks.next(), if !send_tasks.is_empty() => {}
                msg = inbox.recv() => {
                    match msg {
                        Some(msg) => self.handle_message(msg, &mut send_tasks),
                        None => break,
                    }
                }
                Some((id, evt)) = self.state.path_events.next() => {
                    self.handle_path_event(id, evt);
                }
                Some((id, evt)) = self.state.addr_events.next() => {
                    trace!(?id, ?evt, "remote addrs updated, triggering holepunching");
                    self.trigger_holepunching();
                }
                Some((conn_id, closed)) = self.state.connections_close.next(), if !self.state.connections_close.is_empty() => {
                    self.handle_connection_close(conn_id, closed);
                }
                res = self.state.local_direct_addrs.updated() => {
                    if let Err(n0_watcher::Disconnected) = res {
                        trace!("direct address watcher disconnected, shutting down");
                        break;
                    }
                    self.update_local_direct_address();
                    trace!("local addrs updated, triggering holepunching");
                    self.trigger_holepunching();
                }
                _ = &mut scheduled_path_open => {
                    trace!("triggering scheduled path_open");
                    self.state.scheduled_open_path = None;
                    let mut addrs = std::mem::take(&mut self.state.pending_open_paths);
                    while let Some(addr) = addrs.pop_front() {
                        self.open_path_on_all_conns(&addr);
                    }
                }
                _ = &mut scheduled_hp => {
                    trace!("triggering scheduled holepunching");
                    self.state.scheduled_holepunch = None;
                    self.trigger_holepunching();
                }
                Some(item) = maybe_next(self.state.address_lookup_stream.as_mut()), if self.state.address_lookup_stream.is_some() => {
                    self.state.handle_address_lookup_item(item, &mut send_tasks);
                    self.open_custom_paths();
                }
                _ = &mut scheduled_custom_open => {
                    self.state.scheduled_custom_open = None;
                    self.open_custom_paths();
                }
                _ = &mut relay_reopen => {
                    self.state.relay_reopen_at = None;
                    self.reopen_relay_paths();
                }
                _ = check_connections.tick() => {
                    self.check_connections();
                }
                _ = reselect.tick(), if !self.connections.is_empty() => {
                    self.select_path();
                }
                _ = &mut idle_timeout => {
                    if self.is_idle(&inbox) {
                        trace!("idle timeout expired and still idle: terminate actor");
                        break;
                    } else {
                        // Seems like we weren't really idle, so we reset
                        idle_timeout.as_mut().reset(Instant::now() + ACTOR_MAX_IDLE_TIMEOUT);
                    }
                }
            }
        }

        inbox.close();
        // There might be a race between checking `inbox.is_empty()` and `inbox.close()`,
        // so we pull out all messages that are left over.
        let mut leftover_msgs = Vec::with_capacity(inbox.len());
        inbox.recv_many(&mut leftover_msgs, inbox.len()).await;

        drop(send_tasks);
        trace!("actor terminating");
        (self.state.endpoint_id, leftover_msgs)
    }

    /// Returns `true` if the actor is fully idle.
    fn is_idle(&self, inbox: &mpsc::Receiver<RemoteStateMessage>) -> bool {
        self.connections.is_empty()
            && inbox.is_empty()
            && self.state.paths.resolve_requests_is_empty()
    }

    /// Handles an actor message, admitting transport sends as bounded independent work.
    #[instrument(skip(self, send_tasks))]
    fn handle_message(&mut self, msg: RemoteStateMessage, send_tasks: &mut DatagramSends) {
        // trace!("handling message");
        match msg {
            RemoteStateMessage::SendDatagram(sender, transmit) => {
                self.state.handle_msg_send_datagram(sender, transmit, send_tasks);
            }
            RemoteStateMessage::AddConnection(handle, tx) => {
                self.handle_msg_add_connection(handle, tx);
            }
            RemoteStateMessage::ResolveRemote(addrs, disabled, tx) => {
                // ember: the socket's sets took these before the message was sent (`resolve_remote_disabled`); what
                // the remote's connections have through them is given up as with `set_disabled_relays`.
                if disabled.is_some() {
                    self.apply_relay_policy();
                }
                self.state.handle_msg_resolve_remote(addrs, tx);
                self.open_custom_paths();
            }
            RemoteStateMessage::RemoteInfo(tx) => {
                let addrs = self.state.paths.to_remote_addrs();
                let info = RemoteInfo {
                    endpoint_id: self.state.endpoint_id,
                    addrs,
                };
                tx.send(info).ok();
            }
            RemoteStateMessage::NetworkChange { is_major } => {
                self.handle_msg_network_change(is_major);
            }
            RemoteStateMessage::ApplyRelayPolicy(done) => {
                self.apply_relay_policy();
                done.send(()).ok();
            }
            RemoteStateMessage::RelayRemoved(url, done) => {
                self.handle_relay_removed(url);
                done.send(()).ok();
            }
            RemoteStateMessage::RelayConnected(url) => {
                self.handle_relay_connected(url);
            }
            #[cfg(test)]
            RemoteStateMessage::RelayLossStats(conn_stable_id, url, tx) => {
                let stats = self.connections.get(&ConnId(conn_stable_id)).map(|conn_state| {
                    let opening = conn_state
                        .relay_opening
                        .values()
                        .filter(|a| matches!(a, transports::Addr::Relay(u, _) if u == &url))
                        .count();
                    let lost = conn_state
                        .relay_lost
                        .iter()
                        .filter(|(a, _)| matches!(a, transports::Addr::Relay(u, _) if u == &url))
                        .map(|(_, &n)| n)
                        .sum();
                    (opening, lost, conn_state.relay_lost_total)
                });
                tx.send(stats).ok();
            }
        }
    }

    /// ember: goes by the remote's disabled relays as they are now (`Endpoint::set_disabled_relays`, `ConnectOptions::with_disabled_relays`): every address of it
    /// through a disabled relay is shelved out of `paths` (and restored when allowed again), with the paths waiting to
    /// be opened to one dropped, and on every connection the paths through one, and those being opened, closed and
    /// taken out of the connection's state at once (so no selection takes one before its abandon is polled). When
    /// shelved relays become allowed again, their `relay_lost` counters are cleared and client connections reopen paths
    /// through them immediately.
    fn apply_relay_policy(&mut self) {
        let endpoint_id = self.state.endpoint_id;
        let policies = self.state.relay_policies.clone();
        let restored = self.state.paths.set_disabled_relays(policies.disabled(&endpoint_id));
        self.state.paths.retain(|addr| relay_allowed(&policies, &endpoint_id, addr));
        self.state
            .pending_open_paths
            .retain(|tuple| relay_usable(&policies, &endpoint_id, &tuple.remote()));
        if self
            .state
            .selected_path
            .as_ref()
            .is_some_and(|tuple| !relay_usable(&policies, &endpoint_id, &tuple.remote()))
        {
            self.state.selected_path = None;
        }
        let relays: Vec<_> = self
            .state
            .paths
            .addrs()
            .filter(|addr| addr.is_relay() && relay_usable(&policies, &endpoint_id, addr))
            .map(|addr| transports::FourTuple::from_remote(addr.clone()))
            .collect();
        for (conn_id, conn_state) in self.connections.iter_mut() {
            if conn_state.relay_lost_total < RELAY_CONN_LOST_MAX {
                for addr in &restored {
                    conn_state.relay_lost.remove(addr);
                }
            }
            let Some(conn) = conn_state.handle.upgrade() else {
                continue;
            };
            let forbidden = conn_state
                .paths
                .values()
                .any(|tuple| !relay_usable(&policies, &endpoint_id, &tuple.remote()));
            if forbidden && conn.side().is_client() {
                // (a way left before one is given up: QUIC keeps a connection's last path)
                for open_addr in &relays {
                    self.state.open_path_on_conn(*conn_id, conn_state, &conn, open_addr);
                }
            }
            self.state.close_forbidden_paths(*conn_id, conn_state, &conn);
        }
        if !restored.is_empty() {
            self.reopen_relay_paths();
        }
        self.select_path();
        self.trigger_holepunching();
    }

    /// ember: `url` was locally removed (`Endpoint::remove_relay`): keep `url` in `State::paths` as a known remote
    /// address for when `url` is inserted again, but immediately close paths through `url` on active connections so
    /// they neither wait out idle timeout nor exhaust `relay_lost`.
    fn handle_relay_removed(&mut self, url: RelayUrl) {
        let endpoint_id = self.state.endpoint_id;
        let policies = self.state.relay_policies.clone();
        self.state
            .pending_open_paths
            .retain(|tuple| relay_usable(&policies, &endpoint_id, &tuple.remote()));
        if self
            .state
            .selected_path
            .as_ref()
            .is_some_and(|tuple| !relay_usable(&policies, &endpoint_id, &tuple.remote()))
        {
            self.state.selected_path = None;
        }
        let relays: Vec<_> = self
            .state
            .paths
            .addrs()
            .filter(|addr| addr.is_relay() && relay_usable(&policies, &endpoint_id, addr))
            .map(|addr| transports::FourTuple::from_remote(addr.clone()))
            .collect();
        let target = transports::Addr::Relay(url, endpoint_id);
        for (conn_id, conn_state) in self.connections.iter_mut() {
            let Some(conn) = conn_state.handle.upgrade() else {
                continue;
            };
            let has_removed = conn_state.paths.values().any(|tuple| tuple.remote() == target);
            if has_removed && conn.side().is_client() {
                for open_addr in &relays {
                    self.state.open_path_on_conn(*conn_id, conn_state, &conn, open_addr);
                }
            }
            self.state.close_forbidden_paths(*conn_id, conn_state, &conn);
        }
        self.select_path();
        self.trigger_holepunching();
    }

    /// ember: local relay `url` is connected and usable again (e.g. after `Endpoint::insert_relay` reconnects): clear
    /// per-relay `relay_lost` for `url` and reopen missing client paths through it.
    fn handle_relay_connected(&mut self, url: RelayUrl) {
        let addr = transports::Addr::Relay(url, self.state.endpoint_id);
        if !self.state.relay_usable(&addr) || !self.state.paths.addrs().any(|a| a == &addr) {
            return;
        }
        for conn_state in self.connections.values_mut() {
            if conn_state.relay_lost_total < RELAY_CONN_LOST_MAX {
                conn_state.relay_lost.remove(&addr);
            }
        }
        self.reopen_relay_paths();
    }

    /// Handles [`RemoteStateMessage::AddConnection`].
    ///
    /// Error returns are fatal and kill the actor.
    fn handle_msg_add_connection(
        &mut self,
        conn: noq::Connection,
        tx: oneshot::Sender<PathStateReceiver>,
    ) {
        let (path_state_sender, path_state_receiver) = PathStateSender::new();
        self.state.metrics.num_conns_opened.inc();
        // Remove any conflicting stable_ids from the local state.
        let conn_id = ConnId(conn.stable_id());
        self.connections.remove(&conn_id);

        // Hook up paths, NAT addresses and connection closed event streams.
        self.state
            .path_events
            .push(Box::pin(conn.path_events().map(move |evt| (conn_id, evt))));
        self.state.addr_events.push(Box::pin(
            conn.nat_traversal_updates().map(move |evt| (conn_id, evt)),
        ));
        self.state.connections_close.push(OnClosed::new(&conn));

        // Add local addrs to the connection
        let local_addrs = self.state.local_candidates();
        update_qnt_candidates(&conn, &local_addrs);

        // Store the connection
        let conn_state = self
            .connections
            .entry(conn_id)
            .insert_entry(ConnectionState {
                handle: conn.weak_handle(),
                path_state: path_state_sender,
                paths: Default::default(),
                has_been_direct: false,
                custom_tries: 0,
                custom_opening: Vec::new(),
                custom_lost: 0,
                custom_event_try: false,
                custom_not_before: None,
                relay_opening: Default::default(),
                relay_lost: Default::default(),
                relay_lost_total: 0,
            })
            .into_mut();

        // Store PathId(0), set path_status and select best path, check if holepunching
        // is needed.
        if let Some(path) = conn.path(PathId::ZERO) {
            let path_remote = self
                .state
                .register_and_configure_path(conn_id, conn_state, &path);

            // ember: a path through every relay the remote is on, the first one a relay's too: an endpoint home on
            // every relay (`Builder::home_on_every_relay`) is reached through any, and the connection goes on through
            // another as one goes away. Upstream opened them only beside a first path over IP.
            if path_remote.is_some() && conn.side().is_client() {
                // We may have raced this with a relay address.  Try and add any
                // relay addresses we have back.
                let relays = self
                    .state
                    .paths
                    .addrs()
                    .filter(|addr| addr.is_relay() && self.state.relay_usable(addr))
                    .map(|addr| transports::FourTuple::from_remote(addr.clone()))
                    .collect::<Vec<_>>();
                for open_addr in relays {
                    self.state
                        .open_path_on_conn(conn_id, conn_state, &conn, &open_addr);
                }
            }
        }
        self.reset_custom_retry();
        self.open_custom_paths();
        self.trigger_holepunching();
        self.select_path();
        tx.send(path_state_receiver).ok();
    }

    /// ember: the next look at the custom paths missing is set again by `open_custom_paths`.
    fn reset_custom_retry(&mut self) {
        self.state.scheduled_custom_open = None;
    }

    /// ember: opens a path on each client connection to every custom transport address of the remote it has none
    /// to, and tries again while one is missing, at the pace of [`CUSTOM_PATH_RETRY_AFTER`], [`CUSTOM_PATH_TRIES`] times,
    /// losing at most [`CUSTOM_PATH_LOST_MAX`] path ids.
    ///
    /// A connection's first path is whichever transport answered its Initial packets first, and only relay paths are
    /// opened beside it otherwise: a connection whose first path went through a relay or IP never had a custom path, so
    /// the path selector, which picks among open paths, never chose it whatever its RTT. A custom transport that drops
    /// packets for a while (a relay socket of the app's before it is registered) also lost its path for good once it
    /// was abandoned.
    fn open_custom_paths(&mut self) {
        let custom: Vec<transports::Addr> = self
            .state
            .paths
            .addrs()
            .filter(|addr| matches!(addr, transports::Addr::Custom(_)))
            .cloned()
            .collect();
        if custom.is_empty() {
            return;
        }
        let known: BTreeSet<transports::Addr> = custom.iter().cloned().collect();
        if known != self.state.known_custom {
            self.state.known_custom = known;
            self.reset_custom_retry();
            for conn_state in self.connections.values_mut() {
                conn_state.custom_tries = 0;
                conn_state.path_state.record_custom_tries(0);
                conn_state.custom_lost = 0;
                conn_state.path_state.record_custom_lost(0);
                conn_state.custom_not_before = None;
            }
        }
        let now = Instant::now();
        let mut next: Option<Instant> = None;
        for (conn_id, conn_state) in self.connections.iter_mut() {
            // Done trying on this connection until a custom path opens on it or the addresses change: past the timer's
            // tries unless a network change asked for one more, and once the ids it may lose are lost or in flight.
            if conn_state.custom_lost + conn_state.custom_opening.len() as u32 >= CUSTOM_PATH_LOST_MAX
                || (conn_state.custom_tries > CUSTOM_PATH_TRIES && !conn_state.custom_event_try)
            {
                continue;
            }
            let Some(conn) = conn_state.handle.upgrade() else {
                continue;
            };
            if !conn.side().is_client() {
                continue;
            }
            // Not yet: the next try is due later (a network change's is not).
            if !conn_state.custom_event_try
                && let Some(due) = conn_state.custom_not_before
                && now < due
            {
                if custom.iter().any(|addr| !conn_state.paths.values().any(|open| &open.remote() == addr)) {
                    next = Some(next.map_or(due, |n| n.min(due)));
                }
                continue;
            }
            let mut missing = false;
            for addr in &custom {
                if conn_state.paths.values().any(|open| &open.remote() == addr) {
                    continue;
                }
                missing = true;
                let opening = self.state.open_path_on_conn(
                    *conn_id,
                    conn_state,
                    &conn,
                    &transports::FourTuple::from_remote(addr.clone()),
                );
                // A try is a new path id taken: one already being opened (validating still) is no new try.
                if let Some(path_id) = opening
                    && !conn_state.custom_opening.contains(&path_id)
                {
                    conn_state.custom_opening.push(path_id);
                    conn_state.path_state.record_custom_opening(conn_state.custom_opening.len());
                    conn_state.custom_tries += 1;
                    conn_state.path_state.record_custom_tries(conn_state.custom_tries);
                    conn_state.custom_event_try = false;
                    conn_state.custom_not_before = CUSTOM_PATH_RETRY_AFTER
                        .get(conn_state.custom_tries as usize - 1)
                        .map(|wait| now + *wait);
                }
            }
            if missing && conn_state.custom_tries <= CUSTOM_PATH_TRIES {
                let due = conn_state.custom_not_before.filter(|due| *due > now).unwrap_or(now + CUSTOM_PATH_RECHECK);
                next = Some(next.map_or(due, |n| n.min(due)));
            }
        }
        if let Some(next) = next
            && self.state.scheduled_custom_open.is_none_or(|scheduled| next < scheduled)
        {
            self.state.scheduled_custom_open = Some(next);
        }
    }

    /// Handles [`RemoteStateMessage::NetworkChange`].
    fn handle_msg_network_change(&mut self, is_major: bool) {
        // Ping all the paths so loss-detection starts ASAP.
        for conn in self.connections.values() {
            if let Some(noq_conn) = conn.handle.upgrade() {
                for (path_id, addr) in &conn.paths {
                    if let Some(path) = noq_conn.path(*path_id) {
                        // Ping the current path
                        if let Err(err) = path.ping() {
                            warn!(%err, %path_id, ?addr, "failed to ping path");
                        }
                    }
                }
            }
        }

        if is_major {
            // ember: on another network a custom transport or relay that never answered may now (Salix or a relay
            // reached again): one more try on each connection, within the ids it may lose (`CUSTOM_PATH_LOST_MAX`,
            // `RELAY_CONN_LOST_MAX`); the timer's tries and waits stay as they were.
            for conn_state in self.connections.values_mut() {
                conn_state.custom_event_try = true;
                if conn_state.relay_lost_total < RELAY_CONN_LOST_MAX {
                    conn_state.relay_lost.clear();
                }
            }
            self.open_custom_paths();
            if self.state.several_relays {
                self.reopen_relay_paths();
            }
            self.trigger_holepunching();
        }
    }

    fn handle_connection_close(&mut self, conn_id: ConnId, closed: Closed) {
        event!(
            target: "iroh::_events::conn::closed",
            Level::DEBUG,
            %conn_id,
            remote_id = %self.state.endpoint_id.fmt_short(),
            reason=?closed.reason,
        );

        if let Some(conn_state) = self.connections.remove(&conn_id) {
            self.state.metrics.num_conns_closed.inc();
            conn_state.path_state.close(closed);
        }
        if self.connections.is_empty() {
            trace!("last connection closed - clearing selected_path");
            self.state.selected_path = None;
        }
    }

    /// Updates the local [`DirectAddr`]s to all connections.
    ///
    /// Each connection needs to have the local direct addresses to use as QNT address
    /// candidates.
    fn update_local_direct_address(&mut self) {
        let local_addrs = self.state.local_candidates();
        for conn in self.connections.values().filter_map(|s| s.handle.upgrade()) {
            update_qnt_candidates(&conn, &local_addrs);
        }
        // todo: trace
    }

    /// Triggers holepunching to the remote endpoint.
    ///
    /// This will manage the entire process of holepunching with the remote endpoint.
    ///
    /// - Holepunching happens on the Connection with the lowest [`ConnId`] which is a
    ///   client.
    ///   - Both endpoints may initiate holepunching if both have a client connection.
    ///   - Any opened paths are opened on all other connections without holepunching.
    /// - If there are no changes in local or remote candidate addresses since the
    ///   last attempt **and** there was a recent attempt, a trigger_holepunching call
    ///   will be scheduled instead.
    fn trigger_holepunching(&mut self) {
        if self.connections.is_empty() {
            trace!("not holepunching: no connections");
            return;
        }

        let Some(conn) = self
            .connections
            .iter()
            .filter_map(|(id, state)| state.handle.upgrade().map(|conn| (*id, conn)))
            .filter(|(_, conn)| conn.side().is_client())
            .min_by_key(|(id, _)| *id)
            .map(|(_, conn)| conn)
        else {
            trace!("not holepunching: no client connection");
            return;
        };
        let remote_candidates = match conn.get_remote_nat_traversal_addresses() {
            Ok(addrs) => BTreeSet::from_iter(addrs),
            Err(err) => {
                warn!("failed to get nat candidate addresses: {err:#}");
                return;
            }
        };
        let local_candidates = self.state.local_candidates();
        let new_candidates = self
            .state
            .last_holepunch
            .as_ref()
            .map(|last_hp| {
                // Addrs are allowed to disappear, but if there are new ones we need to
                // holepunch again.
                trace!(
                    ?last_hp,
                    ?local_candidates,
                    ?remote_candidates,
                    "candidates to holepunch?"
                );
                !remote_candidates.is_subset(&last_hp.remote_candidates)
                    || !local_candidates.is_subset(&last_hp.local_candidates)
            })
            .unwrap_or(true);
        if !new_candidates && let Some(ref last_hp) = self.state.last_holepunch {
            let next_hp = last_hp.when + HOLEPUNCH_ATTEMPTS_INTERVAL;
            let now = Instant::now();
            if next_hp > now {
                trace!(scheduled_in = ?(next_hp - now), "not holepunching: no new addresses");
                self.state.scheduled_holepunch = Some(next_hp);
                return;
            }
        }

        self.state.do_holepunching(conn);
    }

    #[instrument(skip(self))]
    fn handle_path_event(&mut self, conn_id: ConnId, event: Result<NoqPathEvent, noq::Lagged>) {
        let Ok(event) = event else {
            warn!("missed a PathEvent, RemoteStateActor lagging");
            // TODO: Is it possible to recover using the sync APIs to figure out what the
            //    state of the connection and it's paths are?
            return;
        };
        let Some(conn_state) = self.connections.get_mut(&conn_id) else {
            trace!("event for removed connection");
            return;
        };
        let Some(conn) = conn_state.handle.upgrade() else {
            trace!("event for closed connection");
            return;
        };
        trace!("path event");
        match event {
            NoqPathEvent::Established { id: path_id, .. } => {
                let Some(path) = conn.path(path_id) else {
                    trace!("path open event for unknown path");
                    return;
                };
                // ember: a path through a relay disabled for the remote (one the remote opened, or
                // one that was being opened as the policy changed): closed, never taken.
                if let Some(tuple) = self.state.transport_tuple_for_path(&path)
                    && !self.state.relay_usable(&tuple.remote())
                {
                    conn_state.relay_opening.remove(&path_id);
                    debug!(%conn_id, %path_id, "closing a path established through a disabled or removed relay");
                    if !close_policy_path(&path) {
                        // (the connection's only path: taken, and closed once another opens)
                        self.state.register_and_configure_path(conn_id, conn_state, &path);
                    }
                    return;
                }

                let opened = self
                    .state
                    .register_and_configure_path(conn_id, conn_state, &path);
                // ember: a custom path that opens: a later one missing is tried for soon again.
                conn_state.custom_opening.retain(|id| *id != path_id);
                conn_state.path_state.record_custom_opening(conn_state.custom_opening.len());
                conn_state.relay_opening.remove(&path_id);
                // ember: a path through a relay left out that could not be closed while it was the last one, closed now.
                self.state.close_forbidden_paths(conn_id, conn_state, &conn);
                if let Some(ref open) = opened {
                    if matches!(open.remote(), transports::Addr::Custom(_)) {
                        conn_state.custom_not_before = None;
                        conn_state.custom_tries = 0;
                        conn_state.path_state.record_custom_tries(0);
                        conn_state.custom_lost = 0;
                        conn_state.path_state.record_custom_lost(0);
                    } else if open.is_relay() {
                        conn_state.relay_lost.remove(&open.remote());
                    }
                }
                self.select_path();
            }
            NoqPathEvent::Abandoned { id, reason, .. } => {
                // ember: a custom path given up before it opened: its id is lost for good (`CUSTOM_PATH_LOST_MAX`).
                if conn_state.custom_opening.contains(&id) {
                    conn_state.custom_lost += 1;
                    conn_state.path_state.record_custom_lost(conn_state.custom_lost);
                }
                conn_state.custom_opening.retain(|opening| *opening != id);
                conn_state.path_state.record_custom_opening(conn_state.custom_opening.len());
                // ember: a relay path given up before it opened: its id is lost for good (`RELAY_PATH_LOST_MAX`,
                // `RELAY_CONN_LOST_MAX`).
                if let Some(relay_addr) = conn_state.relay_opening.remove(&id) {
                    let lost = conn_state.relay_lost.entry(relay_addr).or_default();
                    *lost += 1;
                    conn_state.relay_lost_total += 1;
                    if self.state.several_relays
                        && *lost < RELAY_PATH_LOST_MAX
                        && conn_state.relay_lost_total < RELAY_CONN_LOST_MAX
                    {
                        self.state.relay_reopen_at = Some(Instant::now() + RELAY_REOPEN);
                    }
                }
                // Remove abandoned path from the conn state.
                let Some(network_path) = conn_state.remove_path(&id, &conn) else {
                    debug!(%id, "path not in path_id_map");
                    return;
                };

                // We track all known remote addresses for the peer in `State::paths`. The paths are tracked
                // by remote address only (we ignore the local IP). Therefore, we mark a remote addr as abandoned
                // in the remote-global state only once no connections have any path to that remote addr.
                if !conn_state
                    .paths
                    .values()
                    .any(|tuple| tuple.remote() == network_path.remote())
                {
                    self.state.paths.abandoned_path(&network_path.remote());
                }

                event!(
                    target: "iroh::_events::path::abandoned",
                    Level::DEBUG,
                    remote = %self.state.endpoint_id.fmt_short(),
                    %conn_id,
                    path_id = %id,
                    %network_path,
                    ?reason
                );

                let no_ip_left = conn.side().is_client()
                    && !conn_state
                        .paths
                        .iter()
                        .any(|(pid, a)| a.is_ip() && conn.path(*pid).is_some());

                // If the remote closed our selected path, select a new one.
                self.select_path();
                // ember: a relay's path, tried again a moment later (`reopen_relay_paths`).
                if network_path.is_relay()
                    && self.state.several_relays
                    && self.state.relay_usable(&network_path.remote())
                {
                    self.state.relay_reopen_at = Some(Instant::now() + RELAY_REOPEN);
                }
                // ember: a custom path that worked and was given up is opened again at once (`open_custom_paths`). One
                // that never opened is not in the connection's paths (it returned above): the retry timer reopens it.
                if matches!(network_path.remote(), transports::Addr::Custom(_)) {
                    self.open_custom_paths();
                }
                // ember: the connection's last direct path was given up: holepunch again so it does not wait out
                // `UPGRADE_INTERVAL` (60 s) on a relay.
                if network_path.is_ip() && no_ip_left {
                    self.trigger_holepunching();
                }
            }
            NoqPathEvent::Discarded { id, path_stats, .. } => {
                trace!(%id, ?path_stats, "path discarded");
            }
            NoqPathEvent::RemoteStatus { .. } | NoqPathEvent::ObservedAddr { .. } => {
                // Nothing to do for these events.
            }
            _ => {
                // We expect to keep noq and iroh in sync in all test setups, but in production it's totally possible
                // that iroh itself is linked against a newer version of noq with additional events we don't yet
                // know how to handle.
                #[cfg(test)]
                panic!("Unhandled path event: {event:?}");
            }
        }
    }

    /// Selects the preferred path by invoking the configured [`PathSelector`].
    ///
    /// The selected path is added to any connections which do not yet have it.  Any unused
    /// direct paths are closed for all connections.
    #[instrument(skip_all)]
    fn select_path(&mut self) {
        let current_path = self.state.selected_path.as_ref();
        let selection = {
            let ctx = PathSelectionContext::new(current_path, &self.connections);
            self.state.path_selector.select(&ctx)
        };
        // ember: never a path through a relay disabled for the remote (one closed, its abandon not
        // polled yet).
        let selected_addr = selection.selected().cloned()
            .filter(|addr| self.state.relay_usable(&addr.remote()));

        if let Some(addr) = selected_addr
            && self.state.selected_path.as_ref() != Some(&addr)
        {
            let prev_remote = self.state.selected_path.replace(addr.clone());
            // ember: a path works; what was kept for addresses found later is not needed.
            self.state.unanswered = None;
            event!(
                target: "iroh::_events::path::selected",
                Level::DEBUG,
                remote = %self.state.endpoint_id.fmt_short(),
                network_path = %addr,
                prev_network_path = %prev_remote.map(|p| format!("{p}")).unwrap_or("None".to_string()),
            );
        } else {
            trace!(?current_path, "keeping current path");
        }

        self.apply_selected_path();
        self.close_withdrawn_paths(&selection);
        self.ping_paths(&selection);
    }

    /// ember: sends one single-path QUIC `PING` for each open path that [`PathSelection::ping`]
    /// named in this selection pass, carrying no policy here. Closed connections, closed paths,
    /// generation mismatches, and disabled relays are ignored without error.
    fn ping_paths(&self, selection: &PathSelection) {
        for target in &selection.ping {
            match target {
                PingTarget::Live {
                    conn: target_conn,
                    path_id,
                    generation,
                    network_path,
                } => {
                    if !self.state.relay_usable(&network_path.remote()) {
                        continue;
                    }
                    for state in self.connections.values() {
                        let Some(conn) = state.handle.upgrade() else {
                            continue;
                        };
                        if !conn.weak_handle().is_same_connection(target_conn) {
                            continue;
                        }
                        if state.paths.get(path_id) != Some(network_path) {
                            break;
                        }
                        if let Some(expected_gen) = generation
                            && conn
                                .path_stats(*path_id)
                                .is_none_or(|stats| stats.path_generation != *expected_gen)
                        {
                            break;
                        }
                        if let Some(path) = conn.path(*path_id)
                            && let Err(error) = path.ping()
                        {
                            trace!(?error, ?network_path, %path_id, "could not ping path");
                        }
                        break;
                    }
                }
                #[cfg(test)]
                PingTarget::Test(network_path) => {
                    if !self.state.relay_usable(&network_path.remote()) {
                        continue;
                    }
                    for state in self.connections.values() {
                        let Some(conn) = state.handle.upgrade() else {
                            continue;
                        };
                        for (path_id, addr) in &state.paths {
                            if addr == network_path
                                && let Some(path) = conn.path(*path_id)
                                && let Err(error) = path.ping()
                            {
                                trace!(?error, ?network_path, %path_id, "could not ping path");
                            }
                        }
                    }
                }
            }
        }
    }

    /// Retire withdrawn custom paths only after this connection has a validated replacement.
    fn close_withdrawn_paths(&mut self, selection: &PathSelection) {
        let Some(selected) = self.state.selected_path.as_ref() else {
            return;
        };
        // Discovery is shared by remote address. Wait until every connection still
        // using an address has its own validated replacement, then close together.
        // Partial retirement would keep the address discoverable and reopen it on
        // already-retired connections. Usually there is only one connection.
        // Abandoned events remove state.paths before reselection. If noq retires
        // a replacement concurrently, before its event is consumed here, close's
        // LastOpenPath guard still prevents abandoning the last usable path.
        let requested: BTreeSet<_> = selection.close.iter().map(|path| path.remote()).collect();
        let ready: BTreeSet<_> = requested.into_iter().filter(|remote| {
            self.connections.values().all(|state| {
                let Some(conn) = state.handle.upgrade() else { return true };
                let uses_remote = state.paths.iter().any(|(id, path)| {
                    &path.remote() == remote && conn.path(*id).is_some()
                });
                !uses_remote || state.paths.iter().any(|(id, path)| {
                    path == selected && &path.remote() != remote && conn.path(*id).is_some()
                        && conn.path_stats(*id).is_some_and(|stats| stats.same_path_rtt.is_some())
                })
            })
        }).collect();
        let mut retired = BTreeSet::new();
        let mut failed = BTreeSet::new();
        for state in self.connections.values() {
            let Some(conn) = state.handle.upgrade() else { continue };
            for (id, addr) in &state.paths {
                if !ready.contains(&addr.remote()) { continue; }
                if !selection.close.contains(addr) {
                    failed.insert(addr.remote());
                    continue;
                }
                if let Some(path) = conn.path(*id) {
                    // noq still enforces its last-open-path guard. Its path() lookup
                    // remains Some during draining, so use close's result, not a
                    // second path() lookup, to decide whether retirement succeeded.
                    match path.close() {
                        Ok(()) | Err(noq_proto::ClosePathError::ClosedPath) => {
                            retired.insert(addr.remote());
                        }
                        Err(error) => {
                            failed.insert(addr.remote());
                            trace!(?error, ?addr, "could not close withdrawn custom path");
                        }
                    }
                }
            }
        }
        retired.retain(|addr| !failed.contains(addr));
        self.state.paths.retain(|addr| !retired.contains(addr));
    }

    /// Propagates a change of [`State::selected_path`] to noq.
    ///
    /// Iterates over all connections and applies the selected path as follows:
    /// - Closes non-selected IP paths (but keeps one IP path open still)
    /// - Sets all non-selected paths to [`PathStatus::Backup`]
    /// - Opens the selected path if it does not exist on the connection
    /// - Sets the selected path to [`PathStatus::Available`]
    fn apply_selected_path(&mut self) {
        let Some(selected) = self.state.selected_path.clone() else {
            // We can't open the selected path on all paths if we don't have one yet.
            // And we can't close all "unselected" paths either, because we don't know which one is selected.
            return;
        };

        for (conn_id, conn_state) in self.connections.iter_mut() {
            let Some(conn) = conn_state.handle.upgrade() else {
                continue;
            };

            // Open path if it doesn't exist yet.
            self.state
                .open_path_on_conn(*conn_id, conn_state, &conn, &selected);

            // ember: which live IP path on this connection to keep open (`conn_state.paths` still holds paths
            // `path.close()` just abandoned until their `NoqPathEvent::Abandoned` is polled, and `selected` may be a
            // relay or custom path, in which case `conn_state.paths.values().filter(|a| a.is_ip()).count() > 1` inside
            // the loop closed every IP path on the connection).
            let keep_ip = conn_state
                .paths
                .iter()
                .filter(|(path_id, addr)| addr.is_ip() && conn.path(**path_id).is_some())
                .min_by_key(|(path_id, addr)| {
                    let is_selected = *addr == &selected;
                    let rtt = conn
                        .path_stats(**path_id)
                        .and_then(|s| s.same_path_rtt.or(Some(s.rtt)))
                        .unwrap_or(Duration::MAX);
                    (!is_selected, rtt, **path_id)
                })
                .map(|(path_id, _)| *path_id);

            for (path_id, path_remote) in conn_state.paths.iter() {
                let Some(path) = conn.path(*path_id) else {
                    continue;
                };

                // Closes redundant IP paths so that at most one remains per connection.
                //
                // Relay and custom paths are kept open. Only the client closes paths,
                // to avoid the client and server independently closing different paths
                // and racing to abandon the last one.
                if conn.side().is_client()
                    && path_remote.is_ip()
                    && Some(*path_id) != keep_ip
                {
                    trace!(?path_remote, %conn_id, %path_id, "closing direct path");
                    match path.close() {
                        Err(noq_proto::ClosePathError::MultipathNotNegotiated) => {
                            error!("multipath not negotiated");
                        }
                        Err(noq_proto::ClosePathError::LastOpenPath) => {
                            error!("could not close last open path");
                        }
                        Err(noq_proto::ClosePathError::ClosedPath) => {
                            // We already closed this.
                        }
                        Ok(()) => {}
                    }
                    continue;
                }

                // Set path status: The selected path becomes Available, all other paths become Backup.
                self.state.set_path_status(*conn_id, &path, path_remote);
            }

            // Record the new selected path in the path watcher.
            conn_state.path_state.record_selected(&selected);
        }
    }

    /// ember: a path through each relay the remote is on, on every connection that has none through it (its relay
    /// gone a while, back now perhaps): tried again after RELAY_REOPEN while one is missing, within the path ids the
    /// connection may lose to relays that do not answer (`RELAY_PATH_LOST_MAX`, `RELAY_CONN_LOST_MAX`).
    fn reopen_relay_paths(&mut self) {
        let relays: Vec<_> = self
            .state
            .paths
            .addrs()
            .filter(|addr| addr.is_relay() && self.state.relay_usable(addr))
            .map(|addr| transports::FourTuple::from_remote(addr.clone()))
            .collect();
        let mut missing = false;
        for (conn_id, conn_state) in self.connections.iter_mut() {
            let Some(conn) = conn_state.handle.upgrade() else {
                continue;
            };
            if !conn.side().is_client() {
                continue;
            }
            for addr in &relays {
                let remote = addr.remote();
                if conn_state.paths.values().any(|p| p == addr) {
                    continue;
                }
                if conn_state.relay_lost.get(&remote).copied().unwrap_or(0) >= RELAY_PATH_LOST_MAX {
                    continue;
                }
                if conn_state.relay_opening.values().any(|a| a == &remote) {
                    missing = true;
                    continue;
                }
                if conn_state.relay_lost_total + conn_state.relay_opening.len() as u32
                    >= RELAY_CONN_LOST_MAX
                {
                    break;
                }
                missing = true;
                self.state.open_path_on_conn(*conn_id, conn_state, &conn, addr);
            }
        }
        if missing {
            self.state.relay_reopen_at = Some(Instant::now() + RELAY_REOPEN);
        }
    }

    fn open_path_on_all_conns(&mut self, open_addr: &transports::FourTuple) {
        for (conn_id, conn_state) in self.connections.iter_mut() {
            let Some(conn) = conn_state.handle.upgrade() else {
                continue;
            };
            self.state
                .open_path_on_conn(*conn_id, conn_state, &conn, open_addr);
        }
    }

    /// Handles regularly checking if any paths need hole punching currently
    ///
    /// Currently we need to have 1 IP path, with a good enough latency.
    fn check_connections(&mut self) {
        let mut is_goodenough = true;
        for conn_state in self.connections.values() {
            let mut is_conn_goodenough = false;
            if let Some(conn) = conn_state.handle.upgrade() {
                let min_ip_rtt = conn_state
                    .paths
                    .iter()
                    .filter_map(|(path_id, addr)| {
                        if addr.is_ip() {
                            conn.path_stats(*path_id).and_then(|stats| stats.same_path_rtt)
                        } else {
                            None
                        }
                    })
                    .min();

                if let Some(min_ip_rtt) = min_ip_rtt {
                    let is_latency_goodenough = min_ip_rtt <= GOOD_ENOUGH_LATENCY;
                    is_conn_goodenough = is_latency_goodenough;
                } else {
                    // No IP transport found
                    is_conn_goodenough = false;
                }
            }
            is_goodenough &= is_conn_goodenough;
        }

        if !is_goodenough {
            debug!("connections are not good enough, triggering holepunching");
            self.trigger_holepunching();
        }
    }
}

impl State {
    /// ember: whether `addr` is usable right now (allowed by endpoint allowlist & remote disabled set, and not locally removed).
    fn relay_usable(&self, addr: &transports::Addr) -> bool {
        relay_usable(&self.relay_policies, &self.endpoint_id, addr)
    }

    /// Handles [`RemoteStateMessage::SendDatagram`].
    fn handle_msg_send_datagram(
        &mut self,
        sender: Box<TransportsSender>,
        transmit: OwnedTransmit,
        send_tasks: &mut DatagramSends,
    ) {
        // Sending datagrams might fail, e.g. because we don't have the right transports set
        // up to handle sending this owned transmit to.
        // After all, we try every single path that we know (relay URL, IP address), even
        // though we might not have a relay transport or ip-capable transport set up.
        // So these errors must not be fatal for this actor (or even this operation).

        // Initial packets belong to a new connection, while selected_path belongs to the peer: race them on every
        // known path even while a path is selected. An older connection's selection may have become slow before its
        // next RTT sample or path reselection, or dead: a peer whose process restarted on another port is reached
        // through the relay at once, but its old direct path stays selected until the old connection times out (28 s
        // measured). Established packets use their concrete path in TransportsSender and do not come here.
        trace!(
            paths = ?self.paths.addrs().collect::<Vec<_>>(),
            "sending datagram to all known paths",
        );
        // ember: kept for addresses found later (see `unanswered`).
        if self.selected_path.is_none() {
            match &mut self.unanswered {
                Some((kept_sender, kept)) => {
                    *kept_sender = sender.clone();
                    if kept.len() == UNANSWERED_KEPT {
                        kept.remove(0);
                    }
                    kept.push(transmit.clone());
                }
                None => self.unanswered = Some((sender.clone(), vec![transmit.clone()])),
            }
        }
        if self.paths.is_empty() {
            warn!("Cannot send datagrams: No paths to remote endpoint known");
        }

        let mut targets = Vec::new();
        for addr in self.paths.addrs() {
            // We never want to send to our local addresses.
            // The local address set is updated in the main loop so we can use `peek` here.
            if let transports::Addr::Ip(sockaddr) = addr
                && self
                    .local_direct_addrs
                    .peek()
                    .iter()
                    .any(|a| a.addr == *sockaddr)
            {
                trace!(%sockaddr, "not sending datagram to our own address");
            } else if !self.relay_usable(addr) {
                // ember: not through a relay disabled for the remote or locally removed (the sender drops it anyway).
                trace!(?addr, "not sending datagram through a relay not usable");

            // TODO(Frando): We might want to include a local IP here in the future, if we confidently
            // know that it is the correct one.
            // See https://github.com/n0-computer/iroh/issues/4280.
            } else {
                targets.push(transports::FourTuple::from_remote(addr.clone()));
            }
        }
        // This message is received *before* a connection is added.  So we do
        // not yet have a connection to holepunch.  Instead we trigger
        // holepunching when AddConnection is received.
        queue_datagram(send_tasks, sender, transmit, targets);
    }

    /// Handles [`RemoteStateMessage::ResolveRemote`].
    fn handle_msg_resolve_remote(
        &mut self,
        addrs: BTreeSet<TransportAddr>,
        tx: oneshot::Sender<Result<(), AddressLookupFailed>>,
    ) {
        // ember: `insert_multiple` ignores relays outside `allowlist` and shelves relays disabled for the remote.
        let addrs: Vec<_> = to_transports_addr(self.endpoint_id, addrs).collect();
        self.paths.insert_multiple(addrs.into_iter(), Source::App);
        self.paths.resolve_remote(tx);
        // Start Address Lookup if we have no selected path.
        self.trigger_address_lookup();
    }

    /// Triggers Address Lookup for the remote endpoint, if needed.
    ///
    /// Does not start Address Lookup if we have a selected path or if Address Lookup is
    /// currently running.
    fn trigger_address_lookup(&mut self) {
        if self.selected_path.is_some() || self.address_lookup_stream.is_some() {
            return;
        }
        let stream = self.address_lookup.resolve(self.endpoint_id);
        let stream = stream.filter_map(|item| match item {
            // We don't care about errors from individual services, we just continue.
            // Individual errors are buffered into the final error by `AddressLookupServices::resolve`,
            // and if the lookup fails we return them upstream with the final `AddressLookupFailed` error.
            Ok(Err(_err)) => None,
            Ok(Ok(item)) => Some(Ok(item)),
            Err(err) => Some(Err(err)),
        });
        self.address_lookup_stream = Some(Box::pin(stream));
    }

    /// Handles an address lookup result.
    ///
    /// All address lookup results end up being sent here. It takes care of updating the
    /// [`RemotePathState`] with the results.
    fn handle_address_lookup_item(
        &mut self,
        item: Option<Result<AddressLookupItem, AddressLookupFailed>>,
        send_tasks: &mut DatagramSends,
    ) {
        match item {
            None => {
                self.paths.address_lookup_finished(Ok(()));
                self.address_lookup_stream = None;
            }
            Some(Err(err)) => {
                if let AddressLookupFailed::NoServiceConfigured { .. } = err {
                    trace!("Address Lookup not configured");
                } else {
                    debug!("Address Lookup failed: {err:#}");
                }
                self.paths.address_lookup_finished(Err(err));
                self.address_lookup_stream = None;
            }
            Some(Ok(item)) => {
                if item.endpoint_id() != self.endpoint_id {
                    warn!(
                        ?item,
                        "Address Lookup emitted item for wrong remote endpoint"
                    );
                } else {
                    let source = Source::AddressLookup {
                        name: item.provenance().to_string(),
                    };
                    // ember: `insert_multiple` ignores relays outside `allowlist` and shelves relays disabled for the remote.
                    let addrs: Vec<_> =
                        to_transports_addr(self.endpoint_id, item.into_endpoint_addr().addrs)
                            .collect();
                    let known: BTreeSet<transports::Addr> = self.paths.addrs().cloned().collect();
                    self.paths.insert_multiple(addrs.iter().cloned(), source);
                    let found: Vec<_> = addrs
                        .into_iter()
                        .filter(|a| matches!(a, transports::Addr::Ip(_)) && !known.contains(a))
                        .collect();
                    self.send_unanswered(&found, send_tasks);
                }
            }
        }
    }

    /// ember: sends the datagrams kept in [`Self::unanswered`] to addresses just found, while no path is selected
    /// (once one is, they are dropped: the connection is under way).
    fn send_unanswered(&mut self, found: &[transports::Addr], send_tasks: &mut DatagramSends) {
        if self.selected_path.is_some() {
            self.unanswered = None;
            return;
        }
        let Some((sender, kept)) = self.unanswered.as_mut() else {
            return;
        };
        let targets: Vec<_> = found
            .iter()
            .cloned()
            .map(transports::FourTuple::from_remote)
            .collect();
        for transmit in kept.iter() {
            queue_datagram(send_tasks, sender.clone(), transmit.clone(), targets.clone());
        }
    }

    /// Unconditionally perform holepunching.
    #[instrument(skip_all)]
    fn do_holepunching(&mut self, conn: noq::Connection) {
        self.metrics.holepunch_attempts.inc();
        let local_candidates = self.local_candidates();
        match conn.initiate_nat_traversal_round() {
            Ok(remote_candidates) => {
                let remote_candidates = remote_candidates
                    .iter()
                    .map(|addr| SocketAddr::new(addr.ip().to_canonical(), addr.port()))
                    .collect();
                event!(
                    target: "iroh::_events::qnt::init",
                    Level::DEBUG,
                    remote = %self.endpoint_id.fmt_short(),
                    ?local_candidates,
                    ?remote_candidates,
                );
                self.last_holepunch = Some(HolepunchAttempt {
                    when: Instant::now(),
                    local_candidates,
                    remote_candidates,
                });
            }
            Err(err) => {
                debug!("failed to initiate NAT traversal: {err:#}");
                use noq_proto::n0_nat_traversal::Error;
                match err {
                    Error::Closed
                    | Error::TooManyAddresses
                    | Error::WrongConnectionSide
                    | Error::ExtensionNotNegotiated => {
                        // Fatal, no need to retry for now
                    }
                    Error::Multipath(_) | Error::NotEnoughAddresses => {
                        // Retry in a bit
                        let now = Instant::now();
                        let next_hp = now + Duration::from_millis(100);
                        trace!(scheduled_in = ?(next_hp - now), "holepunching retry");
                        self.scheduled_holepunch = Some(next_hp);
                    }
                }
            }
        }
    }

    /// Register a path with our state and configure path-specific settings.
    ///
    /// This inserts the path in the [`ConnectionState`] and [`Self::paths`].
    ///
    /// It configures the path with the correct path status (see [`Self::set_path_status`]),
    /// and applies path-type-specific settings:
    /// Relay paths get a longer idle timeout to accommodate transparent reconnection
    /// by the relay actor (see [`RELAY_PATH_MAX_IDLE_TIMEOUT`]).
    fn register_and_configure_path(
        &mut self,
        conn_id: ConnId,
        conn_state: &mut ConnectionState,
        path: &noq::Path,
    ) -> Option<transports::FourTuple> {
        let network_path = self.transport_tuple_for_path(path)?;
        event!(
            target: "iroh::_events::path::open",
            Level::DEBUG,
            remote = %self.endpoint_id.fmt_short(),
            %conn_id,
            path_id=%path.id(),
            %network_path,
        );
        conn_state.add_open_path(network_path.clone(), path.id(), &self.metrics);
        // ember: not on several relays: a relay path is given up as any other then (the connection's
        // `default_path_max_idle_timeout`), its packets going on through another relay meanwhile, and opened again
        // once its relay is back (`reopen_relay_paths`). Waiting out a relay's reconnection held the connection on a
        // relay that was gone for 30 s.
        if network_path.is_relay()
            && !self.several_relays
            && let Err(e) = path.set_max_idle_timeout(Some(RELAY_PATH_MAX_IDLE_TIMEOUT))
        {
            debug!(?e, "failed to set relay path idle timeout");
        }

        self.set_path_status(conn_id, path, &network_path);
        self.paths
            .insert_open_path(network_path.remote(), Source::Connection);
        Some(network_path)
    }

    fn set_path_status(
        &mut self,
        conn_id: ConnId,
        path: &noq::Path,
        network_path: &transports::FourTuple,
    ) {
        let status = self.path_status_for_addr(network_path);
        match path.set_status(status) {
            Err(error) => warn!(?error, ?network_path, ?status, "set_status failed"),
            Ok(prev_status) if prev_status != status => {
                event!(
                    target: "iroh::_events::path::set_status",
                    Level::DEBUG,
                    remote = %self.endpoint_id.fmt_short(),
                    %conn_id,
                    path_id=%path.id(),
                    %network_path,
                    ?status,
                    ?prev_status,
                );
            }
            Ok(_) => {}
        }
    }

    fn open_path_on_conn(
        &mut self,
        conn_id: ConnId,
        conn_state: &mut ConnectionState,
        conn: &noq::Connection,
        open_addr: &transports::FourTuple,
    ) -> Option<PathId> {
        // Only the client opens paths; the server receives them via
        // QUIC frames and reacts to PathOpened events.
        if conn.side().is_server() {
            return None;
        }
        // Already open on this connection; nothing to do.
        if conn_state.paths.values().any(|a| a == open_addr) {
            return None;
        }
        // ember: never through a relay disabled for the remote or locally removed.
        if !self.relay_usable(&open_addr.remote()) {
            return None;
        }
        if open_addr.is_relay()
            && (conn_state
                .relay_lost
                .get(&open_addr.remote())
                .copied()
                .unwrap_or(0)
                >= RELAY_PATH_LOST_MAX
                || conn_state.relay_lost_total + conn_state.relay_opening.len() as u32
                    >= RELAY_CONN_LOST_MAX)
        {
            return None;
        }

        let quic_addr =
            open_addr.to_noq_four_tuple(&self.relay_mapped_addrs, &self.custom_mapped_addrs);
        let path_status = self.path_status_for_addr(open_addr);

        let fut = conn.open_path_ensure(quic_addr, path_status);
        match fut.path_id() {
            Some(path_id) => {
                trace!(%conn_id, %path_id, ?path_status, "opening new path");
                if open_addr.is_relay() {
                    conn_state.relay_opening.insert(path_id, open_addr.remote());
                }
                return Some(path_id);
            }
            None => {
                let ret = now_or_never(fut);
                match ret {
                    Some(Err(PathError::RemoteCidsExhausted))
                    | Some(Err(PathError::MaxPathIdReached)) => {
                        // ember: once. A retry tries the address on every connection to the remote, and each one still
                        // out of path ids queued it again: with two or more connections at the limit the queue grew
                        // that many times over every 333 ms, to gigabytes (24 GB in one allocation upstream), the
                        // actor's task busy draining and refilling it.
                        // ember: a custom address is not queued at all: its own timer tries it again
                        // (`open_custom_paths`), and queued it would be retried every 333 ms for as long as the
                        // connection has no path id to spare.
                        if !matches!(open_addr, transports::FourTuple::Custom { .. }) {
                            self.scheduled_open_path =
                                Some(Instant::now() + Duration::from_millis(333));
                            if !self.pending_open_paths.contains(open_addr) {
                                self.pending_open_paths.push_back(open_addr.clone());
                            }
                        }
                        trace!(?open_addr, ?ret, "scheduling open_path");
                    }
                    _ => warn!(?ret, "Opening path failed"),
                }
            }
        }
        None
    }

    /// Returns the [`PathStatus`] for `addr`.
    ///
    /// Returns [`PathStatus::Available`] if `addr` is the currently-selected path,
    /// or [`PathStatus::Backup`] otherwise.
    fn path_status_for_addr(&self, addr: &transports::FourTuple) -> PathStatus {
        if Some(addr) == self.selected_path.as_ref() {
            PathStatus::Available
        } else {
            PathStatus::Backup
        }
    }

    /// Returns the [`transports::FourTuple] for a path.
    fn transport_tuple_for_path(&self, path: &noq::Path) -> Option<transports::FourTuple> {
        let noq_network_path = path.network_path().ok()?;
        transports::FourTuple::from_noq(
            noq_network_path,
            &self.relay_mapped_addrs,
            &self.custom_mapped_addrs,
        )
    }

    /// Returns the current set of local direct addresses.
    fn local_candidates(&mut self) -> BTreeSet<SocketAddr> {
        self.local_direct_addrs
            .get()
            .iter()
            .map(|d| d.addr)
            .collect()
    }

    /// ember: every path of a connection through a relay disabled for the remote or locally removed, and every one
    /// being opened through one, closed and taken out of the connection's state at once (its `Abandoned` event finds it
    /// gone). One that cannot be closed yet (the connection's last) is kept, to be closed once another is established.
    fn close_forbidden_paths(
        &mut self,
        conn_id: ConnId,
        conn_state: &mut ConnectionState,
        conn: &noq::Connection,
    ) {
        let opening: Vec<PathId> = conn_state
            .relay_opening
            .iter()
            .filter(|(_, addr)| !relay_usable(&self.relay_policies, &self.endpoint_id, addr))
            .map(|(id, _)| *id)
            .collect();
        for path_id in opening {
            // ember: an unestablished path closed before `Established` permanently consumes its QUIC `PathId` when the
            // peer never saw it (`noq-proto` replenishes `MAX_PATHS` only on `PATH_ABANDON` of a path the peer has), so
            // canceling it here settles one unit of `relay_lost` and `relay_lost_total` (`Abandoned` later sees `None`).
            let closed = match conn.path(path_id) {
                Some(path) => close_policy_path(&path),
                None => true,
            };
            if closed && let Some(relay_addr) = conn_state.relay_opening.remove(&path_id) {
                *conn_state.relay_lost.entry(relay_addr).or_default() += 1;
                conn_state.relay_lost_total += 1;
            }
        }
        let open: Vec<PathId> = conn_state
            .paths
            .iter()
            .filter(|(_, tuple)| {
                !relay_usable(&self.relay_policies, &self.endpoint_id, &tuple.remote())
            })
            .map(|(id, _)| *id)
            .collect();
        for path_id in open {
            let Some(path) = conn.path(path_id) else {
                if let Some(removed) = conn_state.remove_path(&path_id, conn)
                    && !conn_state
                        .paths
                        .values()
                        .any(|tuple| tuple.remote() == removed.remote())
                {
                    self.paths.abandoned_path(&removed.remote());
                }
                continue;
            };
            debug!(%conn_id, %path_id, "closing a path through a disabled or removed relay");
            if close_policy_path(&path)
                && let Some(removed) = conn_state.remove_path(&path_id, conn)
                && !conn_state
                    .paths
                    .values()
                    .any(|tuple| tuple.remote() == removed.remote())
            {
                self.paths.abandoned_path(&removed.remote());
            }
        }
    }
}

/// ember: whether `addr` of `remote` is allowed by policy (allowlist and per-remote disabled set).
fn relay_allowed(policies: &RelayPolicies, remote: &EndpointId, addr: &transports::Addr) -> bool {
    match addr {
        transports::Addr::Relay(url, _) => policies.allows(remote, url),
        _ => true,
    }
}

/// ember: whether `addr` of `remote` is both allowed by policy and not locally removed.
fn relay_usable(policies: &RelayPolicies, remote: &EndpointId, addr: &transports::Addr) -> bool {
    match addr {
        transports::Addr::Relay(url, _) => policies.usable(remote, url),
        _ => true,
    }
}

/// ember: a path through a relay disabled for the remote, closed; whether it was (a connection's last path
/// is not: QUIC keeps one).
fn close_policy_path(path: &noq::Path) -> bool {
    match path.close() {
        Err(noq_proto::ClosePathError::LastOpenPath) => {
            debug!("the connection's last path goes through a relay disabled for it: kept until another opens, its sends dropped");
            false
        }
        Err(noq_proto::ClosePathError::MultipathNotNegotiated) => {
            error!("multipath not negotiated");
            false
        }
        Err(noq_proto::ClosePathError::ClosedPath) | Ok(()) => true,
    }
}

fn update_qnt_candidates(conn: &noq::Connection, direct_addrs: &BTreeSet<SocketAddr>) {
    let noq_candidates = match conn.get_local_nat_traversal_addresses() {
        Ok(addrs) => BTreeSet::from_iter(addrs),
        Err(err) => {
            warn!("failed to get local nat candidates: {err:#}");
            return;
        }
    };
    for addr in direct_addrs.difference(&noq_candidates) {
        if let Err(err) = conn.add_nat_traversal_address(*addr) {
            warn!("failed adding local addr: {err:#}",);
        }
    }
    for addr in noq_candidates.difference(direct_addrs) {
        if let Err(err) = conn.remove_nat_traversal_address(*addr) {
            warn!("failed removing local addr: {err:#}");
        }
    }
    trace!(?direct_addrs, "updated local QNT addresses");
}

fn send_datagram<'a>(
    sender: &'a mut TransportsSender,
    addr: transports::FourTuple,
    owned_transmit: OwnedTransmit,
) -> impl Future<Output = n0_error::Result<()>> + 'a {
    std::future::poll_fn(move |cx| {
        let transmit = transports::Transmit {
            ecn: owned_transmit.ecn,
            contents: owned_transmit.contents.as_ref(),
            segment_size: owned_transmit.segment_size,
        };

        Pin::new(&mut *sender)
            .poll_send(cx, &addr, &transmit)
            .map(|res| res.with_context(|_| format!("failed to send datagram to {:?}", addr)))
    })
}

// All Initial send paths, including replay to late-discovered addresses, use the same
// actor-owned bounded work so no transport can block peer state or shutdown.
fn queue_datagram(
    send_tasks: &mut DatagramSends,
    sender: Box<TransportsSender>,
    transmit: OwnedTransmit,
    targets: Vec<transports::FourTuple>,
) {
    if targets.is_empty() {
        return;
    }
    let send = Box::pin(
        async move {
            if time::timeout(
                DATAGRAM_SEND_TIMEOUT,
                send_datagram_to_targets(sender, transmit, targets),
            )
            .await
            .is_err()
            {
                debug!("Datagram send timed out");
            }
        }
        .instrument(Span::current()),
    );
    if send_tasks.try_push(send).is_err() {
        debug!("dropping datagram: send task limit reached");
    }
}

async fn send_datagram_to_targets(
    sender: Box<TransportsSender>,
    transmit: OwnedTransmit,
    targets: Vec<transports::FourTuple>,
) {
    let mut sends = targets
        .into_iter()
        .map(|target| {
            let mut sender = sender.clone();
            let transmit = transmit.clone();
            async move {
                if let Err(err) = send_datagram(&mut sender, target.clone(), transmit).await {
                    debug!(?target, "failed to send datagram: {err:#}");
                }
            }
        })
        .collect::<FuturesUnordered<_>>();
    while sends.next().await.is_some() {}
}

#[cfg(all(test, not(wasm_browser)))]
mod initial_send_tests {
    use super::*;

    fn relay_transmit() -> (transports::FourTuple, OwnedTransmit) {
        (
            transports::FourTuple::Relay {
                url: "https://relay.example.invalid".parse().unwrap(),
                endpoint_id: iroh_base::SecretKey::from_bytes(&[1; 32]).public(),
            },
            OwnedTransmit {
                ecn: None,
                contents: bytes::Bytes::from_static(b"initial"),
                segment_size: None,
            },
        )
    }

    #[tokio::test(start_paused = true)]
    async fn expired_initial_is_not_sent_when_queue_reopens() {
        let (mut sender, mut receiver) = TransportsSender::with_bounded_relay_for_test(1);
        let (relay, transmit) = relay_transmit();
        send_datagram(&mut sender, relay.clone(), transmit.clone()).await.unwrap();
        let mut tasks = DatagramSends::new(MAX_DATAGRAM_SEND_TASKS);
        queue_datagram(&mut tasks, Box::new(sender), transmit, vec![relay]);
        assert!(now_or_never(tasks.next()).is_none());
        tokio::time::advance(Duration::from_secs(4)).await;
        assert!(tasks.next().await.is_some());
        assert!(tasks.is_empty());
        assert!(receiver.next().await.is_some());
        assert!(receiver.next().await.is_none(), "expired Initial was sent late");
    }

    #[tokio::test(start_paused = true)]
    async fn congested_initials_keep_only_bounded_work() {
        let (mut sender, mut receiver) = TransportsSender::with_bounded_relay_for_test(1);
        let (relay, transmit) = relay_transmit();
        send_datagram(&mut sender, relay.clone(), transmit.clone()).await.unwrap();
        let mut tasks = DatagramSends::new(MAX_DATAGRAM_SEND_TASKS);
        for _ in 0..32 {
            queue_datagram(&mut tasks, Box::new(sender.clone()), transmit.clone(), vec![relay.clone()]);
        }
        drop(sender);
        assert_eq!(tasks.len(), 16);
        let (_, count) = tokio::join!(
            async { while tasks.next().await.is_some() {} },
            async { let mut count = 0; while receiver.next().await.is_some() { count += 1; } count },
        );
        assert_eq!(count, 17, "one already queued packet plus sixteen admitted Initials");
    }

    #[tokio::test]
    async fn blocked_relay_does_not_delay_direct_initial() {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (mut sender, _relay_receiver) = TransportsSender::with_bounded_relay_for_test(1);
        sender.bind_loopback_for_test();
        let relay = transports::FourTuple::Relay {
            url: "https://relay.example.invalid".parse().unwrap(),
            endpoint_id: iroh_base::SecretKey::from_bytes(&[1; 32]).public(),
        };
        let transmit = OwnedTransmit {
            ecn: None,
            contents: bytes::Bytes::from_static(b"initial"),
            segment_size: None,
        };
        send_datagram(&mut sender, relay.clone(), transmit.clone())
            .await
            .unwrap();
        let sends = send_datagram_to_targets(
            Box::new(sender),
            transmit,
            vec![
                relay,
                transports::FourTuple::from_remote(transports::Addr::Ip(
                    receiver.local_addr().unwrap(),
                )),
            ],
        );
        let mut buf = [0; 64];
        // The Relay queue stays full while the later Direct target receives its Initial.
        tokio::select! {
            _ = sends => panic!("blocked Relay send unexpectedly completed"),
            received = time::timeout(Duration::from_secs(1), receiver.recv(&mut buf)) => {
                let len = received.expect("Direct send blocked behind Relay").unwrap();
                assert_eq!(&buf[..len], b"initial");
            }
        }
    }
}

/// Messages to send to the [`RemoteStateActor`].
#[derive(derive_more::Debug)]
pub(crate) enum RemoteStateMessage {
    /// Sends a datagram to all known paths.
    ///
    /// Used to send QUIC Initial packets.  If there is no working direct path this will
    /// trigger holepunching.
    ///
    /// This is not acceptable to use on the normal send path, as it is an async send
    /// operation with a bunch more copying.  So it should only be used for sending QUIC
    /// Initial packets.
    #[debug("SendDatagram(..)")]
    SendDatagram(Box<TransportsSender>, OwnedTransmit),
    /// Adds an active connection to this remote endpoint.
    ///
    /// The actor will downgrade the connection to a [`noq::WeakConnectionHandle`] as soon
    /// as it processes the message. It will keep hold of the weak handle until it closes,
    /// but only update to a strong [`noq::Connection`] for brief moments.
    ///
    /// The actor will actively manage paths on the connection and start holepunching as needed.
    #[debug("AddConnection({})", _0.stable_id())]
    AddConnection(noq::Connection, oneshot::Sender<PathStateReceiver>),
    /// Asks if there is any possible path that could be used.
    ///
    /// This adds the provided transport addresses to the list of potential paths for this
    /// remote and starts Address Lookup if needed.
    ///
    /// Sends back `Ok` immediately if the provided address list is non-empy or we have are
    /// other known paths.  Otherwise sends back `Ok` once Address Lookup produces a result,
    /// or the Address Lookup error if Address Lookup fails or produces no results,
    ///
    /// ember: with the relays the remote is not to be reached through, where they are said (they stay as said last).
    #[debug("ResolveRemote(..)")]
    ResolveRemote(
        BTreeSet<TransportAddr>,
        Option<BTreeSet<RelayUrl>>,
        oneshot::Sender<Result<(), AddressLookupFailed>>,
    ),
    /// Returns information about the remote.
    ///
    /// This currently only includes a list of all known transport addresses for the remote.
    RemoteInfo(oneshot::Sender<RemoteInfo>),
    /// The network status has changed in some way
    NetworkChange { is_major: bool },
    /// ember: the remote's disabled relays changed (`Endpoint::set_disabled_relays`): gone by, then told.
    #[debug("ApplyRelayPolicy(..)")]
    ApplyRelayPolicy(oneshot::Sender<()>),
    /// ember: a relay was locally removed (`Endpoint::remove_relay`): close active paths through it, then acknowledge.
    #[debug("RelayRemoved({_0})")]
    RelayRemoved(RelayUrl, oneshot::Sender<()>),
    /// ember: an inserted local relay connected (`Endpoint::insert_relay`): reopen missing paths.
    #[debug("RelayConnected({_0})")]
    RelayConnected(RelayUrl),
    /// ember: returns `(opening_for_relay, lost_for_relay, relay_lost_total)` for a connection on this remote (tests).
    #[cfg(test)]
    #[debug("RelayLossStats({_0}, {_1})")]
    RelayLossStats(usize, RelayUrl, oneshot::Sender<Option<(usize, u32, u32)>>),
}

/// Information about a holepunch attempt.
///
/// Addresses are always stored in canonical form.
#[derive(Debug)]
struct HolepunchAttempt {
    when: Instant,
    /// The set of local addresses which could take part in holepunching.
    ///
    /// This does not mean every address here participated in the holepunching.  E.g. we
    /// could have tried only a sub-set of the addresses because a previous attempt already
    /// covered part of the range.
    ///
    /// We do not store this as a [`DirectAddr`] because this is checked for equality and we
    /// do not want to compare the sources of these addresses.
    local_candidates: BTreeSet<SocketAddr>,
    /// The set of remote addresses which could take part in holepunching.
    ///
    /// Like [`Self::local_candidates`] we may not have used them.
    remote_candidates: BTreeSet<SocketAddr>,
}

/// Newtype to track Connections.
///
/// The wrapped value is the [`noq::Connection::stable_id`] value, and is thus only valid
/// for active connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, derive_more::Display)]
#[display("{_0}")]
struct ConnId(usize);

/// State about one connection.
#[derive(Debug)]
struct ConnectionState {
    /// Weak handle to the connection.
    handle: WeakConnectionHandle,
    /// Writer-side handle for the connection's path observation state.
    ///
    /// The matching [`PathStateReceiver`] is held by the [`Connection`].
    ///
    /// [`Connection`]: crate::endpoint::Connection
    path_state: PathStateSender,
    /// The open paths that exist on this connection.
    paths: FxHashMap<PathId, transports::FourTuple>,
    /// Whether this connection has ever had a direct path.
    ///
    /// Used for recording metrics.
    has_been_direct: bool,
    /// ember: the tries to open a custom path on this connection, each a new path id, since a custom path last opened
    /// on it or the remote's custom addresses changed (`RemoteStateActor::open_custom_paths`).
    custom_tries: u32,
    /// ember: the custom paths being opened (not yet established or abandoned).
    custom_opening: Vec<PathId>,
    /// ember: the path ids lost to custom paths given up before they opened ([`CUSTOM_PATH_LOST_MAX`] at most), since a
    /// custom path last opened on this connection or the remote's custom addresses changed.
    custom_lost: u32,
    /// ember: one more try asked for by a network change, past the timer's tries.
    custom_event_try: bool,
    /// ember: when the next try may start ([`CUSTOM_PATH_RETRY_AFTER`]).
    custom_not_before: Option<Instant>,
    /// ember: the relay paths being opened (not yet established or abandoned), with the remote relay address of each.
    relay_opening: FxHashMap<PathId, transports::Addr>,
    /// ember: the path ids lost per relay address to paths given up before they opened ([`RELAY_PATH_LOST_MAX`] at
    /// most), since a path through that relay last opened on this connection or a major network change.
    relay_lost: FxHashMap<transports::Addr, u32>,
    /// ember: the total path ids this connection lost to relay paths given up before they opened
    /// ([`RELAY_CONN_LOST_MAX`] at most).
    relay_lost_total: u32,
}

impl ConnectionState {
    /// Tracks an open path for the connection.
    fn add_open_path(
        &mut self,
        network_path: transports::FourTuple,
        path_id: PathId,
        metrics: &Arc<SocketMetrics>,
    ) {
        match network_path {
            transports::FourTuple::Ip { .. } => metrics.paths_direct.inc(),
            transports::FourTuple::Relay { .. } => metrics.paths_relay.inc(),
            transports::FourTuple::Custom { .. } => metrics.paths_custom.inc(),
        };
        if !self.has_been_direct && network_path.is_ip() {
            self.has_been_direct = true;
            metrics.num_conns_direct.inc();
        }

        self.paths.insert(path_id, network_path.clone());
        if let Some(conn) = self.handle.upgrade()
            && let Some(path) = conn.path(path_id)
        {
            let handle = path.weak_handle();
            self.path_state.record_opened(handle, network_path);
        }
    }

    /// Removes a path from this connection.
    fn remove_path(
        &mut self,
        path_id: &PathId,
        conn: &noq::Connection,
    ) -> Option<transports::FourTuple> {
        let addr = self.paths.remove(path_id)?;
        self.path_state.record_abandoned(*path_id, conn);
        Some(addr)
    }
}

/// State of the endpoint relevant for path selection.
///
/// Constructed by the endpoint and passed to [`PathSelector::select`].  Borrows from
/// the endpoint's internal data.
#[derive(Debug)]
#[cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]
pub struct PathSelectionContext<'a> {
    current: Option<&'a transports::FourTuple>,
    source: PathsSource<'a>,
}

/// Either a reference to live connection state, or a synthesized list of paths
/// (for unit-testing selectors).
#[derive(Debug)]
enum PathsSource<'a> {
    Live(&'a FxHashMap<ConnId, ConnectionState>),
    #[cfg(test)]
    Test(Vec<PathSelectionData<'a>>),
}

#[cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]
impl<'a> PathSelectionContext<'a> {
    fn new(
        current: Option<&'a transports::FourTuple>,
        connections: &'a FxHashMap<ConnId, ConnectionState>,
    ) -> Self {
        Self {
            current,
            source: PathsSource::Live(connections),
        }
    }

    /// Constructs a context with synthetic path data for testing.
    #[cfg(test)]
    pub(crate) fn for_test(
        current: Option<&'a transports::FourTuple>,
        paths: Vec<PathSelectionData<'a>>,
    ) -> Self {
        Self {
            current,
            source: PathsSource::Test(paths),
        }
    }

    /// The path currently considered the preferred path to the remote endpoint, if any.
    pub fn current(&self) -> Option<&transports::FourTuple> {
        self.current
    }

    /// Iterator over candidate paths.
    ///
    /// The same address may appear more than once when it is a path on multiple
    /// connections to the remote.  Selectors that care should aggregate as appropriate.
    pub fn paths(&self) -> Box<dyn Iterator<Item = PathSelectionData<'a>> + '_> {
        match &self.source {
            PathsSource::Live(connections) => Box::new(
                connections
                    .values()
                    .filter_map(|state| state.handle.upgrade().map(|conn| (state, conn)))
                    .flat_map(|(state, conn)| {
                        state.paths.iter().map(move |(path_id, addr)| {
                            PathSelectionData::live(addr, *path_id, conn.clone())
                        })
                    }),
            ),
            #[cfg(test)]
            PathsSource::Test(paths) => Box::new(paths.iter().cloned()),
        }
    }
}

/// Data the selector sees about one candidate path.
//
// In production this borrows from a live connection and looks up stats from noq on
// demand.  In `#[cfg(test)]` builds it can also wrap synthesized stats so selectors
// can be unit-tested without standing up real connections.
#[cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]
#[derive(derive_more::Debug, Clone)]
pub struct PathSelectionData<'a> {
    network_path: &'a transports::FourTuple,
    #[debug(skip)]
    source: StatsSource,
}

#[derive(Clone)]
enum StatsSource {
    Live {
        path_id: PathId,
        conn: noq::Connection,
    },
    /// Boxed so `PathStats` (100+ bytes, 14 fields) doesn't inflate the enum's
    /// size in production where only the `Live` variant is ever constructed.
    #[cfg(test)]
    Test(Option<Box<PathStats>>),
}

#[cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]
impl<'a> PathSelectionData<'a> {
    fn live(
        network_path: &'a transports::FourTuple,
        path_id: PathId,
        conn: noq::Connection,
    ) -> Self {
        Self {
            network_path,
            source: StatsSource::Live { path_id, conn },
        }
    }

    /// Constructs a [`PathSelectionData`] with synthetic stats for testing.
    ///
    /// `PathStats` is `#[non_exhaustive]` so callers build it via
    /// `let mut s = PathStats::default(); s.rtt = ...;`.
    #[cfg(test)]
    pub(crate) fn for_test(
        network_path: &'a transports::FourTuple,
        stats: Option<PathStats>,
    ) -> Self {
        Self {
            network_path,
            source: StatsSource::Test(stats.map(Box::new)),
        }
    }

    /// The network path of the candidate path.
    pub fn network_path(&self) -> &transports::FourTuple {
        self.network_path
    }

    /// Identity of the connection supplying these statistics, without keeping it alive.
    /// Pair with PathStats::path_generation to identify a path incarnation.
    #[cfg(feature = "unstable-custom-transports")]
    pub fn connection(&self) -> Option<PathSelectionConnection> {
        match &self.source {
            StatsSource::Live { conn, .. } => Some(PathSelectionConnection(conn.weak_handle())),
            #[cfg(test)]
            StatsSource::Test(_) => None,
        }
    }

    /// Returns path statistics if available.
    pub fn stats(&self) -> Option<PathStats> {
        match &self.source {
            StatsSource::Live { path_id, conn } => conn.path_stats(*path_id),
            #[cfg(test)]
            StatsSource::Test(stats) => stats.as_deref().copied(),
        }
    }
}

/// Opaque connection identity for comparing path-statistics sources.
///
/// A weak handle does not keep the connection alive. Unlike a bare stable_id,
/// it retains allocation identity even after that connection is dropped.
#[derive(Debug, Clone)]
#[cfg(feature = "unstable-custom-transports")]
pub struct PathSelectionConnection(noq::WeakConnectionHandle);

#[cfg(feature = "unstable-custom-transports")]
impl PartialEq for PathSelectionConnection {
    fn eq(&self, other: &Self) -> bool {
        self.0.is_same_connection(&other.0)
    }
}
#[cfg(feature = "unstable-custom-transports")]
impl Eq for PathSelectionConnection {}

/// Trait to configure path selection.
///
/// Most users do not need to provide their own selector.
#[cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]
pub trait PathSelector: Send + Sync + std::fmt::Debug + 'static {
    /// Pick the selected path to carry application data among the currently
    /// open network paths to the remote endpoint.
    ///
    /// Build the result by starting from [`PathSelection::none`] and calling
    /// [`PathSelection::set`] for the path the selector wants active.
    ///
    /// Returning an empty [`PathSelection`] keeps the current selection unchanged.
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection;
}

/// ember: one single-path `PING` request recorded on [`PathSelection`].
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "unstable-custom-transports"), allow(dead_code))]
enum PingTarget {
    Live {
        conn: noq::WeakConnectionHandle,
        path_id: PathId,
        generation: Option<u64>,
        network_path: transports::FourTuple,
    },
    #[cfg(test)]
    Test(transports::FourTuple),
}

#[cfg_attr(not(feature = "unstable-custom-transports"), allow(dead_code))]
impl PingTarget {
    fn same_target(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Live {
                    conn: a_conn,
                    path_id: a_id,
                    generation: a_gen,
                    ..
                },
                Self::Live {
                    conn: b_conn,
                    path_id: b_id,
                    generation: b_gen,
                    ..
                },
            ) => a_conn.is_same_connection(b_conn) && a_id == b_id && a_gen == b_gen,
            #[cfg(test)]
            (Self::Test(a), Self::Test(b)) => a == b,
            #[cfg(test)]
            _ => false,
        }
    }
}

/// The set of paths a [`PathSelector`] has chosen.
///
/// Holds at most one selected path, optional custom-path retirement requests, and optional
/// single-path ping requests.
/// Build via [`PathSelection::none`], [`PathSelection::set`], [`PathSelection::close`], and
/// [`PathSelection::ping`].
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]
pub struct PathSelection {
    selection: Option<transports::FourTuple>,
    close: Vec<transports::FourTuple>,
    ping: Vec<PingTarget>,
}

#[cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]
impl PathSelection {
    /// An empty selection.
    pub fn none() -> Self {
        Self {
            selection: None,
            close: Vec::new(),
            ping: Vec::new(),
        }
    }

    /// Sets the path as the selected path.
    ///
    /// This discards any previously selected path and sets this one as a single selected
    /// path.
    pub fn set(&mut self, path: &PathSelectionData<'_>) {
        if self.selection.is_some() {
            tracing::warn!(
                path = %path.network_path(),
                "PathSelection already contains a path; ignoring additional path"
            );
            return;
        }
        self.selection = Some(path.network_path.clone());
    }

    /// Requests retirement of an explicitly withdrawn custom path.
    ///
    /// This does not close IP or relay paths. Each connection closes the requested
    /// path only when its selected, different path is still open and has a validated
    /// same-path RTT. All connections sharing that remote address must be ready
    /// before any is closed, so discovery cannot reopen it on a retired connection.
    /// Without such a replacement the request is ignored; selectors
    /// should repeat it while the withdrawal remains in effect. Do not use this for
    /// a path that merely scores worse or suffers a short latency spike.
    pub fn close(&mut self, path: &PathSelectionData<'_>) {
        if matches!(path.network_path(), transports::FourTuple::Custom { .. })
            && !self.close.contains(path.network_path())
        {
            self.close.push(path.network_path().clone());
        }
    }

    /// ember: requests one single-path QUIC `PING` on `path` after this selection pass.
    ///
    /// Carries no cadence or budget policy. Callers govern when to probe. Duplicate
    /// requests for the same path incarnation within one selection pass send a single ping,
    /// and closed paths are ignored without error.
    #[cfg_attr(not(feature = "unstable-custom-transports"), allow(dead_code))]
    pub fn ping(&mut self, path: &PathSelectionData<'_>) {
        let target = match &path.source {
            StatsSource::Live { path_id, conn } => PingTarget::Live {
                conn: conn.weak_handle(),
                path_id: *path_id,
                generation: conn.path_stats(*path_id).map(|s| s.path_generation),
                network_path: path.network_path.clone(),
            },
            #[cfg(test)]
            StatsSource::Test(_) => PingTarget::Test(path.network_path.clone()),
        };
        if !self.ping.iter().any(|existing| existing.same_target(&target)) {
            self.ping.push(target);
        }
    }

    /// The selected path: the one data should be sent on. This is not public so
    /// we can later allow for selecting multiple paths without changing the
    /// public API of `PathSelection`.
    ///
    /// Returns `None` when nothing has been selected.
    pub(crate) fn selected(&self) -> Option<&transports::FourTuple> {
        self.selection.as_ref()
    }
}

/// Poll a future once, like n0_future::future::poll_once but sync.
fn now_or_never<T, F: Future<Output = T>>(fut: F) -> Option<T> {
    let fut = std::pin::pin!(fut);
    match fut.poll(&mut std::task::Context::from_waker(std::task::Waker::noop())) {
        Poll::Ready(res) => Some(res),
        Poll::Pending => None,
    }
}

/// Future that resolves to the `conn_id` once a connection is closed.
///
/// This uses [`noq::Connection::on_closed`], which does not keep the connection alive
/// while awaiting the future.
struct OnClosed {
    conn_id: ConnId,
    inner: noq::OnClosed,
}

impl OnClosed {
    fn new(conn: &noq::Connection) -> Self {
        Self {
            conn_id: ConnId(conn.stable_id()),
            inner: conn.on_closed(),
        }
    }
}

impl Future for OnClosed {
    type Output = (ConnId, Closed);

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let closed = std::task::ready!(Pin::new(&mut self.inner).poll(cx));
        Poll::Ready((self.conn_id, closed))
    }
}

/// Converts an iterator of [`TransportAddr'] into an iterator of [`transports::Addr`].
fn to_transports_addr(
    endpoint_id: EndpointId,
    addrs: impl IntoIterator<Item = TransportAddr>,
) -> impl Iterator<Item = transports::Addr> {
    addrs.into_iter().filter_map(move |addr| match addr {
        TransportAddr::Relay(relay_url) => Some(transports::Addr::from((relay_url, endpoint_id))),
        TransportAddr::Ip(sockaddr) => Some(transports::Addr::from(sockaddr)),
        TransportAddr::Custom(custom_addr) => Some(transports::Addr::from(custom_addr)),
        _ => {
            warn!(?addr, "Unsupported TransportAddr");
            None
        }
    })
}

/// Returns the next item if `maybe_stream` is `Some`, or `None` otherwise.
async fn maybe_next<S: Stream + Unpin>(maybe_stream: Option<&mut S>) -> Option<Option<S::Item>> {
    match maybe_stream {
        None => None,
        Some(s) => Some(s.next().await),
    }
}

#[cfg(test)]
mod selector_close_tests {
    use super::*;

    #[derive(Debug, Default)]
    struct CapturePaths {
        paths: std::sync::Mutex<Vec<(noq::Connection, PathId, transports::FourTuple)>>,
        changed: tokio::sync::Notify,
    }
    impl PathSelector for CapturePaths {
        fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
            let mut captured = self.paths.lock().unwrap();
            captured.clear();
            let mut selected = PathSelection::none();
            for path in ctx.paths() {
                if path.stats().is_some_and(|stats| stats.same_path_rtt.is_some()) {
                    if path.network_path().is_ip() && selected.selected().is_none() {
                        selected.set(&path);
                    }
                    if let StatsSource::Live { conn, path_id } = &path.source {
                        captured.push((conn.clone(), *path_id, path.network_path().clone()));
                    }
                }
            }
            self.changed.notify_one();
            selected
        }
    }

    #[tokio::test]
    async fn selector_close_waits_for_all_connections_then_forgets_address() {
        use crate::{Endpoint, endpoint::presets, test_utils::test_transport::{TestNetwork, to_custom_addr}};
        let network = TestNetwork::new();
        let capture = Arc::new(CapturePaths::default());
        let a_key = iroh_base::SecretKey::from_bytes(&[21; 32]);
        let b_key = iroh_base::SecretKey::from_bytes(&[22; 32]);
        let a = Endpoint::builder(presets::Minimal)
            .secret_key(a_key.clone()).alpns(vec![b"retire".to_vec()])
            .add_custom_transport(network.create_transport(a_key.public()).unwrap())
            .path_selector(capture.clone()).bind().await.unwrap();
        let b = Endpoint::builder(presets::Minimal)
            .secret_key(b_key.clone()).alpns(vec![b"retire".to_vec()])
            .add_custom_transport(network.create_transport(b_key.public()).unwrap())
            .path_selector(Arc::new(CapturePaths::default())).bind().await.unwrap();
        let addr = iroh_base::EndpointAddr::from_parts(b.id(), b.addr().addrs.into_iter()
            .chain([iroh_base::TransportAddr::Custom(to_custom_addr(b.id()))]));
        let mut clients = Vec::new();
        let mut servers = Vec::new();
        for _ in 0..2 {
            let (client, server) = tokio::join!(a.connect(addr.clone(), b"retire"), async {
                b.accept().await.unwrap().await.unwrap()
            });
            clients.push(client.unwrap());
            servers.push(server);
        }
        let paths = time::timeout(Duration::from_secs(10), async {
            loop {
                capture.changed.notified().await;
                let paths = capture.paths.lock().unwrap().clone();
                let mut ready = FxHashMap::<usize, (bool, bool)>::default();
                for (conn, _, addr) in &paths {
                    let entry = ready.entry(conn.stable_id()).or_default();
                    entry.0 |= addr.is_ip();
                    entry.1 |= matches!(addr, transports::FourTuple::Custom { .. });
                }
                if ready.len() == 2 && ready.values().all(|p| p.0 && p.1) { break paths; }
            }
        }).await.expect("both connections have validated IP and custom paths");
        let local = n0_watcher::Watchable::new(BTreeSet::new());
        let mut actor = RemoteStateActor::new(b.id(), local.watch(), Default::default(),
            Default::default(), Arc::default(), AddressLookupServices::default(),
            Arc::new(CapturePaths::default()), false, RelayPolicies::default());
        let mut connections = FxHashMap::default();
        for (conn, _, _) in &paths { connections.insert(conn.stable_id(), conn.clone()); }
        for conn in connections.values() {
            let (tx, _) = oneshot::channel();
            actor.handle_msg_add_connection(conn.clone(), tx);
        }
        for state in actor.connections.values_mut() { state.paths.clear(); }
        let mut selection = PathSelection::none();
        for (conn, id, addr) in &paths {
            actor.connections.get_mut(&ConnId(conn.stable_id())).unwrap().paths.insert(*id, addr.clone());
            if matches!(addr, transports::FourTuple::Custom { .. }) {
                selection.close(&PathSelectionData::for_test(addr, None));
                actor.state.paths.insert_open_path(addr.remote(), Source::Connection);
            }
        }
        let selected = paths.iter().find(|(_, _, addr)| addr.is_ip()).unwrap().2.clone();
        actor.state.selected_path = Some(selected.clone());
        let second = *actor.connections.keys().nth(1).unwrap();
        let missing: Vec<_> = actor.connections.get_mut(&second).unwrap().paths.extract_if(|_, addr| *addr == selected).collect();
        assert!(!missing.is_empty(), "same selected IP path exists on both connections");
        let mut events: Vec<_> = connections.values().map(|conn| conn.path_events()).collect();
        actor.close_withdrawn_paths(&selection);
        // A round trip drives both connection tasks, so an erroneous close would
        // be observable as Abandoned; path() itself retains draining path objects.
        for (client, server) in clients.iter().zip(&servers) {
            client.send_datagram(bytes::Bytes::from_static(b"still-open")).unwrap();
            let data = server.read_datagram().await.unwrap();
            server.send_datagram(data).unwrap();
            assert_eq!(client.read_datagram().await.unwrap().as_ref(), b"still-open");
        }
        for events in &mut events {
            while let Some(Some(event)) = now_or_never(events.next()) {
                assert!(!matches!(event.unwrap(), NoqPathEvent::Abandoned { .. }),
                    "no partial retirement without both replacements");
            }
        }
        for (_, _, addr) in &paths {
            if matches!(addr, transports::FourTuple::Custom { .. }) {
                assert!(actor.state.paths.addrs().any(|known| known == &addr.remote()));
            }
        }
        actor.connections.get_mut(&second).unwrap().paths.extend(missing);
        actor.close_withdrawn_paths(&selection);
        for (conn, id, addr) in &paths {
            if matches!(addr, transports::FourTuple::Custom { .. }) {
                // noq keeps the path object while draining; ClosedPath proves the
                // path is already abandoned even before that object is discarded.
                if let Some(path) = conn.path(*id) {
                    assert!(matches!(path.close(), Err(noq_proto::ClosePathError::ClosedPath)),
                        "withdrawn path must already be closed");
                }
                assert!(!actor.state.paths.addrs().any(|known| known == &addr.remote()));
            }
        }
        actor.open_custom_paths();
        assert!(actor.connections.values().all(|state| state.custom_opening.is_empty()),
            "forgotten circuit is not automatically reopened");
        drop(clients); drop(servers);
        a.close().await; b.close().await;
    }

    #[test]
    fn selector_close_only_requests_distinct_custom_paths() {
        let custom = transports::FourTuple::from_remote(transports::Addr::Custom(
            CustomAddr::from_parts(7, b"withdrawn"),
        ));
        let ip = transports::FourTuple::from_remote(transports::Addr::Ip(
            "127.0.0.1:1234".parse().unwrap(),
        ));
        let relay = transports::FourTuple::from_remote(transports::Addr::Relay(
            "https://relay.example".parse().unwrap(),
            iroh_base::SecretKey::from_bytes(&[7; 32]).public(),
        ));
        let mut selection = PathSelection::none();
        assert!(selection.close.is_empty());
        for addr in [&ip, &relay, &custom, &custom] {
            selection.close(&PathSelectionData::for_test(addr, None));
        }
        assert_eq!(selection.close, vec![custom]);
        assert!(selection.selected().is_none());
    }

    #[derive(Debug, Default)]
    struct ScriptedPingSelector {
        paths: std::sync::Mutex<Vec<(noq::Connection, PathId, transports::FourTuple)>>,
        target_conn_stable_id: std::sync::Mutex<Option<usize>>,
        ping_custom_once: std::sync::atomic::AtomicBool,
        ping_all_once: std::sync::atomic::AtomicBool,
        selected: tokio::sync::Notify,
    }

    impl PathSelector for ScriptedPingSelector {
        fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
            let mut captured = self.paths.lock().unwrap();
            captured.clear();
            let mut selection = PathSelection::none();
            let target_conn = *self.target_conn_stable_id.lock().unwrap();
            let ping_custom = self
                .ping_custom_once
                .swap(false, std::sync::atomic::Ordering::SeqCst);
            let ping_all = self
                .ping_all_once
                .swap(false, std::sync::atomic::Ordering::SeqCst);
            for path in ctx.paths() {
                if path.stats().is_some_and(|stats| stats.same_path_rtt.is_some()) {
                    if path.network_path().is_relay() && selection.selected().is_none() {
                        selection.set(&path);
                    }
                    if let StatsSource::Live { conn, path_id } = &path.source {
                        captured.push((conn.clone(), *path_id, path.network_path().clone()));
                        if ping_custom
                            && matches!(path.network_path(), transports::FourTuple::Custom { .. })
                            && Some(conn.stable_id()) == target_conn
                        {
                            selection.ping(&path);
                            selection.ping(&path);
                        }
                        if ping_all {
                            selection.ping(&path);
                        }
                    }
                }
            }
            self.selected.notify_waiters();
            selection
        }
    }

    #[tokio::test]
    async fn selector_ping_sends_only_when_requested_and_once_per_request_and_ignores_closed_paths() {
        use crate::{
            Endpoint, RelayMap, RelayMode,
            endpoint::{QuicTransportConfig, presets},
            test_utils::{
                run_relay_server_with,
                test_transport::{TestNetwork, to_custom_addr},
            },
            tls::CaTlsConfig,
        };
        let (_, relay_url, _relay_guard) = run_relay_server_with(false).await.unwrap();
        let relay_map = RelayMap::from(relay_url.clone());
        let network = TestNetwork::new();
        let scripted = Arc::new(ScriptedPingSelector::default());
        // Suppress automatic connection/path keepalives, DPLPMTUD MTU probes, and IP QNT
        // holepunching, and keep initial RTT high so short CPU stalls cannot fire a PTO PING.
        let transport = QuicTransportConfig::builder()
            .keep_alive_interval(Duration::from_secs(60))
            .default_path_keep_alive_interval(Duration::from_secs(60))
            .default_path_max_idle_timeout(Duration::from_secs(60))
            .mtu_discovery_config(None)
            .initial_rtt(Duration::from_millis(500))
            .build();
        let a_key = iroh_base::SecretKey::from_bytes(&[31; 32]);
        let b_key = iroh_base::SecretKey::from_bytes(&[32; 32]);
        let a = Endpoint::builder(presets::Minimal)
            .secret_key(a_key.clone())
            .alpns(vec![b"ping".to_vec()])
            .clear_ip_transports()
            .relay_mode(RelayMode::Custom(relay_map.clone()))
            .ca_tls_config(CaTlsConfig::insecure_skip_verify())
            .transport_config(transport.clone())
            .add_custom_transport(network.create_transport(a_key.public()).unwrap())
            .path_selector(scripted.clone())
            .bind()
            .await
            .unwrap();
        let b = Endpoint::builder(presets::Minimal)
            .secret_key(b_key.clone())
            .alpns(vec![b"ping".to_vec()])
            .clear_ip_transports()
            .relay_mode(RelayMode::Custom(relay_map))
            .ca_tls_config(CaTlsConfig::insecure_skip_verify())
            .transport_config(transport)
            .add_custom_transport(network.create_transport(b_key.public()).unwrap())
            .path_selector(Arc::new(CapturePaths::default()))
            .bind()
            .await
            .unwrap();
        b.online().await;
        let addr = iroh_base::EndpointAddr::from_parts(
            b.id(),
            [
                iroh_base::TransportAddr::Relay(relay_url),
                iroh_base::TransportAddr::Custom(to_custom_addr(b.id())),
            ],
        );
        let mut clients = Vec::new();
        let mut servers = Vec::new();
        for _ in 0..2 {
            let (client, server) = tokio::join!(a.connect(addr.clone(), b"ping"), async {
                b.accept().await.unwrap().await.unwrap()
            });
            clients.push(client.unwrap());
            servers.push(server);
        }
        let paths = time::timeout(Duration::from_secs(10), async {
            loop {
                scripted.selected.notified().await;
                let paths = scripted.paths.lock().unwrap().clone();
                let mut ready = FxHashMap::<usize, (bool, bool)>::default();
                for (conn, _, p_addr) in &paths {
                    let entry = ready.entry(conn.stable_id()).or_default();
                    entry.0 |= p_addr.is_relay();
                    entry.1 |= matches!(p_addr, transports::FourTuple::Custom { .. });
                }
                if ready.len() == 2 && ready.values().all(|p| p.0 && p.1) {
                    break paths;
                }
            }
        })
        .await
        .expect("both connections have validated relay and custom paths");

        let target_stable_id = clients[0].stable_id();
        let other_stable_id = clients[1].stable_id();
        assert_ne!(target_stable_id, other_stable_id);
        let target_conn = paths
            .iter()
            .find_map(|(c, _, _)| (c.stable_id() == target_stable_id).then(|| c.clone()))
            .expect("first client connection present in selector snapshot");
        let other_conn = paths
            .iter()
            .find_map(|(c, _, _)| (c.stable_id() == other_stable_id).then(|| c.clone()))
            .expect("second client connection present in selector snapshot");
        *scripted.target_conn_stable_id.lock().unwrap() = Some(target_conn.stable_id());
        let (_, target_custom_id, target_custom_addr) = paths
            .iter()
            .find(|(c, _, p)| {
                c.stable_id() == target_conn.stable_id()
                    && matches!(p, transports::FourTuple::Custom { .. })
            })
            .unwrap()
            .clone();
        let (_, target_relay_id, _) = paths
            .iter()
            .find(|(c, _, p)| c.stable_id() == target_conn.stable_id() && p.is_relay())
            .unwrap();

        let flush_round_trip = async |clients: &[crate::endpoint::Connection],
                                      servers: &[crate::endpoint::Connection]| {
            for (client, server) in clients.iter().zip(servers) {
                client
                    .send_datagram(bytes::Bytes::from_static(b"sync"))
                    .unwrap();
                let data = server.read_datagram().await.unwrap();
                server.send_datagram(data).unwrap();
                assert_eq!(client.read_datagram().await.unwrap().as_ref(), b"sync");
            }
        };

        // 1. Without PathSelection::ping, a real select_path pass sends zero PING frames.
        scripted.selected.notified().await;
        flush_round_trip(&clients, &servers).await;
        let before_unrequested_0 = target_conn.stats().frame_tx.ping;
        let before_unrequested_1 = other_conn.stats().frame_tx.ping;
        let before_custom_samples = target_conn
            .path_stats(target_custom_id)
            .unwrap()
            .same_path_rtt_samples;
        scripted.selected.notified().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(target_conn.stats().frame_tx.ping, before_unrequested_0);
        assert_eq!(other_conn.stats().frame_tx.ping, before_unrequested_1);
        assert_eq!(
            target_conn
                .path_stats(target_custom_id)
                .unwrap()
                .same_path_rtt_samples,
            before_custom_samples
        );

        // 2. Requesting ping (including duplicate calls on the same PathSelectionData in one pass)
        // sends exactly one PING on that exact connection and path, and zero on the other connection.
        let before_tx_relay = target_conn
            .path_stats(*target_relay_id)
            .unwrap()
            .udp_tx
            .datagrams;
        scripted
            .ping_custom_once
            .store(true, std::sync::atomic::Ordering::SeqCst);
        time::timeout(Duration::from_secs(5), async {
            loop {
                if target_conn
                    .path_stats(target_custom_id)
                    .unwrap()
                    .same_path_rtt_samples
                    > before_custom_samples
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("single-path ping refreshes same_path_rtt_samples on the requested backup path");
        assert_eq!(target_conn.stats().frame_tx.ping, before_unrequested_0 + 1);
        assert_eq!(other_conn.stats().frame_tx.ping, before_unrequested_1);
        assert_eq!(
            target_conn
                .path_stats(*target_relay_id)
                .unwrap()
                .udp_tx
                .datagrams,
            before_tx_relay,
            "unrequested relay path on the same connection transmits nothing"
        );

        // 3. Pinging an already closed path or closed connection does not fail or disrupt live paths.
        if let Some(path) = target_conn.path(target_custom_id) {
            let _ = path.close();
        }
        other_conn.close(0u32.into(), b"closed");
        let local = n0_watcher::Watchable::new(BTreeSet::new());
        let mut actor = RemoteStateActor::new(
            b.id(),
            local.watch(),
            Default::default(),
            Default::default(),
            Arc::default(),
            AddressLookupServices::default(),
            Arc::new(CapturePaths::default()),
            false,
            RelayPolicies::default(),
        );
        for conn in [&target_conn, &other_conn] {
            let (tx, _) = oneshot::channel();
            actor.handle_msg_add_connection(conn.clone(), tx);
        }
        actor
            .connections
            .get_mut(&ConnId(target_conn.stable_id()))
            .unwrap()
            .paths
            .insert(target_custom_id, target_custom_addr.clone());
        let mut closed_selection = PathSelection::none();
        closed_selection.ping(&PathSelectionData::live(
            &target_custom_addr,
            target_custom_id,
            target_conn.clone(),
        ));
        closed_selection.ping(&PathSelectionData::live(
            &target_custom_addr,
            target_custom_id,
            other_conn.clone(),
        ));
        actor.ping_paths(&closed_selection);
        scripted
            .ping_all_once
            .store(true, std::sync::atomic::Ordering::SeqCst);
        scripted.selected.notified().await;
        clients[0]
            .send_datagram(bytes::Bytes::from_static(b"after-close"))
            .unwrap();
        let data = servers[0].read_datagram().await.unwrap();
        assert_eq!(data.as_ref(), b"after-close");

        drop(clients);
        drop(servers);
        a.close().await;
        b.close().await;
    }

    #[test]
    fn selector_ping_deduplicates_test_targets_without_changing_selection() {
        let ip = transports::FourTuple::from_remote(transports::Addr::Ip(
            "127.0.0.1:1234".parse().unwrap(),
        ));
        let relay = transports::FourTuple::from_remote(transports::Addr::Relay(
            "https://relay.example".parse().unwrap(),
            iroh_base::SecretKey::from_bytes(&[9; 32]).public(),
        ));
        let mut selection = PathSelection::none();
        for addr in [&ip, &ip, &relay] {
            selection.ping(&PathSelectionData::for_test(addr, None));
        }
        assert_eq!(selection.ping.len(), 2);
        assert!(selection.selected().is_none());
    }
}
