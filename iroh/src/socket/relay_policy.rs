//! ember: the relays each remote is not to be reached through ([`crate::Endpoint::set_disabled_relays`],
//! `ConnectOptions::with_disabled_relays`).
//!
//! A remote with none disabled is reached through any relay, as upstream. One with some is never reached through them:
//! every datagram the endpoint would send it through one is dropped where datagrams are handed to the relay transports
//! ([`super::transports::TransportsSender::poll_send`], the one place both a connection's packets on a concrete path
//! and the Initials raced on every known address go through), and its `RemoteStateActor` keeps no address, path or
//! path being opened through one (`RemoteStateActor::apply_relay_policy`). Its IP and custom addresses are never touched.
//!
//! The sets are the socket's, read where they are used, so an actor started anew (after it idled out, or restarted with
//! what came while it stopped) goes by them as they are. An entry is kept until set empty: the caller bounds them
//! (still.fail: a workspace's stations).

use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, RwLock, RwLockReadGuard},
};

use iroh_base::{EndpointId, RelayUrl};

/// Each remote's disabled relays.
type Disabled = HashMap<EndpointId, BTreeSet<RelayUrl>>;

#[derive(Debug, Default, Clone)]
pub(crate) struct RelayPolicies {
    inner: Arc<RwLock<Disabled>>,
    #[cfg(any(test, feature = "test-utils"))]
    counts: Arc<std::sync::Mutex<HashMap<(RelayUrl, EndpointId), RelayDatagrams>>>,
}

/// ember: what was handed to a relay transport for one remote through one relay, and what was dropped instead, the
/// relay being disabled for it (tests).
#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RelayDatagrams {
    /// Handed to the relay transport, taken by it.
    pub sent: u64,
    /// Dropped: the relay is disabled for the remote.
    pub refused: u64,
}

impl RelayPolicies {
    /// Sets the relays `remote` is not to be reached through (none: any relay). Waits for every sender reading them
    /// (`read`) to be done: once this returns, no datagram is handed on by the sets before.
    pub(crate) fn set(&self, remote: EndpointId, disabled: BTreeSet<RelayUrl>) {
        let mut inner = self.inner.write().expect("poisoned");
        if disabled.is_empty() {
            inner.remove(&remote);
        } else {
            inner.insert(remote, disabled);
        }
    }

    /// The relays `remote` is not to be reached through.
    pub(crate) fn disabled(&self, remote: &EndpointId) -> BTreeSet<RelayUrl> {
        self.read().get(remote).cloned().unwrap_or_default()
    }

    /// Whether `remote` may be reached through `relay`.
    pub(crate) fn allows(&self, remote: &EndpointId, relay: &RelayUrl) -> bool {
        Self::allows_in(&self.read(), remote, relay)
    }

    /// The sets, read: [`Self::set`] waits until this is let go. Held only across what does not wait (a sender's
    /// non-blocking poll), so that what it decides and what it hands on are of one set.
    pub(crate) fn read(&self) -> RwLockReadGuard<'_, Disabled> {
        self.inner.read().expect("poisoned")
    }

    /// Whether `remote` may be reached through `relay`, by the sets read.
    pub(crate) fn allows_in(disabled: &Disabled, remote: &EndpointId, relay: &RelayUrl) -> bool {
        disabled.get(remote).is_none_or(|relays| !relays.contains(relay))
    }

    /// A datagram for `remote` through `relay` handed on (`sent`) or dropped (tests count them).
    #[allow(unused_variables)]
    pub(crate) fn counted(&self, relay: &RelayUrl, remote: &EndpointId, sent: bool) {
        #[cfg(any(test, feature = "test-utils"))]
        {
            let mut counts = self.counts.lock().expect("poisoned");
            let entry = counts.entry((relay.clone(), *remote)).or_default();
            if sent {
                entry.sent += 1;
            } else {
                entry.refused += 1;
            }
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn datagrams(&self, relay: &RelayUrl, remote: &EndpointId) -> RelayDatagrams {
        self.counts.lock().expect("poisoned").get(&(relay.clone(), *remote)).copied().unwrap_or_default()
    }
}
