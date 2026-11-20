//! ember: the relays each remote is not to be reached through ([`crate::Endpoint::set_disabled_relays`],
//! `ConnectOptions::with_disabled_relays`).
//!
//! The immutable endpoint allowlist, when configured, is a ceiling on every remote. Within that ceiling,
//! a remote with none disabled is reached through any relay, as upstream. One with some is never reached through them:
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

/// ember: an endpoint's immutable ceiling, independent of learned relay URLs.
#[derive(Debug, Default, Clone)]
pub(crate) struct RelayAllowlist(Option<Arc<BTreeSet<RelayUrl>>>);

impl RelayAllowlist {
    pub(crate) fn new(relays: Option<BTreeSet<RelayUrl>>) -> Self {
        Self(relays.map(Arc::new))
    }

    pub(crate) fn allows(&self, relay: &RelayUrl) -> bool {
        self.0.as_ref().is_none_or(|relays| relays.contains(relay))
    }

    pub(crate) fn config(&self, config: Arc<iroh_relay::RelayConfig>) -> Arc<iroh_relay::RelayConfig> {
        if self.0.is_none() { return config; }
        let mut config = (*config).clone();
        config.entries.retain(|url| self.allows(url));
        Arc::new(config)
    }

    pub(crate) fn relay_map(&self, map: &iroh_relay::RelayMap) -> iroh_relay::RelayMap {
        // Do not mutate the caller's shared map, or let later writes expand ours.
        if self.0.is_none() { return map.clone(); }
        let filtered = iroh_relay::RelayMap::empty();
        for url in map.urls::<Vec<_>>() {
            if self.allows(&url) && let Some(config) = map.get(&url) {
                filtered.insert(url, self.config(config));
            }
        }
        filtered
    }
}

/// Each remote's disabled relays.
type Disabled = HashMap<EndpointId, BTreeSet<RelayUrl>>;

#[derive(Debug, Default, Clone)]
pub(crate) struct RelayPolicies {
    pub(crate) allowlist: RelayAllowlist,
    inner: Arc<RwLock<Disabled>>,
    /// ember: relays removed locally via [`crate::Endpoint::remove_relay`] until re-inserted via
    /// [`crate::Endpoint::insert_relay`].
    removed: Arc<RwLock<BTreeSet<RelayUrl>>>,
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
    /// Dropped: the relay is outside the endpoint allowlist or disabled for the remote.
    pub refused: u64,
}

impl RelayPolicies {
    pub(crate) fn with_allowlist(allowlist: RelayAllowlist) -> Self {
        Self { allowlist, ..Self::default() }
    }

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
        self.allowlist.allows(relay) && Self::allows_in(&self.read(), remote, relay)
    }

    /// Marks `relay` as locally removed (`Endpoint::remove_relay`) or present again (`Endpoint::insert_relay`).
    pub(crate) fn set_removed(&self, relay: &RelayUrl, is_removed: bool) {
        let mut removed = self.removed.write().expect("poisoned");
        if is_removed {
            removed.insert(relay.clone());
        } else {
            removed.remove(relay);
        }
    }

    /// Whether `relay` has been locally removed from this endpoint.
    pub(crate) fn is_removed(&self, relay: &RelayUrl) -> bool {
        self.removed.read().expect("poisoned").contains(relay)
    }

    /// Whether `relay` is both allowed by policy for `remote` and not locally removed.
    pub(crate) fn usable(&self, remote: &EndpointId, relay: &RelayUrl) -> bool {
        self.allows(remote, relay) && !self.is_removed(relay)
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

#[cfg(test)]
mod allowlist_tests {
    use super::*;

    #[test]
    fn relay_allowlist_detaches_home_and_probe_maps_from_external_mutation() {
        let allowed: RelayUrl = "http://127.0.0.1:12340".parse().unwrap();
        let forbidden: RelayUrl = "http://127.0.0.1:12341".parse().unwrap();
        let source: iroh_relay::RelayMap = [allowed.clone(), forbidden.clone()].into_iter().collect();
        source.insert(allowed.clone(), Arc::new(iroh_relay::RelayConfig::from(allowed.clone()).with_entries(vec![forbidden.clone()])));
        let ceiling = RelayAllowlist::new(Some([allowed.clone()].into()));
        let map = ceiling.relay_map(&source);
        assert_eq!(map.urls::<Vec<_>>(), vec![allowed.clone()]);
        assert!(map.get(&allowed).unwrap().entries.is_empty());
        source.insert(forbidden.clone(), Arc::new(iroh_relay::RelayConfig::from(forbidden.clone())));
        assert!(!map.contains(&forbidden));
        assert!(RelayAllowlist::new(Some(Default::default())).relay_map(&source).is_empty());
        assert!(RelayAllowlist::default().relay_map(&source).contains(&forbidden));
    }
}
