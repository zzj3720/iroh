//! ember: a connection home on every relay leaves a relay whose path went seconds slow. A test binary of its own (CI:
//! `cargo test -p iroh --features test-utils --test relay_slow`): its relays held seconds long slowed the lib's tests
//! with second-long timeouts beside it (`test_paths_watcher`).
#![cfg(not(wasm_browser))]

use std::{sync::Arc, time::Duration};

use iroh::{
    Endpoint, RelayMap, RelayMode, RelayUrl, SecretKey, TransportAddr,
    endpoint::presets,
    test_utils::run_relay_server_with,
    tls::CaTlsConfig,
};
use n0_error::{Result, StdResultExt};
use n0_future::time;
use iroh::Watcher;

const TEST_ALPN: &[u8] = b"n0/iroh/test";

/// ember: a TCP proxy in front of `to` holding what goes through it, either way, `delay` ms (a delay line, in order):
/// a relay seconds away, as its queue to a phone makes it. Its url, for the endpoints that should find it slow.
async fn delayed_relay(to: &RelayUrl, delay: Arc<std::sync::atomic::AtomicU64>) -> Result<RelayUrl> {
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let upstream = format!("{}:{}", to.host_str().expect("host"), to.port().expect("port"));
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.anyerr()?;
    let port = listener.local_addr().anyerr()?.port();
    tokio::spawn(async move {
        while let Ok((down, _)) = listener.accept().await {
            let Ok(up) = tokio::net::TcpStream::connect(&upstream).await else { continue };
            let (dr, dw) = down.into_split();
            let (ur, uw) = up.into_split();
            for (mut from, mut to) in [(Box::new(dr) as Box<dyn tokio::io::AsyncRead + Unpin + Send>, Box::new(uw) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>), (Box::new(ur), Box::new(dw))] {
                let delay = delay.clone();
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(time::Instant, Vec<u8>)>();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 64 * 1024];
                    while let Ok(n) = from.read(&mut buf).await {
                        if n == 0 || tx.send((time::Instant::now() + Duration::from_millis(delay.load(Ordering::Relaxed)), buf[..n].to_vec())).is_err() {
                            break;
                        }
                    }
                });
                tokio::spawn(async move {
                    while let Some((at, bytes)) = rx.recv().await {
                        time::sleep_until(at).await;
                        if to.write_all(&bytes).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
    });
    Ok(format!("https://127.0.0.1:{port}").parse().expect("url"))
}

/// ember: a connection on two relays whose selected path became seconds slower than the other (2026-10-30, a
/// station's reply log: `*https://39.105.157.122/ 11893ms, https://47.76.247.168/ 255ms`, minutes long) moves its
/// packets to the other. Its path was chosen only as a path opened, was established or was given up, and a path
/// slow but alive is none of those.
#[tokio::test]
async fn endpoint_home_on_every_relay_leaves_a_relay_gone_slow() -> Result {
    let (_map_a, url_a, _relay_a) = run_relay_server_with(false).await?;
    let (_map_b, url_b, _relay_b) = run_relay_server_with(false).await?;
    let (delay_a, delay_b) = (Arc::new(std::sync::atomic::AtomicU64::new(0)), Arc::new(std::sync::atomic::AtomicU64::new(0)));
    let (via_a, via_b) = (delayed_relay(&url_a, delay_a.clone()).await?, delayed_relay(&url_b, delay_b.clone()).await?);
    let relays = RelayMap::from_iter([via_a.clone(), via_b.clone()]);
    let bind = |seed: u64| {
        let relays = relays.clone();
        async move {
            Endpoint::builder(presets::N0)
                .secret_key(SecretKey::from_bytes(&[seed as u8 + 1; 32]))
                .alpns(vec![TEST_ALPN.to_vec()])
                .ca_tls_config(CaTlsConfig::insecure_skip_verify())
                .relay_mode(RelayMode::Custom(relays))
                .home_on_every_relay()
                // As still.fail's station and devices: kept alive every second, given up after 3 s of silence.
                .transport_config(
                    iroh::endpoint::QuicTransportConfig::builder()
                        .default_path_keep_alive_interval(Duration::from_secs(1))
                        .default_path_max_idle_timeout(Duration::from_secs(3))
                        .build(),
                )
                .clear_ip_transports()
                .bind()
                .await
        }
    };
    let server = bind(1).await?;
    let client = bind(0).await?;
    let addr = time::timeout(Duration::from_secs(10), async {
        loop {
            let addr = server.addr();
            let urls: Vec<_> = addr.relay_urls().cloned().collect();
            if urls.contains(&via_a) && urls.contains(&via_b) {
                return addr;
            }
            time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .anyerr()?;
    let echo = tokio::spawn(async move {
        let conn = server.accept().await.anyerr()?.await.anyerr()?;
        let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
        let mut buf = [0u8; 8];
        while recv.read_exact(&mut buf).await.is_ok() {
            send.write_all(&buf).await.anyerr()?;
        }
        server.close().await;
        Ok::<_, n0_error::AnyError>(())
    });
    let conn = client.connect(addr, TEST_ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
    let mut n = 0u64;
    let mut round = async |send: &mut iroh::endpoint::SendStream, recv: &mut iroh::endpoint::RecvStream| -> Result<Duration> {
        n += 1;
        let at = time::Instant::now();
        send.write_all(&n.to_be_bytes()).await.anyerr()?;
        let mut buf = [0u8; 8];
        recv.read_exact(&mut buf).await.anyerr()?;
        Ok(at.elapsed())
    };
    round(&mut send, &mut recv).await?;
    let selected = |conn: &iroh::endpoint::Connection| conn.paths().iter().find(|p| p.is_selected()).map(|p| p.remote_addr().clone());
    // Both relays' paths up; the one the packets go through slowed from here on (not given up: still answering).
    let first = time::timeout(Duration::from_secs(20), async {
        loop {
            if conn.paths().iter().filter(|p| p.is_relay()).count() >= 2
                && let Some(TransportAddr::Relay(url)) = selected(&conn)
            {
                return url;
            }
            time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .anyerr()?;
    let (slowed, other) = if first == via_a { (&delay_a, via_b.clone()) } else { (&delay_b, via_a.clone()) };
    slowed.store(600, std::sync::atomic::Ordering::Relaxed);
    // A round trip through it is now 2.4 s and more (both legs, both ways), the other's some milliseconds: within a
    // few seconds the packets go through the other, and what is asked is answered quickly again.
    let slowed_at = time::Instant::now();
    let moved = time::timeout(Duration::from_secs(20), async {
        loop {
            let _ = round(&mut send, &mut recv).await;
            if selected(&conn) == Some(TransportAddr::Relay(other.clone())) {
                return slowed_at.elapsed();
            }
        }
    })
    .await;
    println!("EMBER-RESULT moved off the slow relay: {moved:?}");
    let moved = moved.anyerr()?;
    assert!(moved < Duration::from_secs(10), "{moved:?}");
    // What was in flight on the slow path comes in its time; then the rounds go at the other relay's pace.
    let mut last = Duration::MAX;
    for _ in 0..5 {
        last = round(&mut send, &mut recv).await?;
    }
    assert!(last < Duration::from_millis(500), "{last:?}");
    send.finish().anyerr()?;
    conn.close(0u8.into(), b"");
    client.close().await;
    let _ = echo.await;
    Ok(())
}

// A peer's selected path belongs to an older connection. Once it goes slow, a second
// connection must still reach the healthy relay, as a fresh endpoint can. Assert the
// route reached, not how long the machine took to complete the handshake.
#[tokio::test]
async fn new_connection_races_relays_despite_an_existing_selected_path() -> Result {
    let (_map_a, url_a, _relay_a) = run_relay_server_with(false).await?;
    let (_map_b, url_b, _relay_b) = run_relay_server_with(false).await?;
    let delay_a = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let delay_b = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let via_a = delayed_relay(&url_a, delay_a.clone()).await?;
    let via_b = delayed_relay(&url_b, delay_b.clone()).await?;
    let relays = RelayMap::from_iter([via_a.clone(), via_b.clone()]);
    let bind = || Endpoint::builder(presets::N0)
        .alpns(vec![TEST_ALPN.to_vec()])
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .relay_mode(RelayMode::Custom(relays.clone()))
        .home_on_every_relay().clear_ip_transports().bind();
    let server = bind().await?;
    let client = bind().await?;
    let fresh = bind().await?;
    for ep in [&server, &client, &fresh] {
        time::timeout(Duration::from_secs(10), async {
            loop {
                let status = ep.home_relay_status().get();
                if status.len() == 2 && status.iter().all(|s| s.is_connected()) { break; }
                time::sleep(Duration::from_millis(10)).await;
            }
        }).await.anyerr()?;
    }
    let accepting = server.clone();
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(incoming) = accepting.accept().await {
            held.push(incoming.await.unwrap());
        }
    });
    let addr = server.addr();
    let old = client.connect(addr.clone(), TEST_ALPN).await?;
    let selected = time::timeout(Duration::from_secs(10), async {
        loop {
            if old.paths().iter().filter(|p| p.is_relay()).count() >= 2 {
                if let Some(TransportAddr::Relay(url)) = old.paths().iter().find(|p| p.is_selected()).map(|p| p.remote_addr().clone()) { break url; }
            }
            time::sleep(Duration::from_millis(10)).await;
        }
    }).await.anyerr()?;
    let delayed = if selected == via_a { &delay_a } else { &delay_b };
    delayed.store(75, std::sync::atomic::Ordering::Relaxed);
    let begin = time::Instant::now();
    let (reused, clean) = tokio::join!(
        async { let c = client.connect(addr.clone(), TEST_ALPN).await?; Ok::<_, n0_error::AnyError>((begin.elapsed(), c)) },
        async { let c = fresh.connect(addr.clone(), TEST_ALPN).await?; Ok::<_, n0_error::AnyError>((begin.elapsed(), c)) },
    );
    let (reused_ms, reused) = reused?;
    let (clean_ms, clean) = clean?;
    println!("RELAY-HANDSHAKE selected={selected} reused={}ms fresh={}ms", reused_ms.as_millis(), clean_ms.as_millis());
    for (label, c) in [("old", &old), ("reused", &reused), ("fresh", &clean)] {
        for p in c.paths().iter() { println!("RELAY-HANDSHAKE {label} selected={} addr={:?} rtt={}ms", p.is_selected(), p.remote_addr(), p.stats().rtt.as_millis()); }
    }
    let healthy = if selected == via_a { via_b } else { via_a };
    assert!(
        reused.paths().iter().any(|p| p.remote_addr() == &TransportAddr::Relay(healthy.clone())),
        "the new handshake inherited the old slow path instead of reaching the healthy relay"
    );
    reused.close(0u8.into(), b"done"); clean.close(0u8.into(), b"done"); old.close(0u8.into(), b"done");
    client.close().await; fresh.close().await; server.close().await; task.abort();
    Ok(())
}
