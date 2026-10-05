//! Relay embedding with policy-aware traffic shaping (Gates A–C).
//!
//! Pattern follows upstream `iroh-relay/tests/relay_axum.rs` using only
//! public APIs: custom WebSocket adapter -> `handshake::serverside` ->
//! `authorize_with` -> `RelayedStream::new` -> `Config::new` ->
//! `Clients::register`.
//!
//! Differences from the test: honest subprotocol negotiation (V2 preferred,
//! V1 supported), handshake timeout, bounded handshake concurrency, pluggable
//! `AccessControl`, and (Gate C) shared per-endpoint directional buckets.
//! Handshake traffic flows unthrottled; shaping engages after authorization.

use std::{
    future::Future as _,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration as StdDuration,
};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        FromRequestParts, State,
    },
    http::{HeaderValue, StatusCode},
    response::Response,
    routing::get,
    Router,
};
use bytes::Bytes;
use iroh_relay::{
    http::{ProtocolVersion, CLIENT_AUTH_HEADER, RELAY_PATH, RELAY_PROBE_PATH},
    protos::{handshake, streams::StreamError},
    server::{
        client::Config as ClientConfig, clients::Clients, streams::RelayedStream, DynAccessControl,
    },
    ExportKeyingMaterial, KeyCache,
};
use n0_error::AnyError;
use n0_future::{task::AbortOnDropHandle, Sink, Stream};
use tokio::{net::TcpListener, sync::Semaphore};
use tracing::{debug, warn};

use crate::{
    limiter::{EndpointLimiter, LimiterMap},
    quota::{AcquireReply, QuotaClient},
};

/// Shared relay state. One `Clients` registry for all endpoints.
#[derive(Clone)]
pub struct RelayState {
    pub key_cache: KeyCache,
    pub access: Arc<dyn DynAccessControl>,
    pub metrics: Arc<iroh_relay::server::Metrics>,
    pub clients: Clients,
    pub handshake_semaphore: Arc<Semaphore>,
    pub handshake_timeout: StdDuration,
    /// Present when admission is policy-backed (Gate B+); used for
    /// post-register revalidation to close the revoke race.
    pub policy: Option<Arc<crate::policy::PolicyManager>>,
    /// Present when throughput enforcement is enabled (Gate C+).
    pub limiter: Option<Arc<LimiterMap>>,
    /// Present when the monthly budget gate is enabled (Gate D+).
    /// `None` preserves Gate A–C passthrough (no budget configured).
    pub quota: Option<QuotaClient>,
    /// Global concurrent-connection ceiling (Gate E). Permits are held by
    /// connection adapters for the connection lifetime. `None` = unbounded.
    pub conn_permits: Option<Arc<tokio::sync::Semaphore>>,
}

impl RelayState {
    pub fn new(
        access: Arc<dyn DynAccessControl>,
        key_cache_capacity: usize,
        max_handshake_concurrency: usize,
        handshake_timeout: StdDuration,
    ) -> Self {
        Self {
            key_cache: KeyCache::new(key_cache_capacity),
            access,
            metrics: Arc::new(iroh_relay::server::Metrics::default()),
            clients: Clients::default(),
            handshake_semaphore: Arc::new(Semaphore::new(max_handshake_concurrency)),
            handshake_timeout,
            policy: None,
            limiter: None,
            quota: None,
            conn_permits: None,
        }
    }

    pub fn with_policy(mut self, policy: Arc<crate::policy::PolicyManager>) -> Self {
        policy.set_clients(self.clients.clone());
        self.policy = Some(policy.clone());
        self.access = policy as Arc<dyn DynAccessControl>;
        self
    }

    pub fn with_limiter(mut self, limiter: Arc<LimiterMap>) -> Self {
        self.limiter = Some(limiter);
        self
    }

    pub fn with_quota(mut self, quota: QuotaClient) -> Self {
        self.quota = Some(quota);
        self
    }

    pub fn with_connection_limit(mut self, max: usize) -> Self {
        self.conn_permits = Some(Arc::new(tokio::sync::Semaphore::new(max.max(1))));
        self
    }
}

/// Pick the best supported subprotocol from the client's offer.
///
/// Returns `None` when the client offered no supported version.
fn negotiate_version(offered: Option<&HeaderValue>) -> Option<ProtocolVersion> {
    let header = offered?.to_str().ok()?;
    let mut has_v1 = false;
    let mut has_v2 = false;
    for token in header.split(',') {
        match token.trim() {
            "iroh-relay-v2" => has_v2 = true,
            "iroh-relay-v1" => has_v1 = true,
            _ => {}
        }
    }
    if has_v2 {
        Some(ProtocolVersion::V2)
    } else if has_v1 {
        Some(ProtocolVersion::V1)
    } else {
        None
    }
}

async fn serve_inner(
    listener: TcpListener,
    state: RelayState,
) -> n0_error::Result<AbortOnDropHandle<()>> {
    let router = Router::new()
        .route(RELAY_PATH, get(relay_handler))
        .route(RELAY_PROBE_PATH, get(ping_handler))
        .route("/healthz", get(health_handler))
        .route("/", get(root_handler))
        .with_state(state);
    let task = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router.into_make_service()).await {
            warn!("axum serve error: {e:#}");
        }
    });
    Ok(AbortOnDropHandle::new(task))
}

/// Bind loopback (or configured) address and serve. Returns bound addr + task.
pub async fn serve(
    bind: SocketAddr,
    state: RelayState,
) -> n0_error::Result<(SocketAddr, AbortOnDropHandle<()>)> {
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let handle = serve_inner(listener, state).await?;
    Ok((addr, handle))
}

async fn root_handler() -> &'static str {
    "relay-warden"
}

async fn ping_handler() -> impl axum::response::IntoResponse {
    (
        StatusCode::OK,
        [(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
    )
}

async fn health_handler() -> impl axum::response::IntoResponse {
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "relay-warden",
    }))
}

async fn relay_handler(
    State(state): State<RelayState>,
    request: axum::extract::Request,
) -> Result<Response, StatusCode> {
    let (mut parts, _body) = request.into_parts();
    let offered = parts
        .headers
        .get(axum::http::header::SEC_WEBSOCKET_PROTOCOL)
        .cloned();
    let Some(version) = negotiate_version(offered.as_ref()) else {
        warn!("unsupported or missing relay subprotocol");
        return Err(StatusCode::BAD_REQUEST);
    };
    let client_auth_header = parts.headers.get(CLIENT_AUTH_HEADER).cloned();
    let ws = WebSocketUpgrade::from_request_parts(&mut parts, &state)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    // Echo back only the negotiated version.
    let ws = ws.protocols([version.to_str()]);
    Ok(ws.on_upgrade(move |socket| async move {
        // Bound unauthenticated work.
        let _permit = match state.handshake_semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!("handshake concurrency exhausted, rejecting");
                return;
            }
        };
        let timeout = state.handshake_timeout;
        let fut = handle_relay_websocket(socket, state, parts, client_auth_header, version);
        match tokio::time::timeout(timeout, fut).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!("relay websocket error: {e:#}"),
            Err(_) => warn!("handshake timed out"),
        }
    }))
}

async fn handle_relay_websocket(
    socket: WebSocket,
    state: RelayState,
    request_parts: http::request::Parts,
    client_auth_header: Option<HeaderValue>,
    version: ProtocolVersion,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut adapter = AxumWebSocketAdapter::new(socket, state.quota.clone());
    let authentication = handshake::serverside(&mut adapter, client_auth_header).await?;
    debug!(?authentication.mechanism, version = ?version, "authenticated");
    let client_key = authentication.client_key;

    let request = iroh_relay::server::ClientRequest::new(client_key, version, request_parts);
    let guard = authentication
        .authorize_with(&request, &state.access, &mut adapter)
        .await?;
    debug!("authorized");

    // Global connection ceiling (Gate E): the permit lives in the adapter,
    // so it is held for the whole connection and released on disconnect.
    // The authorization guard drops here on denial, keeping live counters
    // balanced.
    if let Some(sem) = &state.conn_permits {
        match sem.clone().try_acquire_owned() {
            Ok(p) => adapter.hold_permit(p),
            Err(_) => {
                warn!("connection ceiling reached, rejecting");
                return Err("too many connections".into());
            }
        }
    }

    // Engage shaping after authorization: handshake traffic stays unthrottled.
    // The limiter is shared across all connections of this endpoint.
    if let (Some(policy), Some(limiter)) = (&state.policy, &state.limiter) {
        let id = client_key.to_string();
        let record = policy.get(&id);
        let defaults = policy.defaults_snapshot();
        let lim = limiter.get_or_create(&id, record.as_ref(), &defaults, std::time::Instant::now());
        adapter.set_limiter(lim);
    }

    let stream = RelayedStream::new(adapter, state.key_cache.clone());
    let endpoint = guard.endpoint_id();
    let config = ClientConfig::new(guard, stream, version);
    state.clients.register(config, state.metrics.clone());
    // Close the revoke race: a revoke published between on_connect and
    // register must still kill this connection. Either this revalidation or
    // the revoke-path disconnect lands after the race window.
    if let Some(policy) = &state.policy {
        policy.revalidate(&endpoint);
    }
    Ok(())
}

static NEXT_WAIT_ID: AtomicU64 = AtomicU64::new(1);

/// Direction for throttle gating.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Rx,
    Tx,
}

/// Bridges axum's [`WebSocket`] to upstream's `Bytes` stream/sink contract.
///
/// Binary messages are relay frames. Control/close handling mirrors the
/// upstream embedding test: text/ping/pong are skipped, close ends stream.
///
/// Gate C shaping: each direction shares its endpoint bucket. Gating peeks
/// (`check_*`, never deducting); the single deduct happens exactly once per
/// delivered frame (`consume_*` in `poll_next`/`start_send`). Polls, retries,
/// and flushes never touch balances, so double-charging is impossible by
/// construction. At most one frame is buffered per direction.
struct AxumWebSocketAdapter {
    inner: Pin<Box<WebSocket>>,
    limiter: Option<Arc<EndpointLimiter>>,
    quota: Option<QuotaClient>,
    /// False during the handshake (unthrottled, uncounted); enabled after authorization.
    throttling: bool,
    wait_id: u64,
    rx_sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    tx_sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    rx_wait_start: Option<std::time::Instant>,
    tx_wait_start: Option<std::time::Instant>,
    /// Quota lease balance in charged bytes (may go negative = bounded debt).
    quota_lease: i64,
    quota_gen: u64,
    quota_pending: Option<tokio::sync::oneshot::Receiver<AcquireReply>>,
    quota_sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    /// Global connection permit, held for the connection lifetime (Gate E).
    #[allow(dead_code)]
    conn_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl AxumWebSocketAdapter {
    fn set_limiter(&mut self, limiter: Arc<EndpointLimiter>) {
        self.limiter = Some(limiter);
        self.throttling = true;
    }

    /// Gate one direction. Peeks only; deducts happen in `poll_next` /
    /// `start_send`. Returns `Ready` when the frame may proceed.
    fn poll_gate(&mut self, cx: &mut Context<'_>, dir: Direction) -> Poll<()> {
        let Some(lim) = self.limiter.clone() else {
            return Poll::Ready(());
        };
        if !self.throttling {
            return Poll::Ready(());
        }
        let (sleep_slot, wait_start) = match dir {
            Direction::Rx => (&mut self.rx_sleep, &mut self.rx_wait_start),
            Direction::Tx => (&mut self.tx_sleep, &mut self.tx_wait_start),
        };
        loop {
            let now = std::time::Instant::now();
            let wait = match dir {
                Direction::Rx => lim.check_rx(now),
                Direction::Tx => lim.check_tx(now),
            };
            let Some(d) = wait else {
                *sleep_slot = None;
                lim.unsubscribe(self.wait_id);
                return Poll::Ready(());
            };
            if wait_start.is_none() {
                *wait_start = Some(now);
            }
            lim.subscribe(self.wait_id, cx.waker().clone());
            let deadline = tokio::time::Instant::now() + d;
            *sleep_slot = Some(Box::pin(tokio::time::sleep_until(deadline)));
            if sleep_slot
                .as_mut()
                .expect("armed")
                .as_mut()
                .poll(cx)
                .is_ready()
            {
                *sleep_slot = None;
                continue; // Timer fired: recheck the bucket.
            }
            return Poll::Pending;
        }
    }

    /// Gate outbound frames on the monthly budget (Gate D).
    ///
    /// Spends from a chunk lease granted by the quota actor (durable before
    /// spend). Refills request the next chunk asynchronously; exhaustion parks
    /// here until the global disconnect drops the connection.
    fn poll_quota(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let Some(q) = self.quota.clone() else {
            return Poll::Ready(());
        };
        if !self.throttling {
            return Poll::Ready(());
        }
        loop {
            if q.exhausted() {
                // Parked: exhaustion disconnects all connections, which drops
                // this adapter. Never fail the send; the disconnect is the
                // termination signal.
                return Poll::Pending;
            }
            if q.generation() != self.quota_gen {
                // New month: discard the old lease (its charge stays in the
                // old period: conservative) and re-request under the new one.
                self.quota_lease = 0;
                self.quota_gen = q.generation();
                self.quota_pending = None;
            }
            if self.quota_lease > 0 {
                self.quota_sleep = None;
                return Poll::Ready(());
            }
            if let Some(rx) = self.quota_pending.as_mut() {
                match Pin::new(rx).poll(cx) {
                    Poll::Ready(Ok(AcquireReply::Granted { bytes, generation })) => {
                        self.quota_pending = None;
                        if generation == self.quota_gen {
                            self.quota_lease += bytes as i64;
                        }
                        continue;
                    }
                    Poll::Ready(_) => {
                        // Denied (exhaustion landed) or actor gone: recheck.
                        self.quota_pending = None;
                        continue;
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            match q.try_acquire() {
                Some(rx) => {
                    self.quota_pending = Some(rx);
                    continue;
                }
                None => {
                    // Request channel momentarily full (actor drains fast):
                    // retry on a short timer via the existing wake loop.
                    let deadline = tokio::time::Instant::now() + StdDuration::from_millis(10);
                    self.quota_sleep = Some(Box::pin(tokio::time::sleep_until(deadline)));
                    if self
                        .quota_sleep
                        .as_mut()
                        .expect("armed")
                        .as_mut()
                        .poll(cx)
                        .is_ready()
                    {
                        self.quota_sleep = None;
                        continue;
                    }
                    return Poll::Pending;
                }
            }
        }
    }

    /// Attribute observed throttle delay to the just-admitted frame.
    fn take_waited_ms(&mut self, dir: Direction) -> (bool, u64) {
        let slot = match dir {
            Direction::Rx => &mut self.rx_wait_start,
            Direction::Tx => &mut self.tx_wait_start,
        };
        match slot.take() {
            Some(t) => (true, t.elapsed().as_millis() as u64),
            None => (false, 0),
        }
    }
}

impl Drop for AxumWebSocketAdapter {
    fn drop(&mut self) {
        if let Some(lim) = &self.limiter {
            lim.unsubscribe(self.wait_id);
        }
        // Hand back the proven-unspent lease remainder. Best effort: if the
        // actor is gone the bytes stay charged (conservative, fail-closed).
        if let Some(q) = &self.quota {
            if self.quota_lease > 0 {
                q.return_unused(self.quota_lease as u64);
            }
        }
    }
}

impl AxumWebSocketAdapter {
    fn new(socket: WebSocket, quota: Option<QuotaClient>) -> Self {
        Self {
            inner: Box::pin(socket),
            limiter: None,
            quota,
            throttling: false,
            wait_id: NEXT_WAIT_ID.fetch_add(1, Ordering::Relaxed),
            rx_sleep: None,
            tx_sleep: None,
            rx_wait_start: None,
            tx_wait_start: None,
            quota_lease: 0,
            quota_gen: 0,
            quota_pending: None,
            quota_sleep: None,
            conn_permit: None,
        }
    }

    fn hold_permit(&mut self, permit: tokio::sync::OwnedSemaphorePermit) {
        self.conn_permit = Some(permit);
    }
}

impl Stream for AxumWebSocketAdapter {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Gate first: do not read from the network while overdrawn, so
        // backpressure reaches the sender. At most one frame is buffered.
        if self.throttling && self.poll_gate(cx, Direction::Rx).is_pending() {
            return Poll::Pending;
        }
        let frame = loop {
            match self.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(data)))) => break data,
                Poll::Ready(Some(Ok(Message::Close(_)))) => return Poll::Ready(None),
                Poll::Ready(Some(Ok(_))) => continue,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(AnyError::from_std(e)))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            };
        };
        // Deduct exactly once per delivered frame. Polls/retries never deduct.
        if self.throttling {
            if let Some(lim) = self.limiter.clone() {
                let (waited, waited_ms) = self.take_waited_ms(Direction::Rx);
                let _debt = lim.consume_rx(frame.len(), std::time::Instant::now());
                if waited {
                    lim.record_throttled(frame.len(), waited_ms);
                }
            }
        }
        Poll::Ready(Some(Ok(frame)))
    }
}

impl Sink<Bytes> for AxumWebSocketAdapter {
    type Error = StreamError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Gate delivery while overdrawn. Size is unknown here, so this peeks
        // only; the single deduct happens in `start_send`.
        if self.throttling && self.poll_gate(cx, Direction::Tx).is_pending() {
            return Poll::Pending;
        }
        // Budget gate: spend from the chunk lease (refills asynchronously).
        if self.throttling && self.poll_quota(cx).is_pending() {
            return Poll::Pending;
        }
        self.inner
            .as_mut()
            .poll_ready(cx)
            .map_err(AnyError::from_std)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        // Deduct exactly once per forwarded frame (never on flush/retry).
        if self.throttling {
            if let Some(lim) = self.limiter.clone() {
                let (waited, waited_ms) = self.take_waited_ms(Direction::Tx);
                let _debt = lim.consume_tx(item.len(), std::time::Instant::now());
                if waited {
                    lim.record_throttled(item.len(), waited_ms);
                }
            }
            if let Some(q) = self.quota.clone() {
                // Charged bytes leave the lease (bounded debt allowed, as
                // with the throughput buckets). The grant was already
                // committed durably; this frame was admitted by it.
                self.quota_lease -= q.charge_for(item.len()) as i64;
                // Top up proactively so the next frame rarely waits for a
                // round trip. At most one refill is outstanding.
                if self.quota_lease <= 0 && self.quota_pending.is_none() {
                    if let Some(rx) = q.try_acquire() {
                        self.quota_pending = Some(rx);
                    }
                }
            }
        }
        self.inner
            .as_mut()
            .start_send(Message::Binary(item))
            .map_err(AnyError::from_std)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .as_mut()
            .poll_flush(cx)
            .map_err(AnyError::from_std)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .as_mut()
            .poll_close(cx)
            .map_err(AnyError::from_std)
    }
}

// Behind a reverse proxy (or plain loopback HTTP) there is no TLS exporter
// material, so we return None and use the signed-challenge fallback — same as
// the upstream embedding example. Do not invent keying material.
impl ExportKeyingMaterial for AxumWebSocketAdapter {
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        _output: T,
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> Option<T> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::negotiate_version;
    use axum::http::HeaderValue;
    use iroh_relay::http::ProtocolVersion;

    #[test]
    fn negotiates_v2_preferred() {
        let h = HeaderValue::from_static("iroh-relay-v1, iroh-relay-v2");
        assert_eq!(negotiate_version(Some(&h)), Some(ProtocolVersion::V2));
    }

    #[test]
    fn negotiates_v1_only() {
        let h = HeaderValue::from_static("iroh-relay-v1");
        assert_eq!(negotiate_version(Some(&h)), Some(ProtocolVersion::V1));
    }

    #[test]
    fn rejects_unknown() {
        let h = HeaderValue::from_static("mqtt");
        assert_eq!(negotiate_version(Some(&h)), None);
        assert_eq!(negotiate_version(None), None);
    }
}
