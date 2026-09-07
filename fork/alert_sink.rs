// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
// MemGuard fork: push poison-write alerts to WeCom bot / Server酱.

//! AlertSink — batched alert notifier for poison-write detections.
//!
//! Dropped at the tail of the memwrite runner chain: it filters events whose
//! `data.poison` field was injected by PoisonAnalyzer, enqueues them, and a
//! background task flushes the pending window on a fixed interval (default
//! 10s), mirroring the original ebpf_memguard.py `Notifier`.
//!
//! Two channels:
//!   - WeCom (企业微信) bot webhook: JSON markdown POST.
//!   - ServerChan (Server酱): form-encoded GET `.send` API.
//!
//! `--alert-base` overrides the API host (dry-run echo endpoint for联调);
//! `--alert-dry-run` prints instead of sending. No new dependencies: reuses
//! the hyper client already used by the OTel sink.

use super::Analyzer;
use crate::event::Event;
use async_trait::async_trait;
use futures::stream::{Stream, StreamExt};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::{json, Value};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

type EventStream = Pin<Box<dyn Stream<Item = Event> + Send>>;

const WECOM_API: &str = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send";
const SERVERCHAN_API: &str = "https://sctapi.ftqq.com";
const DEFAULT_INTERVAL_SECS: u64 = 10;

/// A single poison alert waiting to be pushed.
#[derive(Debug, Clone)]
struct Alert {
    ts_ms: u64,
    severity: String,
    pid: u32,
    comm: String,
    file: String,
    signatures: String,
}

/// Channel + batching configuration.
#[derive(Debug, Clone)]
pub struct AlertConfig {
    wecom_key: Option<String>,
    serverchan_key: Option<String>,
    /// Override the API host for联调 echo endpoints.
    base: Option<String>,
    dry_run: bool,
    interval_secs: u64,
}

impl AlertConfig {
    pub fn new() -> Self {
        Self {
            wecom_key: None,
            serverchan_key: None,
            base: None,
            dry_run: false,
            interval_secs: DEFAULT_INTERVAL_SECS,
        }
    }

    pub fn wecom(mut self, key: impl Into<String>) -> Self {
        self.wecom_key = Some(key.into());
        self
    }

    pub fn serverchan(mut self, key: impl Into<String>) -> Self {
        self.serverchan_key = Some(key.into());
        self
    }

    pub fn base(mut self, url: impl Into<String>) -> Self {
        self.base = Some(url.into());
        self
    }

    pub fn dry_run(mut self, v: bool) -> Self {
        self.dry_run = v;
        self
    }

    pub fn interval_secs(mut self, secs: u64) -> Self {
        self.interval_secs = secs.max(1);
        self
    }

    pub fn enabled(&self) -> bool {
        self.dry_run || self.wecom_key.is_some() || self.serverchan_key.is_some()
    }
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Batched alert notifier (see module docs).
pub struct AlertSink {
    config: AlertConfig,
    sender: mpsc::UnboundedSender<Alert>,
    _handle: tokio::task::JoinHandle<()>,
}

impl AlertSink {
    /// Build the sink and spawn its background flusher.
    pub fn new(config: AlertConfig) -> Self {
        let (tx, rx) = mpsc::unbounded_channel::<Alert>();
        let client: Arc<
            Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
        > = Arc::new(Client::builder(TokioExecutor::new()).build_http());
        let cfg = config.clone();
        let handle = tokio::task::spawn(async move {
            run_flusher(rx, cfg, client).await;
        });
        Self {
            config,
            sender: tx,
            _handle: handle,
        }
    }

    fn push(&self, alert: Alert) {
        if !self.config.enabled() {
            return;
        }
        let _ = self.sender.send(alert);
    }
}

#[async_trait]
impl Analyzer for AlertSink {
    async fn process(
        &mut self,
        stream: EventStream,
    ) -> Result<EventStream, Box<dyn std::error::Error + Send + Sync>> {
        let sink = self.clone_for_stream();
        let scanned = stream.filter_map(move |ev| {
            let sink = sink.clone();
            async move {
                let Some(poison) = ev.data.get("poison") else {
                    return Some(ev);
                };
                let matched = poison
                    .get("matched")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let alert = Alert {
                    ts_ms: ev.timestamp,
                    severity: poison
                        .get("severity")
                        .and_then(|v| v.as_str())
                        .unwrap_or("HIGH")
                        .to_string(),
                    pid: ev.pid,
                    comm: ev.comm.clone(),
                    file: poison
                        .get("file")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    signatures: matched
                        .iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                };
                sink.push(alert);
                Some(ev)
            }
        });
        Ok(Box::pin(scanned))
    }
}

impl AlertSink {
    /// Cloneable per-event view of the sink (Arc'd sender + config).
    fn clone_for_stream(&self) -> StreamSink {
        StreamSink {
            sender: self.sender.clone(),
            config: self.config.clone(),
        }
    }
}

#[derive(Clone)]
struct StreamSink {
    sender: mpsc::UnboundedSender<Alert>,
    config: AlertConfig,
}

impl StreamSink {
    fn push(&self, alert: Alert) {
        if !self.config.enabled() {
            return;
        }
        let _ = self.sender.send(alert);
    }
}

/// Background flusher: batch alerts per interval window, push on tick, and
/// drain the last window when the channel closes.
async fn run_flusher(
    mut rx: mpsc::UnboundedReceiver<Alert>,
    config: AlertConfig,
    client: Arc<Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>>,
) {
    if !config.enabled() {
        // Drain and drop; nothing configured.
        while rx.recv().await.is_some() {}
        return;
    }
    let mut pending: Vec<Alert> = Vec::new();
    let mut tick = tokio::time::interval(Duration::from_secs(config.interval_secs));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if !pending.is_empty() {
                    flush_alerts(&client, &config, &pending).await;
                    pending.clear();
                }
            }
            alert = rx.recv() => {
                match alert {
                    Some(a) => pending.push(a),
                    None => {
                        // Channel closed: drain buffered alerts, then exit.
                        while let Ok(a) = rx.try_recv() {
                            pending.push(a);
                        }
                        if !pending.is_empty() {
                            flush_alerts(&client, &config, &pending).await;
                        }
                        break;
                    }
                }
            }
        }
    }
}

fn format_ts(ts_ms: u64) -> String {
    if let Some(dt) = chrono::DateTime::from_timestamp_millis(ts_ms as i64) {
        dt.format("%H:%M:%S").to_string()
    } else {
        "??:??:??".to_string()
    }
}

fn build_title(pending: &[Alert]) -> String {
    format!(
        "MemGuard 告警 {}条 「记忆库写入×{}」",
        pending.len(),
        pending.len()
    )
}

fn build_body(pending: &[Alert]) -> String {
    let mut lines = Vec::new();
    for a in pending {
        lines.push(format!(
            "[{}] {} pid={} comm={} file={} sig={}",
            format_ts(a.ts_ms),
            a.severity,
            a.pid,
            a.comm,
            a.file,
            a.signatures
        ));
    }
    lines.join("\n")
}

/// Rewrite an API URL against the联调 base override (mirrors the Python
/// `_url()` helper: `base.rstrip('/') + '/' + api_no_scheme`).
fn override_url(base: &str, api: &str, suffix: &str) -> String {
    let no_scheme = api.split_once("//").map(|(_, rest)| rest).unwrap_or(api);
    format!("{}/{}{}", base.trim_end_matches('/'), no_scheme, suffix)
}

async fn flush_alerts(
    client: &Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
    config: &AlertConfig,
    pending: &[Alert],
) {
    let title = build_title(pending);
    let body = build_body(pending);

    if config.dry_run {
        log::warn!(
            "[MemGuard][dry-run] {}\n---\n{}",
            title,
            body
        );
        return;
    }

    // WeCom: markdown JSON POST.
    if let Some(key) = &config.wecom_key {
        let suffix = format!("?key={}", key);
        let url = match &config.base {
            Some(b) => override_url(b, WECOM_API, &suffix),
            None => format!("{}{}", WECOM_API, suffix),
        };
        let payload = json!({
            "msgtype": "markdown",
            "markdown": { "content": format!("**{}**\n{}", title, body) },
        });
        post_json(client, "wecom", &url, payload).await;
    }

    // ServerChan: form-encoded GET .send.
    if let Some(key) = &config.serverchan_key {
        let suffix = format!("/{}.send", key);
        let url = match &config.base {
            Some(b) => override_url(b, SERVERCHAN_API, &suffix),
            None => format!("{}{}", SERVERCHAN_API, suffix),
        };
        let params = format!("?title={}&desp={}", urlencode(&title), urlencode(&body));
        get_url(client, "serverchan", &format!("{}{}", url, params)).await;
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

async fn post_json(
    client: &Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
    channel: &str,
    url: &str,
    payload: Value,
) {
    let body = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(e) => {
            log::error!("[MemGuard][{}] serialize failed: {}", channel, e);
            return;
        }
    };
    let req = Request::builder()
        .method(hyper::Method::POST)
        .uri(url)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)));
    let Ok(req) = req else {
        log::error!("[MemGuard][{}] bad request: {}", channel, url);
        return;
    };
    match client.request(req).await {
        Ok(resp) => {
            let status = resp.status();
            log::info!("[MemGuard][{}] pushed -> {} (HTTP {})", channel, url, status);
        }
        Err(e) => log::error!("[MemGuard][{}] push failed: {}", channel, e),
    }
}

async fn get_url(
    client: &Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
    channel: &str,
    url: &str,
) {
    let req = Request::builder()
        .method(hyper::Method::GET)
        .uri(url)
        .body(Full::new(Bytes::new()));
    let Ok(req) = req else {
        log::error!("[MemGuard][{}] bad request: {}", channel, url);
        return;
    };
    match client.request(req).await {
        Ok(resp) => {
            let status = resp.status();
            log::info!("[MemGuard][{}] pushed -> {} (HTTP {})", channel, url, status);
        }
        Err(e) => log::error!("[MemGuard][{}] push failed: {}", channel, e),
    }
}