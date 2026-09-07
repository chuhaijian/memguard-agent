// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
// MemGuard fork: LLM memory-store poison write detection (FARMA/MINJA).

//! PoisonAnalyzer — detects writes that carry memory-poisoning signatures
//! (see POISON_SIGNATURES) in the memwrite event stream.
//!
//! Detection has two layers:
//!   1. Window scan: match the kernel-captured head/tail payload windows.
//!   2. Filesystem compensation: SQLite writes whole 4096B pages whose cell
//!      content sits outside the head/tail windows, so the analyzer re-reads
//!      the written byte range `[offset, offset+count]` from disk and scans
//!      it in full. Poison text reliably lands in the written page range.
//!
//! Hits are injected into `Event.data["poison"] = { matched, severity, file }`
//! and logged at WARN; non-hit events pass through untouched.

use super::Analyzer;
use crate::event::Event;
use async_trait::async_trait;
use futures::stream::{Stream, StreamExt};
use serde_json::{json, Value};
use std::pin::Pin;

type EventStream = Pin<Box<dyn Stream<Item = Event> + Send>>;

/// Memory-poisoning signatures, carried over from ebpf_memguard.py
/// (POISON_SIGNATURES, 15 entries — zh/en). Lower-cased at match time so
/// ASCII signatures are case-insensitive.
pub const POISON_SIGNATURES: [&str; 15] = [
    "免验证",
    "无需验证",
    "可直接导入",
    "已通过安全审查",
    "可信来源",
    "预批准",
    "trusted source",
    "pre-approved",
    "preapproved",
    "without validation",
    "skip validation",
    "no validation",
    "bypass validation",
    "auto import",
    "import directly",
];

/// A memory-store write event is considered poison-positive when this many
/// distinct signatures match (currently unused; kept for tuning).
const _CRITICAL_SEVERITY_THRESHOLD: usize = 3;

pub struct PoisonAnalyzer {
    /// Memory-store filename prefix this analyzer watches (for the fs
    /// compensation path, we only re-read files whose name contains it).
    prefix: String,
}

impl PoisonAnalyzer {
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
        }
    }

    /// Scan the kernel-captured head/tail windows for signatures.
    fn scan_windows(head: Option<&str>, tail: Option<&str>) -> Vec<String> {
        let mut matched: Vec<String> = Vec::new();
        for sig in POISON_SIGNATURES {
            let needle = sig.to_lowercase();
            let hit = head
                .map(|h| h.to_lowercase().contains(&needle))
                .unwrap_or(false)
                || tail
                    .map(|t| t.to_lowercase().contains(&needle))
                    .unwrap_or(false);
            if hit {
                matched.push(sig.to_string());
            }
        }
        matched
    }

    /// Filesystem compensation: re-read the written byte range and scan it.
    /// The write is a full SQLite page, so the poison cell is inside it.
    /// Bounds the read to 4 MiB to stay cheap on huge stores.
    async fn scan_file_range(path: &str, offset: u64, count: u64) -> Vec<String> {
        const MAX_SCAN: u64 = 4 * 1024 * 1024;
        let Ok(data) = tokio::fs::read(path).await else {
            return Vec::new();
        };
        let len = data.len() as u64;
        let start = offset.min(len) as usize;
        let end = offset
            .saturating_add(count.min(MAX_SCAN))
            .min(len) as usize;
        if start >= end {
            return Vec::new();
        }
        let chunk = String::from_utf8_lossy(&data[start..end]).to_lowercase();
        let mut matched: Vec<String> = Vec::new();
        for sig in POISON_SIGNATURES {
            if chunk.contains(&sig.to_lowercase()) {
                matched.push(sig.to_string());
            }
        }
        matched
    }

    fn severity(matched: &[String]) -> &'static str {
        if matched.len() >= _CRITICAL_SEVERITY_THRESHOLD {
            "CRITICAL"
        } else {
            "HIGH"
        }
    }
}

#[async_trait]
impl Analyzer for PoisonAnalyzer {
    async fn process(
        &mut self,
        stream: EventStream,
    ) -> Result<EventStream, Box<dyn std::error::Error + Send + Sync>> {
        let prefix = self.prefix.clone();
        let scanned = stream.filter_map(move |mut ev| {
            let prefix = prefix.clone();
            async move {
                // Only memwrite MEM_WRITE events carry a memory-store write.
                let is_mem_write = ev.source == "memwrite"
                    && ev.data.get("event").and_then(|v| v.as_str()) == Some("MEM_WRITE");
                if !is_mem_write {
                    return Some(ev);
                }

                let head = ev.data.get("head").and_then(|v| v.as_str());
                let tail = ev.data.get("tail").and_then(|v| v.as_str());
                let mut matched = PoisonAnalyzer::scan_windows(head, tail);

                // Window miss -> filesystem compensation on the written range.
                if matched.is_empty() {
                    if let (Some(path), Some(offset), Some(count)) = (
                        ev.data.get("path").and_then(|v| v.as_str()),
                        ev.data.get("offset").and_then(|v| v.as_u64()),
                        ev.data.get("count").and_then(|v| v.as_u64()),
                    ) {
                        if prefix.is_empty() || path.contains(&prefix) {
                            matched =
                                PoisonAnalyzer::scan_file_range(path, offset, count).await;
                        }
                    }
                }

                if !matched.is_empty() {
                    let file = ev
                        .data
                        .get("path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let poison: Value = json!({
                        "matched": matched,
                        "severity": PoisonAnalyzer::severity(&matched),
                        "file": file,
                    });
                    if let Some(obj) = ev.data.as_object_mut() {
                        obj.insert("poison".to_string(), poison);
                    }
                    log::warn!(
                        "[MemGuard] poison write detected: pid={} comm={} file={} signatures={}",
                        ev.pid,
                        ev.comm,
                        file,
                        matched.join(",")
                    );
                }
                Some(ev)
            }
        });
        Ok(Box::pin(scanned))
    }
}