// Copyright 2026 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! `subscription.rs` for the browser: the same types, the same calls, so the
//! Pub/Sub, keyspace-notification and `MONITOR` panels keep their loops.
//!
//! A page cannot hold a socket the server pushes on. The bridge holds it
//! instead (`/v1/watch`, the bridge's `watch.rs`) and buffers what arrives,
//! and these ask for it a batch at a time with a request that waits until
//! something has come. A batch is handed out an item per call, as the
//! desktop's connection hands out a message per call. Dropping the value
//! tells the bridge to let go — and if the page is gone before it can, the
//! bridge lets go of a watch nobody polls by itself.

use crate::bridge::{BridgeTransport, WatchBatch, WatchItem, WatchKind, bridge_transport};
use crate::error::Error;
use crate::server_db::ServerDb;
use futures::StreamExt;
use futures::channel::mpsc::{TryRecvError, UnboundedReceiver, UnboundedSender, unbounded};
use futures::future::{Either, select};
use futures::lock::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, PoisonError};

type Result<T, E = Error> = std::result::Result<T, E>;

/// One message as it arrived: the channel it was published to (not the
/// pattern that matched it) and the payload's bytes, undecoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelMessage {
    pub channel: String,
    pub payload: Vec<u8>,
}

/// Which Pub/Sub a subscription speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscribeKind {
    /// Classic, by pattern (`PSUBSCRIBE`).
    Patterns,
    /// Sharded (`SSUBSCRIBE`, Redis 7+).
    Sharded,
    /// Keyspace notifications, on every master.
    KeyspaceEvents,
}

impl SubscribeKind {
    fn watch_kind(self) -> WatchKind {
        match self {
            Self::Patterns => WatchKind::Patterns,
            Self::Sharded => WatchKind::Sharded,
            Self::KeyspaceEvents => WatchKind::KeyspaceEvents,
        }
    }
}

fn transport() -> Result<Arc<dyn BridgeTransport>> {
    bridge_transport().ok_or_else(|| Error::Invalid {
        message: "no bridge transport".to_string(),
    })
}

fn bridge_error(e: crate::bridge::BridgeError) -> Error {
    Error::Redis { source: e.into() }
}

/// The bridge's watch, let go of when the last holder is dropped.
struct Watch {
    transport: Arc<dyn BridgeTransport>,
    token: String,
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.transport.release_watch(self.token.clone());
    }
}

/// A live subscription. Drop it to unsubscribe.
pub struct ChannelSubscription {
    watch: Watch,
    pending: VecDeque<ChannelMessage>,
    ended: bool,
}

impl ChannelSubscription {
    /// Have the bridge subscribe for this page. Pub/Sub has no databases;
    /// `at` names the server.
    pub async fn open(at: &ServerDb, kind: SubscribeKind, channels: &[&str]) -> Result<Self> {
        let transport = transport()?;
        let opened = transport
            .open_watch(
                at.server_id().to_string(),
                at.db(),
                kind.watch_kind(),
                channels.iter().map(|c| c.to_string()).collect(),
                None,
            )
            .await
            .map_err(bridge_error)?;
        Ok(Self {
            watch: Watch {
                transport,
                token: opened.token,
            },
            pending: VecDeque::new(),
            ended: false,
        })
    }

    /// The next message; `None` once the subscription is gone.
    pub async fn next_message(&mut self) -> Option<ChannelMessage> {
        loop {
            if let Some(message) = self.pending.pop_front() {
                return Some(message);
            }
            if self.ended {
                return None;
            }
            // A poll the bridge could not answer is a link that went: the
            // panel ends its loop, as it does when a socket closes.
            let batch = self.watch.transport.poll_watch(self.watch.token.clone()).await.ok()?;
            self.ended = batch.closed.is_some();
            self.pending
                .extend(batch.items.into_iter().filter_map(|item| match item {
                    WatchItem::Message { channel, payload } => Some(ChannelMessage { channel, payload }),
                    WatchItem::Line { .. } => None,
                }));
        }
    }
}

/// What every feed of one `MONITOR` shares: one watch on the bridge for all
/// the masters, and a queue per node to deal its lines into.
struct Lines {
    watch: Watch,
    by_node: std::sync::Mutex<HashMap<String, UnboundedSender<String>>>,
    /// Who polls next. One poll at a time serves every feed: whichever
    /// feed finds its queue empty takes the turn, unless its lines arrive
    /// first — so a feed is never kept waiting on a node that is quiet.
    turn: Mutex<()>,
}

impl Lines {
    /// Deal a batch out; an ended watch closes every queue.
    fn deal(&self, batch: Option<WatchBatch>) {
        let mut by_node = self.by_node.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(batch) = batch else {
            by_node.clear();
            return;
        };
        for item in batch.items {
            if let WatchItem::Line { node, line } = item
                && let Some(queue) = by_node.get(&node)
            {
                let _ = queue.unbounded_send(line);
            }
        }
        if batch.closed.is_some() {
            by_node.clear();
        }
    }
}

/// The `MONITOR` feed of one node.
pub struct MonitorFeed {
    node: String,
    queue: UnboundedReceiver<String>,
    lines: Arc<Lines>,
}

impl MonitorFeed {
    /// The node it watches, as `host:port`.
    pub fn node(&self) -> &str {
        &self.node
    }

    /// The next line as the server wrote it; `None` once the watch is gone.
    pub async fn next_line(&mut self) -> Option<String> {
        loop {
            match self.queue.try_recv() {
                Ok(line) => return Some(line),
                Err(TryRecvError::Closed) => return None,
                Err(TryRecvError::Empty) => {}
            }
            let next = self.queue.next();
            let turn = self.lines.turn.lock();
            futures::pin_mut!(next, turn);
            let _turn = match select(next, turn).await {
                Either::Left((line, _)) => return line,
                Either::Right((turn, _)) => turn,
            };
            // A poll the bridge could not answer is a link that went.
            let batch = self
                .lines
                .watch
                .transport
                .poll_watch(self.lines.watch.token.clone())
                .await
                .ok();
            self.lines.deal(batch);
        }
    }
}

/// One feed per master and, by node, the ones that could not be opened.
pub struct MonitorFeeds {
    pub feeds: Vec<MonitorFeed>,
    pub failures: Vec<(String, Error)>,
}

/// Have the bridge start `MONITOR` on every master of the server.
pub async fn open_monitor_feeds(at: &ServerDb) -> Result<MonitorFeeds> {
    let transport = transport()?;
    let opened = transport
        .open_watch(
            at.server_id().to_string(),
            at.db(),
            WatchKind::Monitor,
            Vec::new(),
            at.confirmation().map(str::to_string),
        )
        .await
        .map_err(bridge_error)?;
    let mut by_node = HashMap::new();
    let mut queues = Vec::with_capacity(opened.nodes.len());
    for node in opened.nodes {
        let (sender, queue) = unbounded();
        by_node.insert(node.clone(), sender);
        queues.push((node, queue));
    }
    let lines = Arc::new(Lines {
        watch: Watch {
            transport,
            token: opened.token,
        },
        by_node: std::sync::Mutex::new(by_node),
        turn: Mutex::new(()),
    });
    Ok(MonitorFeeds {
        feeds: queues
            .into_iter()
            .map(|(node, queue)| MonitorFeed {
                node,
                queue,
                lines: lines.clone(),
            })
            .collect(),
        failures: opened
            .failures
            .into_iter()
            .map(|(node, message)| (node, Error::Invalid { message }))
            .collect(),
    })
}
