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

//! The link to the server as this connection has known it: whether its
//! first load went through, what the heartbeat makes of it, how long to
//! wait before the next attempt, and the loads owed a retry.

use super::*;

#[derive(Debug, Clone, Default)]
pub(super) struct Link {
    /// Current server status
    pub(super) server_status: RedisServerStatus,

    /// Live-connection health derived from the heartbeat PING (online /
    /// reconnecting / offline). Separate from `server_status`, which only
    /// covers the initial connect/load.
    pub(super) connection_health: ConnectionHealth,

    /// Why the last heartbeat failed (auth / perms / timeout / network /
    /// tunnel), surfaced in the status-bar offline tooltip. Cleared on a
    /// healthy PING.
    pub(super) last_connection_error: ConnectionErrorKind,

    /// Consecutive heartbeat PING failures; drives the reconnecting->offline
    /// transition in `note_ping_result`, reset to 0 on any success.
    ping_failures: u32,

    /// User pressed "disconnect" on the status-bar health dot: the live
    /// connection is dropped and the heartbeat paused (health stays `Offline`)
    /// until `reconnect` re-establishes it. Distinct from an involuntary drop,
    /// where the heartbeat keeps retrying on its own.
    pub(super) manually_offline: bool,

    /// The error the link last failed with — a refused connect, a failed
    /// beat — for the panel that says why there is nothing to show
    /// ([`Self::link_problem`]). Kept across the retries of the same target,
    /// which `reset` otherwise wipes, so the panel does not flicker back to
    /// the empty state for the length of every attempt; cleared once a load
    /// or a beat goes through.
    pub(super) link_failure: Option<(ConnectionErrorKind, SharedString)>,

    /// Unix seconds of the last "reconnect first" notice shown while
    /// `manually_offline`. Throttles it so a background refresh loop can't spam
    /// the notification each tick.
    pub(super) last_offline_notice: i64,

    /// Unix seconds of the last link-level notice (`note_link_error`), so a
    /// burst of failed calls during a reconnect yields one toast, not ten.
    last_link_notice: i64,

    /// This state belongs to an inactive workspace tab: its status-bar
    /// heartbeat keeps ticking, but `refresh_redis_info` throttles itself to a
    /// relaxed cadence so background tabs don't poll Redis at full speed.
    background: bool,

    /// Unix seconds of the last refresh allowed through while `background`.
    last_background_refresh: i64,

    /// Earliest moment the heartbeat may dial again after a failed PING.
    /// Consecutive failures double the wait (2s, 4s, 8s … capped at 60s), so
    /// an unreachable server is not put through DNS, the TLS/SSH handshake
    /// and topology discovery every two seconds for as long as the tab stays
    /// open. Cleared by a healthy PING, by any other task reaching the server
    /// (the link is evidently up) and by `reset` (ADR 5).
    pub(super) heartbeat_retry_at: Option<Instant>,

    /// When the last heartbeat attempt went out — what a large cluster's
    /// stretched interval is measured from (`pacing::heartbeat_interval`).
    pub(super) last_heartbeat_at: Option<Instant>,

    /// A heartbeat refresh is still in flight: the next tick skips instead of
    /// stacking a second attempt while a connect timeout runs its course.
    pub(super) heartbeat_in_flight: bool,

    /// The last full load (`select`) failed for a reason the link explains —
    /// refused, timed out, still loading its dataset — so the heartbeat runs
    /// it again once the server answers ([`Self::retry_failed_load`]). A
    /// server that was down when the app started used to come back as
    /// "Connected" over an empty tree, with no version, no databases and no
    /// node count, until the user reconnected by hand.
    pub(super) load_retry_pending: bool,

    /// Automatic retries since the last load somebody asked for. Bounded
    /// ([`MAX_LOAD_RETRIES`]): a load that keeps failing while the heartbeat
    /// keeps succeeding must not be retried, and toasted, on every beat.
    pub(super) load_retries: u8,

    /// The `select` now starting is one of those retries, not a new request.
    pub(super) load_retry_running: bool,
}

/// What a heartbeat's outcome did to the health.
pub(super) struct PingOutcome {
    /// The health moved, which is announced.
    pub(super) changed: bool,
    /// It moved back to Connected after a Reconnecting / Offline stretch.
    pub(super) restored: bool,
}

impl Link {
    /// Consecutive heartbeat PING failures before the live link is reported as
    /// Offline rather than Reconnecting (~2s heartbeat cadence -> >=6s down).
    pub(super) const PING_OFFLINE_THRESHOLD: u32 = 3;

    /// The status bar's heartbeat cadence; also the first retry wait. Paced
    /// per target in `helpers::pacing` (2s on the desktop).
    const HEARTBEAT_INTERVAL: Duration = pacing::HEARTBEAT_INTERVAL;
    /// Longest wait between two attempts against an unreachable server.
    const HEARTBEAT_BACKOFF_CAP: Duration = Duration::from_secs(60);

    /// How long the heartbeat waits before dialling again after `failures`
    /// consecutive misses: the interval doubled per miss — 2s, 4s, 8s, 16s,
    /// 32s — and pinned at the cap from there. A failed attempt is a full
    /// connect (DNS, TLS/SSH handshake, topology discovery, PING), which is
    /// what the plain 2s tick used to repeat against a dead endpoint for as
    /// long as its tab stayed open.
    pub(super) fn heartbeat_backoff(failures: u32) -> Duration {
        let doublings = failures.saturating_sub(1).min(5);
        Self::HEARTBEAT_INTERVAL
            .saturating_mul(1 << doublings)
            .min(Self::HEARTBEAT_BACKOFF_CAP)
    }

    /// What a server switch forgets. The load status, the retries counted,
    /// the notices' throttles and whether the tab is in the background are
    /// kept: the next `select` sets the first two again.
    pub(super) fn reset(&mut self) {
        self.connection_health = ConnectionHealth::Unknown;
        self.last_connection_error = ConnectionErrorKind::Unknown;
        self.link_failure = None;
        self.ping_failures = 0;
        self.heartbeat_retry_at = None;
        self.last_heartbeat_at = None;
        self.heartbeat_in_flight = false;
        // A fresh select / reconnect always re-establishes the link, so clear
        // any manual-disconnect pause (reconnect routes through here too).
        self.manually_offline = false;
        self.load_retry_pending = false;
    }

    pub(super) fn is_busy(&self) -> bool {
        matches!(self.server_status, RedisServerStatus::Loading)
    }

    /// See [`ZedisServerState::link_problem`].
    pub(super) fn problem(&self) -> Option<LinkProblem> {
        link_problem_for(
            &self.server_status,
            self.connection_health,
            self.manually_offline,
            self.link_failure.as_ref(),
        )
    }

    /// What the link failed with, as the status bar and the link panel say it.
    pub(super) fn note_failure(&mut self, kind: ConnectionErrorKind, detail: SharedString) {
        self.last_connection_error = kind;
        self.link_failure = Some((kind, detail));
    }

    pub(super) fn set_background(&mut self, background: bool) {
        self.background = background;
        if !background {
            self.last_background_refresh = 0;
        }
    }

    pub(super) fn is_background(&self) -> bool {
        self.background || pacing::unattended()
    }

    /// Whether the "reconnect first" notice may be shown now (at most every
    /// three seconds), taking the turn.
    pub(super) fn offline_notice_due(&mut self) -> bool {
        let now = unix_ts();
        if now.saturating_sub(self.last_offline_notice) < 3 {
            return false;
        }
        self.last_offline_notice = now;
        true
    }

    /// Whether a link notice may be shown now (at most every ten seconds),
    /// taking the turn: a burst of failed calls during a reconnect yields one
    /// toast, not ten.
    pub(super) fn link_notice_due(&mut self) -> bool {
        let now = unix_ts();
        if now.saturating_sub(self.last_link_notice) < 10 {
            return false;
        }
        self.last_link_notice = now;
        true
    }

    /// Some task just reached the server, so the link is up: the next beat
    /// goes out at once instead of sitting out its backoff.
    pub(super) fn reached(&mut self) {
        self.heartbeat_retry_at = None;
    }

    /// Whether a beat should go out now for a server of `masters` masters.
    pub(super) fn beat_due(&mut self, masters: usize) -> bool {
        // Paused by a manual disconnect — don't PING (that would flip health
        // back to Connected). Cleared by reconnect (via `reset`).
        if self.manually_offline {
            return false;
        }
        // One attempt at a time: a connect against a dead host takes up to
        // the 10s connection timeout, and the 2s tick would otherwise stack
        // five of them.
        if self.heartbeat_in_flight {
            return false;
        }
        // Backing off after failed PINGs (`note_ping`): sit this tick out.
        // Checked before the background throttle so a blocked tick doesn't
        // consume the background window either.
        if let Some(retry_at) = self.heartbeat_retry_at
            && Instant::now() < retry_at
        {
            return false;
        }
        // Inactive workspace tabs poll at a relaxed cadence: the 2s status-bar
        // heartbeat keeps firing, but only one refresh per interval gets
        // through. Re-activating the tab resets the window (`set_background`).
        // A cluster's beat is one `INFO` per master, so a large one beats
        // less often (`pacing::heartbeat_interval`; up to four masters — and
        // every standalone or Sentinel entry — are untouched). The 2s tick
        // stays the metronome; this only decides which ticks go through.
        // Not while a retry is pending: the backoff above owns that wait.
        let stretched = pacing::heartbeat_interval(masters);
        if stretched > Self::HEARTBEAT_INTERVAL
            && let Some(last) = self.last_heartbeat_at
            && last.elapsed() + Self::HEARTBEAT_INTERVAL / 2 < stretched
        {
            return false;
        }
        if self.is_background() {
            let now = unix_ts();
            if now - self.last_background_refresh < pacing::BACKGROUND_REFRESH_SECS {
                return false;
            }
            self.last_background_refresh = now;
        }
        true
    }

    /// The app is looked at again: the next beat goes out without waiting
    /// out what is left of a relaxed or stretched interval.
    pub(super) fn beat_now(&mut self) {
        self.last_background_refresh = 0;
        self.last_heartbeat_at = None;
    }

    /// A beat went out.
    pub(super) fn beat_started(&mut self) {
        self.heartbeat_in_flight = true;
        self.last_heartbeat_at = Some(Instant::now());
    }

    /// Fold a heartbeat `PING` outcome into the observable [`ConnectionHealth`].
    /// Success -> `Connected` (failure counter cleared). Failure ->
    /// `Reconnecting` for the first few consecutive misses, then `Offline` past
    /// the threshold (the heartbeat can't distinguish "retrying" from "down",
    /// so this elapsed-failures heuristic stands in). Only an actual
    /// transition is `changed`, so a steady state costs no extra re-render.
    pub(super) fn note_ping(&mut self, ok: bool, server_id: &str) -> PingOutcome {
        let was_down = matches!(
            self.connection_health,
            ConnectionHealth::Reconnecting | ConnectionHealth::Offline
        );
        let next = if ok {
            self.ping_failures = 0;
            self.heartbeat_retry_at = None;
            self.last_connection_error = ConnectionErrorKind::Unknown;
            // A load that failed while the server answers beats (a denied
            // command, say) is still failed: its reason stays until it loads.
            if !matches!(self.server_status, RedisServerStatus::Failed) {
                self.link_failure = None;
            }
            ConnectionHealth::Connected
        } else {
            self.ping_failures = self.ping_failures.saturating_add(1);
            let wait = Self::heartbeat_backoff(self.ping_failures);
            self.heartbeat_retry_at = Some(Instant::now() + wait);
            debug!(
                server_id,
                failures = self.ping_failures,
                retry_in_secs = wait.as_secs(),
                "heartbeat backing off"
            );
            if self.ping_failures >= Self::PING_OFFLINE_THRESHOLD {
                ConnectionHealth::Offline
            } else {
                ConnectionHealth::Reconnecting
            }
        };
        let changed = self.connection_health != next;
        if changed {
            self.connection_health = next;
        }
        PingOutcome {
            changed,
            restored: changed && ok && was_down,
        }
    }

    /// Taken offline by hand: the heartbeat pauses until a reconnect.
    /// Answers whether the health changed.
    pub(super) fn go_offline(&mut self) -> bool {
        self.manually_offline = true;
        self.ping_failures = Self::PING_OFFLINE_THRESHOLD;
        if self.connection_health == ConnectionHealth::Offline {
            return false;
        }
        self.connection_health = ConnectionHealth::Offline;
        true
    }

    /// A load starts: one somebody asked for starts the count of automatic
    /// retries again; one the heartbeat started carries it on.
    pub(super) fn start_load(&mut self) {
        if !std::mem::take(&mut self.load_retry_running) {
            self.load_retries = 0;
        }
        self.load_retry_pending = false;
    }

    /// A load failed with `kind`: worth another go by itself once the
    /// server answers, when it is the link that failed it.
    pub(super) fn note_load_failure(&mut self, kind: ConnectionErrorKind) {
        self.load_retry_pending = self.load_retries < MAX_LOAD_RETRIES && heals_with_the_link(kind);
    }

    /// Whether a retry is owed, taking it: the load failed with the link, it
    /// is still the failed one on screen, and nothing has retried it since.
    pub(super) fn take_load_retry(&mut self) -> bool {
        if !self.load_retry_pending || !matches!(self.server_status, RedisServerStatus::Failed) {
            return false;
        }
        self.load_retry_pending = false;
        self.load_retries += 1;
        self.load_retry_running = true;
        true
    }
}
