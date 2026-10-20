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

//! `MONITOR` read through a tunnel, by hand: redis-rs builds its `Monitor`
//! only on a socket it dialed, and `MONITOR`'s lines are not pushes a
//! multiplexed connection could carry.

use super::*;

/// Lines a tunnelled `MONITOR` may run ahead of its reader. Past this the
/// reader stops reading and the tunnel's flow control holds the server back,
/// as a socket's does for a direct feed.
const MONITOR_BACKLOG: usize = 1024;

/// `MONITOR` through the entry's SSH tunnel: the server's lines, one per
/// command it receives, until the stream is dropped.
///
/// Read by hand, because redis-rs will not do it over a tunnel: its
/// `Monitor` is built only on a socket it dialed itself (`Monitor::new` is
/// crate-private), and the multiplexed connection the rest of this file
/// builds has nowhere to put replies nobody asked for — which is all
/// `MONITOR` sends, plain `+…` lines on RESP2 and RESP3 alike, not pushes.
/// Without it the Monitor panel dialed an SSH entry's host from this
/// machine, where the far side's `127.0.0.1` is another Redis or none.
pub async fn open_ssh_tunnel_monitor(config: &RedisServer) -> Result<impl Stream<Item = String> + Send + 'static> {
    let dial = TunnelDial::new(config)?;
    let response_timeout = resolve_response_timeout(config);
    // `(command, must succeed)`, sent in one write and answered in order.
    let mut handshake: Vec<(Cmd, bool)> = Vec::with_capacity(3);
    if let Some(password) = config.password.as_deref() {
        let mut auth = cmd("AUTH");
        if let Some(user) = config.username.as_deref() {
            auth.arg(user);
        }
        auth.arg(password);
        handshake.push((auth, true));
    }
    // Named like every connection this app opens, so an operator can tell
    // whose feed it is in `CLIENT LIST`; best effort, as there.
    let mut setname = cmd("CLIENT");
    setname.arg("SETNAME").arg(client_name());
    handshake.push((setname, false));
    handshake.push((cmd("MONITOR"), true));

    let (tx, lines) = smol::channel::bounded::<String>(MONITOR_BACKLOG);
    let reader = run_in_tokio(async move {
        let mut stream = BufReader::new(dial.open().await?);
        tokio::time::timeout(response_timeout, start_monitor(&mut stream, &handshake))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("MONITOR did not start within {}s", response_timeout.as_secs()),
                )
            })??;
        Ok::<_, Error>(AbortOnDrop(tokio::spawn(forward_monitor_lines(stream, tx)).abort_handle()))
    })
    .await?;
    Ok(futures::stream::unfold((lines, reader), |(lines, reader)| async move {
        let line = lines.recv().await.ok()?;
        Some((line, (lines, reader)))
    }))
}

/// Send the handshake and read its replies: an error to a command that must
/// succeed (`AUTH`, `MONITOR` itself — `NOPERM` where the ACL forbids it)
/// ends the attempt; one to a courtesy (`SETNAME`) is only logged.
pub(super) async fn start_monitor(stream: &mut BufReader<Box<dyn TunnelIo>>, handshake: &[(Cmd, bool)]) -> Result<()> {
    let packed: Vec<u8> = handshake.iter().flat_map(|(command, _)| command.get_packed_command()).collect();
    stream.write_all(&packed).await?;
    stream.flush().await?;
    let mut line = Vec::new();
    for (_, required) in handshake {
        line.clear();
        if stream.read_until(b'\n', &mut line).await? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the server closed the connection before MONITOR started",
            )
            .into());
        }
        match redis::parse_redis_value(&line).and_then(Value::extract_error) {
            Ok(_) => {}
            Err(e) if *required => return Err(e.into()),
            Err(e) => warn!(error = %e, "the tunnelled MONITOR connection kept no name"),
        }
    }
    Ok(())
}

/// Hand the feed's lines to `tx` until the server closes the connection,
/// or the receiving side is gone.
pub(super) async fn forward_monitor_lines(mut stream: BufReader<Box<dyn TunnelIo>>, tx: smol::channel::Sender<String>) {
    let mut line = Vec::new();
    loop {
        line.clear();
        if !matches!(stream.read_until(b'\n', &mut line).await, Ok(n) if n > 0) {
            break;
        }
        // Anything but a simple string is the end of the feed: the error a
        // killed client is sent on its way out.
        let Some(text) = monitor_line(&line) else {
            break;
        };
        if tx.send(text).await.is_err() {
            break;
        }
    }
}

/// One `MONITOR` line as the server wrote it: the simple string, without
/// its `+` and line ending. `None` for any other reply.
pub(super) fn monitor_line(raw: &[u8]) -> Option<String> {
    let body = raw.strip_prefix(b"+")?;
    let body = body
        .strip_suffix(b"\r\n")
        .or_else(|| body.strip_suffix(b"\n"))
        .unwrap_or(body);
    Some(String::from_utf8_lossy(body).into_owned())
}

/// Stops the task behind a tunnelled feed when the feed is dropped. The task
/// waits on the socket, so without this an idle server would hold it — and
/// its tunnel channel — open until the next command came along.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
