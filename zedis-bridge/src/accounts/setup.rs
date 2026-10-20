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

//! The setup token: what seats the first administrator, and a new one when
//! every administrator is lost — kept in a file beside the data, or the
//! database.

use super::*;

/// The one-time token that seats an administrator (ADR 17).
///
/// While no administrator exists the bridge mints one at start-up, prints it
/// in its log and keeps it where every process reads it ([`SetupStore`]: the
/// `setup-token` file beside the data, or the database) — or takes
/// [`SETUP_TOKEN_ENV`] from an install that wants to know it in advance.
/// `zedis-bridge setup-token`, run on the host against the same store,
/// keeps a new one when every administrator is lost: host access is
/// administrator access, and nothing over HTTP is. It is read at each
/// attempt, so one kept while the bridge runs works at once, and it is
/// forgotten when it is used.
#[derive(Clone)]
pub struct Setup {
    store: Arc<dyn SetupStore>,
}

impl Setup {
    pub fn new(store: Arc<dyn SetupStore>) -> Self {
        Self { store }
    }

    /// The token kept in `dir`, the local directory's way.
    #[cfg(test)]
    pub fn in_dir(dir: &Path) -> Self {
        Self::new(Arc::new(LocalSetup::new(dir.join("setup-token"))))
    }

    /// Where it is kept, for the log.
    pub fn location(&self) -> String {
        self.store.location()
    }

    /// Keep a fresh token in place of any waiting one, and answer it.
    pub async fn mint(&self) -> io::Result<String> {
        let token = new_code();
        self.store.put(token.clone()).await?;
        Ok(token)
    }

    /// The token to print at start-up while there is no administrator: the
    /// waiting one where the store can say it, else a fresh one unless
    /// another process kept one first (`None`: its log has it).
    pub async fn for_start(&self) -> io::Result<Option<String>> {
        if let Some(token) = self.store.shown().await? {
            return Ok(Some(token));
        }
        let token = new_code();
        Ok(self.store.put_if_none(token.clone()).await?.then_some(token))
    }

    /// Whether the page should offer *Create the administrator*: there is
    /// none, or a token was kept for the recovery of one.
    pub async fn open(&self, accounts: &Accounts) -> bool {
        accounts.admin_count() == 0 || self.store.waiting().await.unwrap_or(false)
    }

    /// Whether `token` is the setup token: the store's, or — while there is
    /// no administrator — the one the environment chose.
    pub async fn accepts(&self, token: &str, accounts: &Accounts) -> bool {
        let token = token.trim();
        if token.is_empty() {
            return false;
        }
        let from_env = accounts.admin_count() == 0
            && std::env::var(SETUP_TOKEN_ENV)
                .ok()
                .is_some_and(|chosen| !chosen.trim().is_empty() && same(chosen.trim().as_bytes(), token.as_bytes()));
        from_env || self.store.accepts(token.to_string()).await.unwrap_or(false)
    }

    /// The token did its work.
    pub async fn used(&self) {
        if let Err(e) = self.store.take().await {
            tracing::warn!(error = %e, "the used setup token could not be forgotten");
        }
    }
}

/// The setup token in a file beside the data, owner-only — in the clear, so
/// a restart can print it again; the file is the host's, and host access is
/// administrator access anyway.
pub struct LocalSetup {
    file: PathBuf,
}

impl LocalSetup {
    pub fn new(file: PathBuf) -> Self {
        Self { file }
    }

    fn read(&self) -> Option<String> {
        std::fs::read_to_string(&self.file)
            .ok()
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty())
    }

    fn write(&self, token: &str) -> io::Result<()> {
        write_file_atomic(&self.file, token.as_bytes())?;
        restrict(&self.file);
        Ok(())
    }
}

impl SetupStore for LocalSetup {
    fn waiting(&self) -> StoreFuture<bool> {
        let waiting = self.file.exists();
        Box::pin(async move { Ok(waiting) })
    }

    fn accepts(&self, token: String) -> StoreFuture<bool> {
        let accepted = self
            .read()
            .is_some_and(|stored| same(stored.as_bytes(), token.as_bytes()));
        Box::pin(async move { Ok(accepted) })
    }

    fn put(&self, token: String) -> StoreFuture<()> {
        let written = self.write(&token);
        Box::pin(async move { written })
    }

    fn put_if_none(&self, token: String) -> StoreFuture<bool> {
        let kept = match self.read() {
            Some(_) => Ok(false),
            None => self.write(&token).map(|()| true),
        };
        Box::pin(async move { kept })
    }

    fn shown(&self) -> StoreFuture<Option<String>> {
        let token = self.read();
        Box::pin(async move { Ok(token) })
    }

    fn take(&self) -> StoreFuture<()> {
        let removed = match std::fs::remove_file(&self.file) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
        Box::pin(async move { removed })
    }

    fn location(&self) -> String {
        self.file.display().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_setup_token_is_the_file_s_and_is_used_once() {
        let dir = std::env::temp_dir().join(format!("zedis-setup-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).expect("dir");
        let setup = Setup::in_dir(&dir);
        let accounts = Accounts::from_inline("alice@secret").expect("accounts");
        assert!(setup.open(&accounts).await, "no administrator yet");
        assert!(!setup.accepts("anything", &accounts).await);
        let token = setup.mint().await.expect("minted");
        assert!(setup.accepts(&token, &accounts).await);
        assert!(setup.accepts(&format!(" {token}\n"), &accounts).await);
        assert!(!setup.accepts("", &accounts).await && !setup.accepts(&token[1..], &accounts).await);
        accounts.make_admin("alice", None).await.expect("promoted");
        assert!(setup.open(&accounts).await, "a written token keeps it open");
        setup.used().await;
        assert!(!setup.open(&accounts).await && !setup.accepts(&token, &accounts).await);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
