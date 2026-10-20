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

//! The accounts in the local directory: `bridge-accounts.json`, the
//! `store::AccountStore` of a bridge without a database.

use super::*;

/// What `bridge-accounts.json` holds.
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct AccountsFile {
    accounts: Vec<AccountRecord>,
    invites: Vec<InviteRecord>,
    signups: Vec<SignupRecord>,
}

/// The accounts in `bridge-accounts.json`, owner-only: read and written
/// whole, one change at a time. Its version counts this process's changes —
/// the file has one writer.
#[derive(Clone)]
pub struct LocalAccounts {
    path: Arc<PathBuf>,
    lock: Arc<Mutex<()>>,
    version: Arc<AtomicU64>,
}

impl LocalAccounts {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path: Arc::new(path),
            lock: Arc::default(),
            version: Arc::default(),
        }
    }

    /// The file, or an empty one when there is none yet. One that cannot be
    /// read is an error, never an empty list: the next write would replace
    /// every account with what the change added.
    fn read(&self) -> io::Result<AccountsFile> {
        match std::fs::read(self.path.as_path()) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(AccountsFile::default()),
            Err(e) => Err(e),
        }
    }

    /// Apply `ops` to the file in one write, if it is still at `seen`.
    fn apply_now(&self, seen: u64, ops: Vec<AccountOp>) -> io::Result<Option<u64>> {
        let _held = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        if self.version.load(Ordering::SeqCst) != seen {
            return Ok(None);
        }
        let mut file = self.read()?;
        for op in ops {
            match op {
                AccountOp::PutAccount(account) => match file.accounts.iter_mut().find(|a| a.name == account.name) {
                    Some(slot) => *slot = account,
                    None => file.accounts.push(account),
                },
                AccountOp::RemoveAccount(name) => file.accounts.retain(|a| a.name != name),
                AccountOp::PutInvite(invite) => match file.invites.iter_mut().find(|i| i.id == invite.id) {
                    Some(slot) => *slot = invite,
                    None => file.invites.push(invite),
                },
                AccountOp::RemoveInvite(id) => file.invites.retain(|i| i.id != id),
                AccountOp::PutSignup(request) => match file.signups.iter_mut().find(|r| r.id == request.id) {
                    Some(slot) => *slot = request,
                    None => file.signups.push(request),
                },
                AccountOp::RemoveSignup(id) => file.signups.retain(|r| r.id != id),
            }
        }
        let bytes = serde_json::to_vec_pretty(&file).map_err(io::Error::other)?;
        write_file_atomic(&self.path, &bytes)?;
        restrict(self.path.as_path());
        Ok(Some(self.version.fetch_add(1, Ordering::SeqCst) + 1))
    }
}

impl AccountStore for LocalAccounts {
    fn load(&self) -> StoreFuture<AccountsAt> {
        let store = self.clone();
        let read = blocking(move || {
            let _held = store.lock.lock().unwrap_or_else(PoisonError::into_inner);
            store.read().map(|file| AccountsAt {
                version: store.version.load(Ordering::SeqCst),
                accounts: file.accounts,
                invites: file.invites,
                signups: file.signups,
            })
        });
        Box::pin(async move { read.await? })
    }

    fn apply(&self, seen: u64, ops: Vec<AccountOp>) -> StoreFuture<Option<u64>> {
        let store = self.clone();
        let apply = blocking(move || store.apply_now(seen, ops));
        Box::pin(async move { apply.await? })
    }

    fn version(&self) -> StoreFuture<u64> {
        let version = self.version.load(Ordering::SeqCst);
        Box::pin(async move { Ok(version) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::tests::register_full;

    /// The file holds hashes, never a password or a code; it is owner-only,
    /// reads back as written, and one that cannot be read is an error —
    /// never an empty list a write would then put over every account.
    #[tokio::test]
    async fn the_local_store_keeps_records_and_refuses_an_unreadable_file() {
        let dir = std::env::temp_dir().join(format!("zedis-accounts-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("bridge-accounts.json");
        let store: Arc<dyn AccountStore> = Arc::new(LocalAccounts::new(path.clone()));
        let accounts = Accounts::load(store.clone()).await.expect("empty");
        assert_eq!(accounts.len(), 0);
        accounts
            .make_admin("root", Some(hash_password("root-password").expect("hash")))
            .await
            .expect("admin");
        let (_, code) = accounts.invite_new("root", register_full(), 1).await.expect("invite");

        let again = Accounts::load(store.clone()).await.expect("reload");
        assert!(again.is_admin("root") && again.invite(&code).await.is_some());
        let on_disk = std::fs::read_to_string(&path).expect("file");
        assert!(
            !on_disk.contains("root-password") && !on_disk.contains(&code),
            "{on_disk}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::write(&path, "not json").expect("damage");
        assert!(Accounts::load(store).await.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
