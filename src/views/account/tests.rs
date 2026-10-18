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

//! The account page against a bridge of its own: what it shows a role, what
//! it checks before it asks, and what it asks.

use super::admin::SAVE_ACCOUNT_ID;
use super::password::{CHANGE_PASSWORD_ID, CURRENT_PASSWORD_ID, NEW_PASSWORD_ID, REPEAT_PASSWORD_ID};
use super::tokens::{ISSUE_TOKEN_ID, TOKEN_NAME_ID};
use super::*;
use crate::connection::{BridgeAccountChange, BridgeAccountResult, BridgeInvite, BridgeNewInvite};
use crate::test_support::init_ui;
use gpui::{AnyWindowHandle, TestAppContext, size};
use gpui_kit::component::Root;
use gpui_kit::test::TestWindowExt;
use std::sync::Mutex;

/// A bridge that answers at once, and writes down what it was asked.
#[derive(Default)]
struct FakeBridge {
    me: Mutex<BridgeOwnAccount>,
    accounts: Mutex<Vec<BridgeAccount>>,
    /// What the page asked, one line a request.
    asked: Mutex<Vec<String>>,
    updates: Mutex<Vec<(String, BridgeAccountChange)>>,
    /// The refusal the next password change gets.
    refuse_password: Mutex<Option<BridgeAccountError>>,
    /// The refusal the next account change gets.
    refuse_update: Mutex<Option<BridgeAccountError>>,
}

impl FakeBridge {
    fn signed_in_as(name: &str, role: BridgeRole) -> Arc<Self> {
        let bridge = Self::default();
        *bridge.me.lock().expect("lock") = BridgeOwnAccount {
            account: account(name, role),
            proxy: false,
        };
        Arc::new(bridge)
    }

    fn asked(&self, line: String) {
        self.asked.lock().expect("lock").push(line);
    }

    fn requests(&self) -> Vec<String> {
        self.asked.lock().expect("lock").clone()
    }
}

fn account(name: &str, role: BridgeRole) -> BridgeAccount {
    BridgeAccount {
        name: name.to_string(),
        role,
        has_password: true,
        created_at: 1_700_000_000,
        ..Default::default()
    }
}

fn answer<T: Send + 'static>(value: Result<T, BridgeAccountError>) -> BridgeAccountResult<T> {
    Box::pin(async move { value })
}

impl BridgeAccounts for FakeBridge {
    fn account(&self) -> BridgeAccountResult<BridgeOwnAccount> {
        answer(Ok(self.me.lock().expect("lock").clone()))
    }

    fn change_password(&self, current: String, new: String) -> BridgeAccountResult<()> {
        self.asked(format!("password {current} -> {new}"));
        match self.refuse_password.lock().expect("lock").take() {
            Some(refusal) => answer(Err(refusal)),
            None => answer(Ok(())),
        }
    }

    fn issue_token(
        &self,
        account: Option<String>,
        name: String,
        expires: Option<String>,
    ) -> BridgeAccountResult<String> {
        self.asked(format!("issue {account:?} {name} {expires:?}"));
        answer(Ok(format!("zdt_{name}")))
    }

    fn revoke_token(&self, account: Option<String>, name: String) -> BridgeAccountResult<()> {
        self.asked(format!("revoke {account:?} {name}"));
        answer(Ok(()))
    }

    fn accounts(&self) -> BridgeAccountResult<Vec<BridgeAccount>> {
        answer(Ok(self.accounts.lock().expect("lock").clone()))
    }

    fn update_account(&self, name: String, change: BridgeAccountChange) -> BridgeAccountResult<BridgeAccount> {
        self.updates.lock().expect("lock").push((name.clone(), change));
        match self.refuse_update.lock().expect("lock").take() {
            Some(refusal) => answer(Err(refusal)),
            None => answer(Ok(account(&name, BridgeRole::Full))),
        }
    }

    fn delete_account(&self, name: String) -> BridgeAccountResult<()> {
        self.asked(format!("delete {name}"));
        answer(Ok(()))
    }

    fn reset_link(&self, name: String) -> BridgeAccountResult<BridgeNewInvite> {
        self.asked(format!("reset {name}"));
        answer(Err(BridgeAccountError::new(BridgeAccountErrorKind::Failed, "not here")))
    }

    fn invites(&self) -> BridgeAccountResult<Vec<BridgeInvite>> {
        answer(Ok(Vec::new()))
    }

    fn create_invite(
        &self,
        role: BridgeRole,
        _servers: Option<Vec<String>>,
        _proxy: bool,
        days: u64,
    ) -> BridgeAccountResult<BridgeNewInvite> {
        self.asked(format!("invite {} {days}", role.as_str()));
        answer(Err(BridgeAccountError::new(BridgeAccountErrorKind::Failed, "not here")))
    }

    fn revoke_invite(&self, id: String) -> BridgeAccountResult<()> {
        self.asked(format!("revoke invite {id}"));
        answer(Ok(()))
    }

    fn invite_link(&self, code: &str) -> String {
        format!("https://bridge.test/#invite={code}")
    }
}

/// The page in a window of its own, with what the bridge first answered.
fn open(cx: &mut TestAppContext, bridge: Arc<FakeBridge>) -> (Entity<ZedisAccount>, AnyWindowHandle) {
    init_ui(cx);
    let mut view = None;
    let handle = cx.open_window(size(px(900.), px(640.)), |window, cx| {
        let account = cx.new(|cx| ZedisAccount::new(bridge.clone(), window, cx));
        view = Some(account.clone());
        Root::new(account, window, cx)
    });
    cx.run_until_parked();
    (view.expect("the window built the page"), handle.into())
}

/// A read-only account has its password and its MCP tokens, and nothing of
/// an administrator's; it is never asked for the accounts.
#[gpui::test]
fn a_read_only_account_has_its_tokens_and_no_administration(cx: &mut TestAppContext) {
    let bridge = FakeBridge::signed_in_as("ai", BridgeRole::ReadOnly);
    let (_, window) = open(cx, bridge.clone());
    cx.update_window(window, |_, window, cx| {
        window.render_frame(cx);
        assert!(window.try_find("section_password").is_some());
        assert!(window.try_find("section_tokens").is_some());
        assert!(window.try_find("section_accounts").is_none());
        assert!(window.try_find("section_invites").is_none());
    })
    .expect("the window is open");
}

/// A short or mistyped new password is caught on the page; a right one is
/// sent, said to be changed, and the fields are emptied.
#[gpui::test]
fn a_password_is_checked_before_it_is_sent(cx: &mut TestAppContext) {
    let bridge = FakeBridge::signed_in_as("alice", BridgeRole::Full);
    let (view, window) = open(cx, bridge.clone());
    cx.update_window(window, |_, window, cx| {
        window.render_frame(cx);
        for (id, text) in [
            (CURRENT_PASSWORD_ID, "old-password"),
            (NEW_PASSWORD_ID, "short"),
            (REPEAT_PASSWORD_ID, "short"),
        ] {
            window.click(id, cx);
            window.input(text, cx);
        }
        window.click(CHANGE_PASSWORD_ID, cx);
    })
    .expect("the window is open");
    cx.run_until_parked();
    let status = view.read_with(cx, |view, _| view.password.status.clone());
    assert_eq!(status, Status::bad("A password has at least 8 characters."));
    assert!(bridge.requests().is_empty(), "nothing is sent for a short one");

    cx.update_window(window, |_, window, cx| {
        window.render_frame(cx);
        for id in [NEW_PASSWORD_ID, REPEAT_PASSWORD_ID] {
            window.click(id, cx);
            window.input("-but-longer", cx);
        }
        window.click(CHANGE_PASSWORD_ID, cx);
    })
    .expect("the window is open");
    cx.run_until_parked();
    assert_eq!(bridge.requests(), vec!["password old-password -> short-but-longer"]);
    cx.update_window(window, |_, window, cx| {
        window.render_frame(cx);
        let view = view.read(cx);
        assert!(view.password.status.as_ref().is_some_and(|status| status.good));
        assert_eq!(view.password.current.read(cx).value(), "");
    })
    .expect("the window is open");
}

/// The page has its own words for the refusals it knows.
#[gpui::test]
fn a_wrong_current_password_is_said_in_the_page_s_words(cx: &mut TestAppContext) {
    let bridge = FakeBridge::signed_in_as("alice", BridgeRole::Full);
    *bridge.refuse_password.lock().expect("lock") = Some(BridgeAccountError::new(
        BridgeAccountErrorKind::Refused,
        "the current password is not right",
    ));
    let (view, window) = open(cx, bridge);
    cx.update_window(window, |_, window, cx| {
        window.render_frame(cx);
        for (id, text) in [
            (CURRENT_PASSWORD_ID, "wrong"),
            (NEW_PASSWORD_ID, "a-new-password"),
            (REPEAT_PASSWORD_ID, "a-new-password"),
        ] {
            window.click(id, cx);
            window.input(text, cx);
        }
        window.click(CHANGE_PASSWORD_ID, cx);
    })
    .expect("the window is open");
    cx.run_until_parked();
    let status = view.read_with(cx, |view, _| view.password.status.clone());
    assert_eq!(status, Status::bad("The current password is not right."));
}

/// An administrator's save sends what the form changed and nothing else —
/// one setting, one line in the audit log.
#[gpui::test]
fn an_administrator_saves_only_what_changed(cx: &mut TestAppContext) {
    let bridge = FakeBridge::signed_in_as("alice", BridgeRole::Admin);
    *bridge.accounts.lock().expect("lock") = vec![
        account("alice", BridgeRole::Admin),
        BridgeAccount {
            servers: Some(vec!["prod-*:ro".to_string()]),
            ..account("bob", BridgeRole::Full)
        },
    ];
    let (view, window) = open(cx, bridge.clone());
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            assert_eq!(view.admin.table.read(cx).delegate().visible_len(), 2);
            view.select_section(AccountSection::Accounts, window, cx);
            view.select_account("bob", window, cx);
        });
        window.render_frame(cx);
        window.click("account-disabled", cx);
        window.click(SAVE_ACCOUNT_ID, cx);
    })
    .expect("the window is open");
    cx.run_until_parked();
    let updates = bridge.updates.lock().expect("lock").clone();
    assert_eq!(
        updates,
        vec![(
            "bob".to_string(),
            BridgeAccountChange {
                role: None,
                servers: None,
                disabled: Some(true),
            }
        )]
    );
}

/// A change the bridge refuses — the last administrator disabled — is said
/// in the page's words, and the form goes back to what the account is: a
/// ticked box left behind would read as a change that was kept.
#[gpui::test]
fn a_refused_change_puts_the_form_back(cx: &mut TestAppContext) {
    let bridge = FakeBridge::signed_in_as("alice", BridgeRole::Admin);
    *bridge.accounts.lock().expect("lock") = vec![account("alice", BridgeRole::Admin)];
    *bridge.refuse_update.lock().expect("lock") = Some(BridgeAccountError::new(
        BridgeAccountErrorKind::Conflict,
        "the bridge would be left without an administrator",
    ));
    let (view, window) = open(cx, bridge);
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| {
            view.select_section(AccountSection::Accounts, window, cx);
            view.select_account("alice", window, cx);
        });
        window.render_frame(cx);
        window.click("account-disabled", cx);
        assert!(view.read(cx).admin.disabled);
        window.click(SAVE_ACCOUNT_ID, cx);
    })
    .expect("the window is open");
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        window.render_frame(cx);
        let view = view.read(cx);
        assert_eq!(
            view.admin.status,
            Status::bad("The last administrator cannot be demoted, disabled or deleted.")
        );
        assert!(!view.admin.disabled, "the form shows the account as it is");
    })
    .expect("the window is open");
}

/// A token is shown once, where it was issued, with its name sent and no
/// expiry when none was picked.
#[gpui::test]
fn an_issued_token_is_shown_once(cx: &mut TestAppContext) {
    let bridge = FakeBridge::signed_in_as("ai", BridgeRole::ReadOnly);
    let (view, window) = open(cx, bridge.clone());
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |view, cx| view.select_section(AccountSection::Tokens, window, cx));
        window.render_frame(cx);
        window.click(TOKEN_NAME_ID, cx);
        window.input("laptop", cx);
        window.click(ISSUE_TOKEN_ID, cx);
    })
    .expect("the window is open");
    cx.run_until_parked();
    assert_eq!(bridge.requests(), vec!["issue None laptop None"]);
    let shown = view.read_with(cx, |view, _| view.shown.clone()).expect("shown");
    assert_eq!(shown.value.as_ref(), "zdt_laptop");
    assert_eq!(shown.section, AccountSection::Tokens);
}

/// The desktop has no bridge to ask, so *Account…* — were anything to send
/// it — opens nothing.
#[gpui::test]
fn the_desktop_opens_no_account_page(cx: &mut TestAppContext) {
    let (_, window) = open(cx, FakeBridge::signed_in_as("alice", BridgeRole::Full));
    cx.update_window(window, |_, window, cx| open_account(window, cx))
        .expect("the window is open");
    cx.run_until_parked();
    cx.update_window(window, |_, window, cx| {
        assert!(!window.has_active_dialog(cx));
    })
    .expect("the window is open");
}

#[test]
fn rules_are_one_a_line_and_none_is_every_shared_entry() {
    assert_eq!(rules_of("  \n , "), None);
    assert_eq!(
        rules_of("prod-*:ro\nstaging, id:0199"),
        Some(vec![
            "prod-*:ro".to_string(),
            "staging".to_string(),
            "id:0199".to_string()
        ])
    );
}
