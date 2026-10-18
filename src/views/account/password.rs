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

//! One's own password. The browser's password manager does not see a
//! change made here (the fields are drawn, not a `<form>`); it offers to
//! update the saved one at the next sign-in instead (ADR 17, amended).

use super::*;
use gpui_kit::component::input::{Input, InputState};

/// The bridge's floor, checked here first so a short one is not a round trip.
const MIN_PASSWORD_CHARS: usize = 8;

pub(super) const CURRENT_PASSWORD_ID: &str = "account-current-password";
pub(super) const NEW_PASSWORD_ID: &str = "account-new-password";
pub(super) const REPEAT_PASSWORD_ID: &str = "account-repeat-password";
pub(super) const CHANGE_PASSWORD_ID: &str = "account-change-password";

pub(super) struct PasswordForm {
    pub(super) current: Entity<InputState>,
    new: Entity<InputState>,
    repeat: Entity<InputState>,
    busy: bool,
    pub(super) status: Option<Status>,
    /// Empty the fields at the next render, which has the window to do it.
    clear: bool,
}

impl PasswordForm {
    pub(super) fn new(window: &mut Window, cx: &mut Context<ZedisAccount>) -> Self {
        Self {
            current: cx.new(|cx| InputState::new(window, cx).masked(true)),
            new: cx.new(|cx| InputState::new(window, cx).masked(true)),
            repeat: cx.new(|cx| InputState::new(window, cx).masked(true)),
            busy: false,
            status: None,
            clear: false,
        }
    }
}

impl ZedisAccount {
    pub(super) fn render_password(
        &mut self,
        me: &BridgeOwnAccount,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        if !me.account.has_password {
            return note(cx, i18n_account(cx, "proxy_no_password")).into_any_element();
        }
        if me.account.locked {
            return note(cx, i18n_account(cx, "password_locked")).into_any_element();
        }
        if std::mem::take(&mut self.password.clear) {
            for state in [&self.password.current, &self.password.new, &self.password.repeat] {
                state.update(cx, |state, cx| state.set_value("", window, cx));
            }
        }
        let form = &self.password;
        v_flex()
            .gap_3()
            .max_w(px(360.))
            .child(field(
                cx,
                i18n_account(cx, "current_password"),
                Input::new(&form.current).id(CURRENT_PASSWORD_ID),
            ))
            .child(field(
                cx,
                i18n_account(cx, "new_password"),
                Input::new(&form.new).id(NEW_PASSWORD_ID),
            ))
            .child(field(
                cx,
                i18n_account(cx, "repeat_password"),
                Input::new(&form.repeat).id(REPEAT_PASSWORD_ID),
            ))
            .child(
                h_flex().child(
                    submit(CHANGE_PASSWORD_ID, i18n_account(cx, "change_password"), form.busy)
                        .icon(gpui_kit::assets::IconName::KeyRound)
                        .on_click(cx.listener(|this, _, _, cx| this.change_password(cx))),
                ),
            )
            .children(status_line(cx, &form.status))
            .into_any_element()
    }

    pub(super) fn change_password(&mut self, cx: &mut Context<Self>) {
        let form = &self.password;
        let current = form.current.read(cx).value().to_string();
        let new = form.new.read(cx).value().to_string();
        let repeat = form.repeat.read(cx).value().to_string();
        let problem = if new.chars().count() < MIN_PASSWORD_CHARS {
            Some("password_short")
        } else if new != repeat {
            Some("passwords_differ")
        } else {
            None
        };
        if let Some(key) = problem {
            self.password.status = Status::bad(i18n_account(cx, key));
            cx.notify();
            return;
        }
        self.password.busy = true;
        self.password.status = None;
        cx.notify();
        let request = self.bridge.change_password(current, new);
        cx.spawn(async move |this, cx| {
            let result = request.await;
            let _ = this.update(cx, |this, cx| {
                this.password.busy = false;
                match result {
                    Ok(()) => {
                        this.password.status = Status::good(i18n_account(cx, "password_changed"));
                        this.password.clear = true;
                    }
                    Err(e) => {
                        let known = [(BridgeAccountErrorKind::Refused, "current_password_wrong")];
                        this.password.status = Status::bad(refusal(cx, &e, &known));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }
}
