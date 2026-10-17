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

//! The dialog that asks for a TTL: the key tree's Set TTL… on a selection,
//! a folder or one key (#226), and a hash row's Set field TTL… (#225).

use crate::connection::ExpireCondition;
use crate::helpers::ttl_secs;
use crate::states::{dialog_button_props, i18n_common, i18n_key_tree};
use gpui::{App, AppContext, Context, Entity, SharedString, Window, prelude::*, px};
use gpui_kit::component::{
    ActiveTheme, Sizable, WindowExt,
    input::{Input, InputState},
    label::Label,
    notification::Notification,
    radio::{Radio, RadioGroup},
    v_flex,
};
use zedis_ui::ZedisDialog;

/// Radio order in the dialog: unconditional first, then the four `EXPIRE`
/// option words; the second field is the label's i18n key.
const TTL_CONDITION_CHOICES: [(Option<ExpireCondition>, &str); 5] = [
    (None, "batch_ttl_cond_none"),
    (Some(ExpireCondition::Nx), "batch_ttl_cond_nx"),
    (Some(ExpireCondition::Xx), "batch_ttl_cond_xx"),
    (Some(ExpireCondition::Gt), "batch_ttl_cond_gt"),
    (Some(ExpireCondition::Lt), "batch_ttl_cond_lt"),
];

/// The dialog body as a **view entity** (a dialog body holding an
/// `InputState` must be one — see the CLAUDE.md dialog gotcha — and the
/// condition radios need `cx.notify` to repaint): the sentence that says
/// what is being set, the TTL input and, where offered, the `EXPIRE`
/// condition (NX / XX / GT / LT).
struct TtlForm {
    prompt: SharedString,
    ttl: Entity<InputState>,
    /// Offer the condition radios (`EXPIRE` option words, Redis 7.0+).
    show_condition: bool,
    condition: Option<ExpireCondition>,
}

impl TtlForm {
    fn new(prompt: SharedString, show_condition: bool, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let ttl = cx.new(|cx| InputState::new(window, cx).placeholder(i18n_key_tree(cx, "batch_ttl_placeholder")));
        Self {
            prompt,
            ttl,
            show_condition,
            condition: None,
        }
    }

    /// What the dialog submits: the parsed TTL (`None` keeps the dialog
    /// open) and the condition — never one on a server that predates the
    /// option words, so nothing extra goes on the wire there.
    fn submission(&self, cx: &App) -> Option<(u64, Option<ExpireCondition>)> {
        // `ttl_secs`, not a bare duration parse: it takes the `3600` the
        // placeholder suggests, and refuses the `0` that EXPIRE would turn
        // into deleting every key in scope.
        let secs = ttl_secs(self.ttl.read(cx).value().as_ref())?;
        Some((secs, self.show_condition.then_some(self.condition).flatten()))
    }
}

impl Render for TtlForm {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        let selected = TTL_CONDITION_CHOICES.iter().position(|(c, _)| *c == self.condition);
        v_flex()
            .gap_2()
            .w_full()
            .child(Label::new(self.prompt.clone()).text_sm())
            .child(Input::new(&self.ttl).small())
            .when(self.show_condition, |this| {
                this.child(
                    Label::new(i18n_key_tree(cx, "batch_ttl_condition"))
                        .text_xs()
                        .text_color(muted),
                )
                .child(
                    RadioGroup::vertical("batch-ttl-condition")
                        .selected_index(selected)
                        .children(
                            TTL_CONDITION_CHOICES
                                .iter()
                                .map(|(_, key)| Radio::new(*key).label(i18n_key_tree(cx, key))),
                        )
                        .on_click(cx.listener(|this, index: &usize, _window, cx| {
                            this.condition = TTL_CONDITION_CHOICES.get(*index).and_then(|(c, _)| *c);
                            cx.notify();
                        })),
                )
            })
    }
}

/// Ask for a TTL and hand it to `apply`. `prompt` says what it is for;
/// `show_condition` offers the `EXPIRE` conditions, which only a server
/// with the option words takes and only a set of keys needs — on one key or
/// one field they would say nothing the user does not already see.
pub(crate) fn open_ttl_dialog(
    prompt: SharedString,
    show_condition: bool,
    apply: impl Fn(u64, Option<ExpireCondition>, &mut App) + 'static,
    window: &mut Window,
    cx: &mut App,
) {
    let form = cx.new(|cx| TtlForm::new(prompt, show_condition, window, cx));
    let body = form.clone();
    let field = form.read(cx).ttl.clone();
    ZedisDialog::new(i18n_key_tree(cx, "batch_ttl_title"))
        .w(px(360.))
        .ok_text(i18n_key_tree(cx, "set_ttl_confirm"))
        .cancel_text(i18n_common(cx, "cancel"))
        .button_props(
            dialog_button_props(cx)
                .ok_text(i18n_key_tree(cx, "set_ttl_confirm"))
                .cancel_text(i18n_common(cx, "cancel")),
        )
        .child(move || body.clone())
        .on_ok(move |_, window, cx| match form.read(cx).submission(cx) {
            Some((secs, condition)) => {
                apply(secs, condition, cx);
                true
            }
            None => {
                window.push_notification(Notification::error(i18n_common(cx, "ttl_invalid")), cx);
                false
            }
        })
        .open(window, cx);
    // Opening the dialog takes the focus for it, so the field is focused
    // after: it is ready to type into without a click.
    field.update(cx, |field, cx| field.focus(window, cx));
}
