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

//! The placeholders of a view that outlives a language change.
//!
//! A label is worded again on every render, so it follows the language the
//! moment the user picks another. A text field's placeholder is not: it is a
//! string the field's state keeps from when the view built it. The views kept
//! for a whole server session — the key tree, the editor and the value
//! editors it caches, the server list — went on showing the language they
//! were built in (#198). Such a view registers each field once with the
//! function that words it ([`Placeholders::add`], which also words it now)
//! and calls [`Placeholders::follow`] at the top of its `render`, which words
//! them all again when the language is not the one they were worded in.
//!
//! A view built again often enough not to need it — a dialog, a tool panel
//! (rebuilt when its route is visited again), a value editor dropped on each
//! load — keeps setting its placeholder where it builds the field.

use crate::states::ZedisGlobalStore;
use gpui::{App, Context, Entity, SharedString, Window};
use gpui_kit::component::input::{EditorState, InputState};

/// A field state whose placeholder can be set after it is built. The kit
/// shares `set_placeholder` among its input states through a type it does
/// not export, so each one the app registers says so here.
pub(crate) trait WordedField: Sized + 'static {
    fn word(&mut self, text: SharedString, window: &mut Window, cx: &mut Context<Self>);
}

impl WordedField for InputState {
    fn word(&mut self, text: SharedString, window: &mut Window, cx: &mut Context<Self>) {
        self.set_placeholder(text, window, cx);
    }
}

impl WordedField for EditorState {
    fn word(&mut self, text: SharedString, window: &mut Window, cx: &mut Context<Self>) {
        self.set_placeholder(text, window, cx);
    }
}

type Wording = Box<dyn Fn(&mut Window, &mut App)>;

pub(crate) struct Placeholders {
    /// The language the fields were last worded in.
    locale: String,
    fields: Vec<Wording>,
}

impl Placeholders {
    pub(crate) fn new(cx: &App) -> Self {
        Self {
            locale: cx.global::<ZedisGlobalStore>().read(cx).locale().to_string(),
            fields: Vec::new(),
        }
    }

    /// Word `field`'s placeholder now, and again after each language change.
    pub(crate) fn add<T: WordedField>(
        &mut self,
        field: &Entity<T>,
        wording: impl Fn(&App) -> SharedString + 'static,
        window: &mut Window,
        cx: &mut App,
    ) {
        let field = field.downgrade();
        let word = move |window: &mut Window, cx: &mut App| {
            let text = wording(cx);
            // A field the view has already dropped has nothing to word.
            let _ = field.update(cx, |field, cx| field.word(text, window, cx));
        };
        word(window, cx);
        self.fields.push(Box::new(word));
    }

    /// Word every field again if the language changed since they were.
    pub(crate) fn follow(&mut self, window: &mut Window, cx: &mut App) {
        if cx.global::<ZedisGlobalStore>().read(cx).locale() == self.locale {
            return;
        }
        self.locale = cx.global::<ZedisGlobalStore>().read(cx).locale().to_string();
        for word in &self.fields {
            word(window, cx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::states::i18n_common;
    use crate::test_support::init_ui;
    use gpui::{AppContext, IntoElement, Render, TestAppContext, div, px, size};
    use gpui_kit::component::Root;
    use gpui_kit::test::TestWindowExt;

    struct Field {
        input: Entity<InputState>,
        placeholders: Placeholders,
    }

    impl Render for Field {
        fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
            self.placeholders.follow(window, cx);
            div()
        }
    }

    fn set_locale(locale: &str, cx: &mut TestAppContext) {
        let locale = locale.to_string();
        cx.update(|cx| {
            let store = cx.global::<ZedisGlobalStore>().clone();
            store.update(cx, |state, _| state.set_locale(locale));
        });
    }

    /// A field registered once is worded in the language of the moment,
    /// and again in the next one after the user picks it (#198).
    #[gpui::test]
    fn a_placeholder_follows_a_language_change(cx: &mut TestAppContext) {
        init_ui(cx);
        set_locale("en", cx);
        let mut view = None;
        let handle = cx.open_window(size(px(300.), px(100.)), |window, cx| {
            let input = cx.new(|cx| InputState::new(window, cx));
            let mut placeholders = Placeholders::new(cx);
            placeholders.add(&input, |cx| i18n_common(cx, "keyword_placeholder"), window, cx);
            let field = cx.new(|_| Field { input, placeholders });
            view = Some(field.clone());
            Root::new(field, window, cx)
        });
        let view = view.expect("the window built the view");
        let placeholder = |cx: &mut TestAppContext| {
            view.read_with(cx, |view, cx| {
                view.input.read(cx).presentation().placeholder().to_string()
            })
        };
        assert_eq!(placeholder(cx), "Filter by keyword");

        set_locale("zh", cx);
        cx.update_window(handle.into(), |_, window, cx| window.render_frame(cx))
            .expect("the window is open");
        assert_eq!(placeholder(cx), "按关键词过滤");
    }
}
