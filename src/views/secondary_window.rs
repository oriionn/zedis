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

use crate::helpers::{MemuAction, with_app_identity};
#[cfg(target_os = "macos")]
use gpui::WindowBounds;
use gpui::{
    AnyWindowHandle, App, AppContext, DisplayId, Entity, FocusHandle, Focusable, Global, KeyDownEvent, Pixels,
    SharedString, Window, WindowOptions, div, prelude::*, px,
};
use gpui_kit::component::{ActiveTheme, Root, StyledExt, h_flex, label::Label, v_flex};
use std::{any::TypeId, collections::HashMap, rc::Rc};

/// The `DisplayId` of the monitor the main (active) window is currently on, or
/// `None` if there's no active window. Pass it to `Bounds::centered` so a
/// secondary window (About / Settings) opens on the same monitor as the app
/// instead of always centering on the primary display.
pub fn active_window_display(cx: &mut App) -> Option<DisplayId> {
    let handle = cx.active_window()?;
    handle
        .update(cx, |_, window, cx| window.display(cx).map(|d| d.id()))
        .ok()
        .flatten()
}

/// Height of the title strip a secondary window draws for itself.
const TITLE_STRIP_HEIGHT: Pixels = px(28.);

/// On macOS a secondary window draws its own title strip, in the app
/// theme's colours: the system's title bar follows the *system* appearance,
/// so with the app set to Light on a Dark system (or the reverse) Settings
/// opened with a dark bar over a light page. The native bar is made
/// transparent — it still drags, and keeps its traffic lights — the window
/// grows by the strip so the content keeps its size, and the answer says
/// that [`SecondaryWindow`] is to draw the title.
#[cfg(target_os = "macos")]
fn own_title_strip(mut options: WindowOptions) -> (WindowOptions, bool) {
    let Some(titlebar) = options.titlebar.as_mut() else {
        return (options, false);
    };
    titlebar.appears_transparent = true;
    if let Some(WindowBounds::Windowed(bounds)) = options.window_bounds.as_mut() {
        bounds.size.height += TITLE_STRIP_HEIGHT;
    }
    (options, true)
}
/// Elsewhere the system's title bar stays: Windows and the Linux desktops
/// draw the window controls in it.
#[cfg(not(target_os = "macos"))]
fn own_title_strip(options: WindowOptions) -> (WindowOptions, bool) {
    (options, false)
}

/// A secondary window's title, asked for again on every render.
///
/// Settings is where the language is changed, and its title was translated
/// once, when the window opened: everything under it turned German and the
/// bar above went on saying "Settings". A title is therefore what it is read
/// from, not a string.
type WindowTitle = Rc<dyn Fn(&App) -> SharedString>;

/// Global registry that tracks open secondary windows by their content type.
/// Allows [`open_secondary_window`] to reuse an existing window instead of
/// opening a duplicate.
struct SecondaryWindowRegistry(HashMap<TypeId, AnyWindowHandle>);

impl Global for SecondaryWindowRegistry {}

impl SecondaryWindowRegistry {
    fn get(cx: &mut App) -> &mut Self {
        if cx.try_global::<Self>().is_none() {
            cx.set_global(Self(HashMap::new()));
        }
        cx.global_mut::<Self>()
    }
}

/// Wrapper view that takes focus on creation and closes the window on ESC.
///
/// Used as the content layer inside [`Root`] for all secondary windows
/// (settings, about, etc.) so that ESC-to-close behaviour is centralised
/// in one place rather than repeated per-window.
struct SecondaryWindow<V: Render + 'static> {
    focus_handle: FocusHandle,
    title: WindowTitle,
    /// What the system was last told the title is: the window's name in
    /// the window list, and the title bar itself where the system draws
    /// it (Windows, Linux).
    system_title: SharedString,
    /// Whether this view draws the title strip itself (macOS — see
    /// [`own_title_strip`]).
    draws_title_strip: bool,
    content: Entity<V>,
}

impl<V: Render + 'static> SecondaryWindow<V> {
    fn new(
        content: Entity<V>,
        title: WindowTitle,
        draws_title_strip: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let focus_handle = cx.focus_handle();
        focus_handle.focus(window, cx);
        Self {
            focus_handle,
            // The window was opened under this title.
            system_title: title(cx),
            title,
            draws_title_strip,
            content,
        }
    }
}

impl<V: Render + 'static> Focusable for SecondaryWindow<V> {
    fn focus_handle(&self, _cx: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl<V: Render + 'static> Render for SecondaryWindow<V> {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let title = (self.title)(cx);
        if title != self.system_title {
            window.set_window_title(&title);
            self.system_title = title.clone();
        }
        let title_strip = self.draws_title_strip.then(|| {
            h_flex()
                .flex_none()
                .w_full()
                .h(TITLE_STRIP_HEIGHT)
                .items_center()
                .justify_center()
                .bg(cx.theme().title_bar)
                .border_b_1()
                .border_color(cx.theme().title_bar_border)
                .child(Label::new(title).text_sm().font_medium())
        });
        v_flex()
            .size_full()
            .track_focus(&self.focus_handle)
            .capture_key_down(cx.listener(|_this, event: &KeyDownEvent, window, _cx| {
                if event.keystroke.key == "escape" {
                    window.remove_window();
                }
            }))
            // ⌘W / the Close Window menu item closes this window, and only
            // it. Answered here, ahead of the app-wide handler: that one
            // hides the whole app on macOS, which from Settings left the
            // Settings window open and the main window gone.
            .on_action(cx.listener(|_this, action: &MemuAction, window, cx| match action {
                MemuAction::Close => window.remove_window(),
                _ => cx.propagate(),
            }))
            .children(title_strip)
            .child(div().flex_1().min_h_0().w_full().child(self.content.clone()))
    }
}

/// Opens a secondary (non-main) window with ESC-to-close support.
///
/// If a window for the same content type `V` is already open it will be
/// activated instead of creating a duplicate.  The `build` closure receives
/// `(window, cx)` and should return the content entity.  The window is
/// automatically wrapped with [`Root`] (required by gpui_component widgets)
/// and [`SecondaryWindow`] (focus + ESC handling).
///
/// `title` is what the window is called, and is asked again whenever the
/// window is drawn — hand it the lookup (`|cx| i18n_settings(cx, "title")`),
/// not its answer, so a language change reaches the title too. It is written
/// into `options.titlebar` here; a caller leaves that title unset.
pub fn open_secondary_window<V, F>(
    mut options: WindowOptions,
    title: impl Fn(&App) -> SharedString + 'static,
    cx: &mut App,
    build: F,
) where
    V: Render + 'static,
    F: FnOnce(&mut Window, &mut App) -> Entity<V> + 'static,
{
    let type_id = TypeId::of::<V>();

    // Check whether a window for this type already exists and is still open.
    if let Some(handle) = SecondaryWindowRegistry::get(cx).0.get(&type_id).copied() {
        let still_open = handle.update(cx, |_, window, _| window.activate_window()).is_ok();
        if still_open {
            return;
        }
        // Window was closed — fall through to create a new one.
        SecondaryWindowRegistry::get(cx).0.remove(&type_id);
    }

    // Stamp Wayland app_id + default title/icon so secondary windows (About,
    // Settings, …) group with the main window and don't show the generic
    // "Wayland (W)" icon on KDE (issue #106). Caller-supplied title wins.
    let title: WindowTitle = Rc::new(title);
    if let Some(titlebar) = options.titlebar.as_mut() {
        titlebar.title = Some(title(cx));
    }
    let options = with_app_identity(options);
    let (options, draws_title_strip) = own_title_strip(options);

    if let Ok(handle) = cx.open_window(options, move |window, cx| {
        let content = build(window, cx);
        let wrapper = cx.new(|cx| SecondaryWindow::new(content, title, draws_title_strip, window, cx));
        cx.new(|cx| Root::new(wrapper, window, cx))
    }) {
        SecondaryWindowRegistry::get(cx).0.insert(type_id, handle.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::init_ui;
    use gpui::{TestAppContext, size};
    use gpui_kit::test::TestWindowExt;
    use std::cell::Cell;

    struct Blank;

    impl Render for Blank {
        fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
            div()
        }
    }

    /// The title is what it is read from at each draw, and the system is told
    /// when it changes: Settings opened in English and switched to German
    /// kept "Settings" over a German page, because the title was a string
    /// made when the window opened.
    #[gpui::test]
    fn the_title_follows_what_it_is_read_from(cx: &mut TestAppContext) {
        init_ui(cx);
        let language = Rc::new(Cell::new("Settings"));
        let source = language.clone();
        let mut wrapper = None;
        let handle = cx.open_window(size(px(400.), px(300.)), |window, cx| {
            let content = cx.new(|_| Blank);
            let title: WindowTitle = Rc::new(move |_| source.get().into());
            let view = cx.new(|cx| SecondaryWindow::new(content, title, true, window, cx));
            wrapper = Some(view.clone());
            Root::new(view, window, cx)
        });
        let wrapper = wrapper.expect("the window built its wrapper");
        cx.update_window(handle.into(), |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(wrapper.read(cx).system_title, "Settings");
        })
        .expect("the window is open");

        // What saving a language does: every window is drawn again.
        language.set("Einstellungen");
        cx.update(|cx| cx.refresh_windows());
        cx.update_window(handle.into(), |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(wrapper.read(cx).system_title, "Einstellungen");
        })
        .expect("the window is open");
    }
}
