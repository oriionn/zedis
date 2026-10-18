// What the bridge's own pages share (ADR 17): the sign-in page (`index.html`)
// and the account page (`account.html`). Plain HTML and a little script, on
// purpose — they are the web version's alone, and as pages rather than GPUI
// views the desktop cannot see them by construction.

// Where the page was served from, without the trailing slash: the origin,
// or the origin plus the bridge's `--base-path`. Everything is addressed
// from here and never from `/`, which belongs to the neighbours.
export const root = new URL(".", window.location.href).href.replace(/\/$/, "");

export const api = (path, init) => fetch(root + path, { credentials: "same-origin", ...init });

/** `api` with a JSON body. */
export const send = (method, path, body) =>
  api(path, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

const SUPPORTED_LOCALES = ["en", "zh", "de", "es", "fr", "ja", "pt", "ru"];

// The language the application itself shows: the preference it saved in
// `localStorage` (`zedis:zedis.toml`), else the browser's. Same rule as the
// wasm's, so the sign-in page and the application never disagree.
export function preferredLocale() {
  try {
    const toml = localStorage.getItem("zedis:zedis.toml") || "";
    const m = toml.match(/^\s*locale\s*=\s*"([a-z]+)"/m);
    if (m && SUPPORTED_LOCALES.includes(m[1])) return m[1];
  } catch {
    // private mode / denied storage: fall through to the browser language
  }
  const lang = (navigator.language || "en").split("-")[0].toLowerCase();
  return SUPPORTED_LOCALES.includes(lang) ? lang : "en";
}

// The `key = "value"` lines of one `[section]` of a TOML file. The pages'
// section holds single-line basic strings only, whose escapes are JSON's.
function section(text, name) {
  const out = {};
  let inside = false;
  for (const line of text.split("\n")) {
    const header = line.match(/^\s*\[([^\]]+)\]\s*$/);
    if (header) {
      inside = header[1].trim() === name;
      continue;
    }
    if (!inside) continue;
    const m = line.match(/^\s*([A-Za-z0-9_]+)\s*=\s*("(?:[^"\\]|\\.)*")\s*$/);
    if (m) {
      try {
        out[m[1]] = JSON.parse(m[2]);
      } catch {
        // a line it cannot read falls back to English
      }
    }
  }
  return out;
}

/**
 * The pages' strings — the `[web_account]` section of the application's
 * own locale files, English underneath the chosen language — and a `t` that
 * fills in `%{name}`. `url` is how a page addresses a file it fetches (the
 * sign-in page versions them).
 */
export async function loadStrings(url = (path) => `${root}/${path}`) {
  const locale = preferredLocale();
  const names = locale === "en" ? ["en"] : ["en", locale];
  const texts = await Promise.all(
    names.map(async (name) => {
      try {
        const res = await fetch(url(`locales/${name}.toml`));
        return res.ok ? await res.text() : "";
      } catch {
        return "";
      }
    }),
  );
  const strings = {};
  for (const text of texts) Object.assign(strings, section(text, "web_account"));
  document.documentElement.lang = locale;
  const t = (key, vars = {}) =>
    (strings[key] ?? key).replace(/%\{(\w+)\}/g, (_, name) => (vars[name] ?? "").toString());
  return { locale, t };
}

/** Every `data-i18n` element gets its text, every `data-i18n-placeholder` its placeholder. */
export function localize(t, scope = document) {
  for (const el of scope.querySelectorAll("[data-i18n]")) el.textContent = t(el.dataset.i18n);
  for (const el of scope.querySelectorAll("[data-i18n-placeholder]")) {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  }
}

/** What the bridge said about a refused request: its message, else the status. */
export async function failure(res) {
  try {
    const body = await res.json();
    return body.message || body.error || `HTTP ${res.status}`;
  } catch {
    return `HTTP ${res.status}`;
  }
}

/** The string key of a role as the bridge spells it (`admin`, `full`, `read_only`). */
export const roleKey = (role) => ({ admin: "role_admin", full: "role_full", read_only: "role_read_only" })[role] || role;

/** Unix seconds as the reader's date and time. */
export const when = (secs, locale) => new Date(secs * 1000).toLocaleString(locale);

/** An element, its text set — never its HTML: names here are what people typed. */
export function el(tag, text, attrs = {}) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = text;
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
  return node;
}
