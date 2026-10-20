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

//! The page's own files: served from the build compiled in (or `--static`),
//! under the base path, compressed as the build made them.

use super::*;

/// What a request path names below `base_path`.
#[derive(Debug, PartialEq, Eq)]
enum Mounted<'a> {
    /// A path of the web build, prefix removed (`/`, `/wasm/zedis_web.js`).
    File(&'a str),
    /// The base path without its trailing slash. Only `/zedis/` is a
    /// directory to the browser: from `/zedis` the page's `./wasm/…` and
    /// `v1/…` would resolve against the site root — the neighbours' paths.
    NeedsSlash,
    /// Not under the base path: someone else's, and not confirmed to exist.
    Outside,
}

fn mounted<'a>(base_path: &str, request_path: &'a str) -> Mounted<'a> {
    if base_path.is_empty() {
        return Mounted::File(request_path);
    }
    match request_path.strip_prefix(base_path) {
        Some("") => Mounted::NeedsSlash,
        // `/zedisx` also starts with `/zedis`: the rest has to be a path.
        Some(rest) if rest.starts_with('/') => Mounted::File(rest),
        _ => Mounted::Outside,
    }
}

/// `--base-path` / `ZEDIS_BRIDGE_BASE_PATH` as the router and the cookie
/// want it: empty for the root (`""`, `/`), else `/prefix` with a leading
/// slash and no trailing one. Refused rather than repaired when it could
/// not be a plain path: it ends up in a route pattern and in a `Set-Cookie`
/// header, where `{`, `;` or a space would each mean something else.
pub fn normalize_base_path(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~');
    for segment in trimmed.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." || !segment.chars().all(plain) {
            return Err(format!(
                "base path {raw:?}: each segment may hold letters, digits and - _ . ~ only"
            ));
        }
    }
    Ok(format!("/{trimmed}"))
}

/// A file of the web build as it is about to be sent.
struct StoredFile {
    /// Static when it is embedded: the binary's own read-only pages, sent
    /// without a copy.
    bytes: Bytes,
    /// Its SHA-256 where one is already known (rust-embed computes it at
    /// build time, and an inflated embedded body is hashed once); `None` for
    /// a file off disk, which is hashed when the `ETag` is made.
    hash: Option<[u8; 32]>,
}

/// Embedded files inflated for a caller that accepts no coding, by the
/// stored file's hash: the body and its own hash. The embedded build cannot
/// change while the bridge runs, so this costs one inflate and one SHA-256
/// per file per process — where every such request, a `304` included, used
/// to inflate the 20 MB module again and hash it to learn its `ETag`.
static INFLATED: LazyLock<Mutex<HashMap<Sha256Hash, (Bytes, Sha256Hash)>>> = LazyLock::new(Default::default);

/// A SHA-256 digest, as rust-embed hands one over.
type Sha256Hash = [u8; 32];

/// `stored`'s gzip inflated, off the async threads, and remembered when the
/// file is an embedded one (it has a hash).
async fn inflated(stored: StoredFile) -> std::io::Result<StoredFile> {
    let cached = |hash: &[u8; 32]| {
        INFLATED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(hash)
            .cloned()
    };
    if let Some(stored_hash) = stored.hash
        && let Some((bytes, hash)) = cached(&stored_hash)
    {
        return Ok(StoredFile {
            bytes,
            hash: Some(hash),
        });
    }
    let StoredFile { bytes, hash } = stored;
    tokio::task::spawn_blocking(move || {
        let raw = Bytes::from(static_files::inflate(&bytes)?);
        let Some(stored_hash) = hash else {
            return Ok(StoredFile { bytes: raw, hash: None });
        };
        let raw_hash: [u8; 32] = Sha256::digest(&raw).into();
        INFLATED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(stored_hash, (raw.clone(), raw_hash));
        Ok(StoredFile {
            bytes: raw,
            hash: Some(raw_hash),
        })
    })
    .await
    .map_err(std::io::Error::other)?
}

/// Anything that is not an API route is a file of the web build: the one
/// compiled into this binary, or — with `--static <dir>` — a directory on
/// disk instead.
///
/// Unauthenticated on purpose: the page has to load before anyone can log in,
/// and it is a client application, not data. Everything it then asks for is
/// behind the cookie.
///
/// Two things keep the 20 MB module from being 20 MB on the wire. It is sent
/// in the best coding the caller accepts that is stored beside it (`.br`,
/// `.gz` — see `static_files::negotiate`), which is a quarter of the bytes.
/// And every answer carries an `ETag`. The page stays `no-cache` (it carries
/// the content hashes) so a new bundle is noticed; a `?v=<md5>` URL is
/// immutable for a year. The validator is what lets a `no-cache` revalidation
/// be a `304` with no body rather than the whole module again.
pub(super) async fn web_asset(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    let not_found = || (StatusCode::NOT_FOUND, "not found").into_response();
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let file_path = match mounted(&state.base_path, uri.path()) {
        Mounted::File(path) => path,
        Mounted::NeedsSlash => {
            let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
            return Redirect::temporary(&format!("{}/{query}", state.base_path)).into_response();
        }
        Mounted::Outside => return not_found(),
    };
    let Some(key) = static_files::request_key(file_path) else {
        return not_found();
    };
    let accept_encoding = header("accept-encoding").unwrap_or_default();

    // The stored file a key names, and its hash when one is already known.
    let root = state.web_root.as_deref();
    let representation = match root {
        Some(root) => static_files::negotiate(&key, accept_encoding, |k| static_files::resolve(root, k).is_some()),
        None => static_files::negotiate(&key, accept_encoding, static_files::embedded_has),
    };
    let Some(representation) = representation else {
        return not_found();
    };
    let (stored_key, encoding, inflate) = match &representation {
        Representation::Stored { key, encoding } => (key, *encoding, false),
        Representation::Inflated { key } => (key, None, true),
    };
    let stored = match root {
        Some(root) => match static_files::resolve(root, stored_key) {
            Some(path) => tokio::fs::read(&path).await.ok().map(|bytes| StoredFile {
                bytes: Bytes::from(bytes),
                hash: None,
            }),
            None => None,
        },
        None => WebBuild::get(stored_key).map(|file| StoredFile {
            hash: Some(file.metadata.sha256_hash()),
            // Borrowed is the release case: `from_static` sends the binary's
            // own pages without a copy.
            bytes: match file.data {
                Cow::Borrowed(bytes) => Bytes::from_static(bytes),
                Cow::Owned(bytes) => Bytes::from(bytes),
            },
        }),
    };
    let Some(stored) = stored else {
        return not_found();
    };
    let StoredFile { bytes, hash } = if inflate {
        match inflated(stored).await {
            Ok(raw) => raw,
            Err(e) => {
                tracing::error!(error = %e, key = stored_key.as_str(), "a stored gzip could not be inflated");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    } else {
        stored
    };
    // The page, with the hashes of what it fetches filled in — and its tag
    // that of what is sent, so a new bundle is a new page.
    let (bytes, hash) = if key == static_files::PAGE {
        let root = root.map(FsPath::to_path_buf);
        let map = tokio::task::spawn_blocking(move || match root {
            Some(root) => static_files::directory_asset_map(&root),
            None => static_files::embedded_asset_map(),
        })
        .await
        .unwrap_or_default();
        (Bytes::from(static_files::with_asset_map(&bytes, &map)), None)
    } else {
        (bytes, hash)
    };
    let etag = hash
        .map(static_files::etag)
        .unwrap_or_else(|| static_files::etag_of(&bytes));

    let mut response = Response::builder()
        .header("etag", &etag)
        .header("cache-control", static_files::cache_control(uri.query()))
        .header("vary", "Accept-Encoding");
    if static_files::matches_etag(header("if-none-match"), &etag) {
        return response
            .status(StatusCode::NOT_MODIFIED)
            .body(Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    // The type is the requested file's, not the `.gz` beside it: the coding
    // is a property of the transfer, which is what `Content-Encoding` says.
    response = response.header("content-type", static_files::content_type(FsPath::new(&key)));
    if let Some(encoding) = encoding {
        response = response.header("content-encoding", encoding);
    }
    response
        .body(Body::from(bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod base_path_tests {
    use super::{Mounted, mounted, normalize_base_path};

    #[test]
    fn a_request_is_a_file_below_the_base_path_or_it_is_not_ours() {
        // At the root every path is a file of the build, as before.
        assert_eq!(mounted("", "/"), Mounted::File("/"));
        assert_eq!(mounted("", "/wasm/zedis_web.js"), Mounted::File("/wasm/zedis_web.js"));

        assert_eq!(mounted("/zedis", "/zedis/"), Mounted::File("/"));
        assert_eq!(mounted("/zedis", "/zedis/fonts/a.ttf"), Mounted::File("/fonts/a.ttf"));
        assert_eq!(mounted("/zedis", "/zedis"), Mounted::NeedsSlash);
        // A neighbour whose name merely starts the same way, and the site
        // root, are not this bridge's to answer.
        assert_eq!(mounted("/zedis", "/zedisx/"), Mounted::Outside);
        assert_eq!(mounted("/zedis", "/"), Mounted::Outside);
        assert_eq!(mounted("/zedis", "/v1/health"), Mounted::Outside);
    }

    #[test]
    fn a_base_path_is_a_leading_slash_and_no_trailing_one() {
        for root in ["", "/", "  ", "///"] {
            assert_eq!(normalize_base_path(root), Ok(String::new()), "{root:?} is the root");
        }
        for spelling in ["zedis", "/zedis", "zedis/", "/zedis/", " /zedis/ "] {
            assert_eq!(normalize_base_path(spelling), Ok("/zedis".to_string()), "{spelling:?}");
        }
        assert_eq!(
            normalize_base_path("/tools/zedis-web_1.0~x"),
            Ok("/tools/zedis-web_1.0~x".to_string())
        );
    }

    #[test]
    fn a_base_path_that_means_something_else_in_a_route_or_a_cookie_is_refused() {
        // `{id}` is a capture to the router; `;` and a space end the cookie's
        // `Path` attribute; `..` and an empty segment are not a place.
        for bad in [
            "/{id}", "/a;b", "/a b", "/a/../b", "/a//b", "/./a", "/a?b", "/a#b", "/中",
        ] {
            assert!(normalize_base_path(bad).is_err(), "{bad:?} was accepted");
        }
    }
}
