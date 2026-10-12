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

//! Line diff for the value diff view, and the patch it is drawn from.
//!
//! Hand-rolled instead of pulling `similar` or `diff-rs`, matching the
//! project's policy of preferring in-crate implementations for
//! self-contained needs. The value diff opens on values of a few MiB — a
//! 1 MiB JSON document pretty-prints to about 120,000 lines — so the diff
//! trims what the two sides share at either end, splits what is left at the
//! lines that occur exactly once on each side (patience diff), and runs a
//! plain LCS only on the pieces between them, which are small.
//!
//! [`line_diff`] answers ops in order: each either matches a left/right line
//! pair (`Equal`), shows a deleted-only left line (`Delete`), or an
//! inserted-only right line (`Insert`). [`whole_patch`] writes them out as one
//! unified patch that holds every line of both texts, which is what the view
//! hands to gpui-kit's `Diff` component: the comparing stays here, the
//! drawing — panes, folds, wrapping, the words that changed within a line —
//! is the component's. [`wrap_line`] is what is left of the old layout, for
//! the plain block of text the view still lists itself.

use std::collections::HashMap;
use std::ops::Range;

/// One row of a side-by-side line diff. Indices reference the original
/// input slices, kept around so the view can show "L23" / "R24" line
/// numbers without re-counting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffOp {
    /// Both sides have the same line. Stored as `(left_idx, right_idx)`.
    Equal(usize, usize),
    /// Left side has a line the right side does not. `usize` is the
    /// left index.
    Delete(usize),
    /// Right side has a line the left side does not. `usize` is the
    /// right index.
    Insert(usize),
}

/// Cells an LCS table may have: `n·m` for the two sides of one piece, `u32`
/// each, so 4 MiB at most. A larger piece is split at unique lines first,
/// and one with none to split at is shown as replaced.
const MAX_LCS_CELLS: usize = 1 << 20;

/// Compute a side-by-side line diff between `left` and `right`.
///
/// Lines keep their endings: `lines()` reads `\r\n` and `\n` alike, so two
/// values that differed only there compared line-equal while the texts were
/// not — neither "identical" nor any line marked. Same line count as
/// `lines()`, so the indices still name the lines a view draws.
///
/// Common lines at both ends are matched first; the middle is split at lines
/// found exactly once on each side, in the order both agree on (the longest
/// increasing run of them — patience diff), and each piece between two such
/// anchors is diffed the same way, down to pieces small enough for an exact
/// LCS. A piece too large for one and without an anchor is shown as all
/// deleted, then all inserted. Runs without recursion, so a pathological
/// input cannot exhaust the stack.
pub fn line_diff(left: &str, right: &str) -> Vec<DiffOp> {
    let left_lines: Vec<&str> = left.split_inclusive('\n').collect();
    let right_lines: Vec<&str> = right.split_inclusive('\n').collect();
    let n = left_lines.len();
    let m = right_lines.len();

    // Fast path: identical content.
    if left == right {
        return (0..n).map(|i| DiffOp::Equal(i, i)).collect();
    }

    let mut out = Vec::with_capacity(n.max(m));
    let mut stack = vec![Work::Diff(0..n, 0..m)];
    while let Some(work) = stack.pop() {
        match work {
            Work::Equal(a, b) => out.push(DiffOp::Equal(a, b)),
            Work::EqualRun(a, b, count) => out.extend((0..count).map(|k| DiffOp::Equal(a + k, b + k))),
            Work::Diff(a, b) => diff_piece(&left_lines, &right_lines, a, b, &mut out, &mut stack),
        }
    }
    out
}

/// What is left to emit, last first: the ops of a piece come out in order
/// because each piece pushes what follows it before what it emits itself.
enum Work {
    Diff(Range<usize>, Range<usize>),
    Equal(usize, usize),
    EqualRun(usize, usize, usize),
}

/// Diff `left[a]` against `right[b]`: emit what can be emitted now (the
/// common prefix, then the middle when it is simple), and push the rest.
fn diff_piece(
    left: &[&str],
    right: &[&str],
    mut a: Range<usize>,
    mut b: Range<usize>,
    out: &mut Vec<DiffOp>,
    stack: &mut Vec<Work>,
) {
    while !a.is_empty() && !b.is_empty() && left[a.start] == right[b.start] {
        out.push(DiffOp::Equal(a.start, b.start));
        a.start += 1;
        b.start += 1;
    }
    let mut tail = 0;
    while !a.is_empty() && !b.is_empty() && left[a.end - 1] == right[b.end - 1] {
        a.end -= 1;
        b.end -= 1;
        tail += 1;
    }
    if tail > 0 {
        stack.push(Work::EqualRun(a.end, b.end, tail));
    }
    if a.is_empty() || b.is_empty() {
        out.extend(a.map(DiffOp::Delete));
        out.extend(b.map(DiffOp::Insert));
        return;
    }
    if a.len().saturating_mul(b.len()) <= MAX_LCS_CELLS {
        lcs_diff(left, right, a, b, out);
        return;
    }
    let anchors = unique_anchors(left, right, a.clone(), b.clone());
    if anchors.is_empty() {
        out.extend(a.map(DiffOp::Delete));
        out.extend(b.map(DiffOp::Insert));
        return;
    }
    // Pushed last-first: the piece after the last anchor, then each anchor
    // and the piece before it.
    let (last_a, last_b) = anchors[anchors.len() - 1];
    stack.push(Work::Diff(last_a + 1..a.end, last_b + 1..b.end));
    for window in (0..anchors.len()).rev() {
        let (anchor_a, anchor_b) = anchors[window];
        stack.push(Work::Equal(anchor_a, anchor_b));
        let (from_a, from_b) = match window {
            0 => (a.start, b.start),
            _ => (anchors[window - 1].0 + 1, anchors[window - 1].1 + 1),
        };
        stack.push(Work::Diff(from_a..anchor_a, from_b..anchor_b));
    }
}

/// Lines found exactly once in `left[a]` and exactly once in `right[b]`,
/// as `(left, right)` index pairs, reduced to the longest run whose right
/// indices increase with the left ones — the matches both sides agree on
/// the order of.
fn unique_anchors(left: &[&str], right: &[&str], a: Range<usize>, b: Range<usize>) -> Vec<(usize, usize)> {
    // Per line: (count on the left, count on the right, left index, right index).
    let mut seen: HashMap<&str, (u32, u32, usize, usize)> = HashMap::with_capacity(a.len());
    for i in a.clone() {
        let entry = seen.entry(left[i]).or_insert((0, 0, i, 0));
        entry.0 += 1;
    }
    for j in b {
        if let Some(entry) = seen.get_mut(right[j]) {
            entry.1 += 1;
            entry.3 = j;
        }
    }
    let pairs: Vec<(usize, usize)> = a
        .filter_map(|i| match seen.get(left[i]) {
            Some(&(1, 1, li, rj)) if li == i => Some((li, rj)),
            _ => None,
        })
        .collect();
    longest_increasing_run(&pairs)
}

/// The longest subsequence of `pairs` (sorted by left index) whose right
/// indices increase — patience sorting, `O(k log k)`.
fn longest_increasing_run(pairs: &[(usize, usize)]) -> Vec<(usize, usize)> {
    // `tails[len]`: index into `pairs` of the smallest right index that ends
    // an increasing run of `len + 1`; `back[i]`: the pair before `i` in the
    // run it ends.
    let mut tails: Vec<usize> = Vec::new();
    let mut back: Vec<Option<usize>> = vec![None; pairs.len()];
    for (i, &(_, right)) in pairs.iter().enumerate() {
        let len = tails.partition_point(|&t| pairs[t].1 < right);
        back[i] = len.checked_sub(1).map(|prev| tails[prev]);
        if len == tails.len() {
            tails.push(i);
        } else {
            tails[len] = i;
        }
    }
    let mut run = Vec::with_capacity(tails.len());
    let mut at = tails.last().copied();
    while let Some(i) = at {
        run.push(pairs[i]);
        at = back[i];
    }
    run.reverse();
    run
}

/// Exact LCS diff of `left[a]` against `right[b]`: a table of LCS lengths,
/// then a walk back from the end. When deletion and insertion score the
/// same the walk takes the insertion first, so in the output a change's
/// deletions come before its insertions, as `diff(1)` prints them.
fn lcs_diff(left: &[&str], right: &[&str], a: Range<usize>, b: Range<usize>, out: &mut Vec<DiffOp>) {
    let (n, m) = (a.len(), b.len());
    let width = m + 1;
    // `lens[i * width + j]`: LCS length of the first `i` left and `j` right lines.
    let mut lens = vec![0_u32; (n + 1) * width];
    for i in 0..n {
        for j in 0..m {
            lens[(i + 1) * width + j + 1] = if left[a.start + i] == right[b.start + j] {
                lens[i * width + j] + 1
            } else {
                lens[(i + 1) * width + j].max(lens[i * width + j + 1])
            };
        }
    }
    let mut ops: Vec<DiffOp> = Vec::with_capacity(n + m);
    let (mut i, mut j) = (n, m);
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && left[a.start + i - 1] == right[b.start + j - 1] {
            ops.push(DiffOp::Equal(a.start + i - 1, b.start + j - 1));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || lens[i * width + j - 1] >= lens[(i - 1) * width + j]) {
            ops.push(DiffOp::Insert(b.start + j - 1));
            j -= 1;
        } else {
            ops.push(DiffOp::Delete(a.start + i - 1));
            i -= 1;
        }
    }
    out.extend(ops.into_iter().rev());
}

/// Both texts as one unified patch: see [`whole_patch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WholePatch {
    /// `--- a/<name>`, `+++ b/<name>`, then one hunk with every line of both
    /// sides in it.
    pub text: String,
    /// Lines only the left side has, and lines only the right side has.
    pub removed: usize,
    pub added: usize,
    /// Runs of changed lines: what "next change" steps through.
    pub changes: usize,
}

/// What marks a line whose `\r\n` ending is part of the change.
const CARRIAGE_RETURN_MARK: char = '\u{240D}';
/// The unified format's own line for a side that ends without a newline.
const NO_FINAL_NEWLINE: &str = "\\ No newline at end of file\n";

/// `left` and `right` as one unified patch named `name`, with every line of
/// both in a single hunk — the unchanged ones as context — so a viewer can
/// fold them and open them again without asking for more.
///
/// Every line is written behind its ` `, `-` or `+`, so a value that looks
/// like a patch itself (`--- a`, `@@ -1 +1 @@`) is only ever a line of
/// content. Two things a patch line cannot show are said another way, and
/// only where they are the change: a `\r\n` ending is drawn as `␍` on a line
/// that differs, and a final newline one side lacks is the format's own "No
/// newline at end of file". Where both sides agree neither is mentioned.
pub fn whole_patch(name: &str, left: &str, right: &str) -> WholePatch {
    let left_lines: Vec<&str> = left.split_inclusive('\n').collect();
    let right_lines: Vec<&str> = right.split_inclusive('\n').collect();
    let ops = line_diff(left, right);
    let unterminated = |text: &str| !text.is_empty() && !text.ends_with('\n');
    let endings_differ = unterminated(left) != unterminated(right);
    let start = |count: usize| usize::from(count > 0);

    let mut text = String::with_capacity(left.len() + right.len() / 4 + ops.len() + 64);
    text.push_str(&format!(
        "--- a/{name}\n+++ b/{name}\n@@ -{},{} +{},{} @@\n",
        start(left_lines.len()),
        left_lines.len(),
        start(right_lines.len()),
        right_lines.len()
    ));
    let (mut removed, mut added, mut changes) = (0, 0, 0);
    let mut in_change = false;
    for op in &ops {
        let (mark, raw, last_of_its_side) = match *op {
            DiffOp::Equal(l, _) => (' ', left_lines[l], false),
            DiffOp::Delete(l) => ('-', left_lines[l], l + 1 == left_lines.len() && unterminated(left)),
            DiffOp::Insert(r) => ('+', right_lines[r], r + 1 == right_lines.len() && unterminated(right)),
        };
        let changed = mark != ' ';
        match mark {
            '-' => removed += 1,
            '+' => added += 1,
            _ => {}
        }
        if changed && !in_change {
            changes += 1;
        }
        in_change = changed;

        let line = raw.strip_suffix('\n').unwrap_or(raw);
        let (line, carriage_return) = match line.strip_suffix('\r') {
            Some(line) => (line, true),
            None => (line, false),
        };
        text.push(mark);
        text.push_str(line);
        if changed && carriage_return {
            text.push(CARRIAGE_RETURN_MARK);
        }
        text.push('\n');
        if endings_differ && last_of_its_side {
            text.push_str(NO_FINAL_NEWLINE);
        }
    }
    WholePatch {
        text,
        removed,
        added,
        changes,
    }
}

/// `line` cut into pieces of at most `columns` columns, as byte ranges: at
/// least one (an empty line is one empty piece). A wide character — CJK,
/// Hangul, full-width forms — takes two columns, as a monospace font draws
/// it; ASCII is sliced by bytes without looking at characters.
pub fn wrap_line(line: &str, columns: usize) -> Vec<Range<usize>> {
    let columns = columns.max(1);
    if line.is_ascii() {
        let mut pieces: Vec<Range<usize>> = (0..line.len())
            .step_by(columns)
            .map(|start| start..(start + columns).min(line.len()))
            .collect();
        if pieces.is_empty() {
            pieces.push(0..0);
        }
        return pieces;
    }
    let mut pieces = Vec::new();
    let (mut start, mut used) = (0, 0);
    for (at, ch) in line.char_indices() {
        let width = char_columns(ch);
        if used + width > columns && at > start {
            pieces.push(start..at);
            start = at;
            used = 0;
        }
        used += width;
    }
    pieces.push(start..line.len());
    pieces
}

/// Columns `ch` takes in a monospace font: two for the East Asian wide and
/// full-width blocks, one otherwise.
fn char_columns(ch: char) -> usize {
    match u32::from(ch) {
        0x1100..=0x115F
        | 0x2E80..=0x303E
        | 0x3041..=0x33FF
        | 0x3400..=0x4DBF
        | 0x4E00..=0x9FFF
        | 0xA000..=0xA4CF
        | 0xAC00..=0xD7A3
        | 0xF900..=0xFAFF
        | 0xFE30..=0xFE4F
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6
        | 0x1F300..=0x1F64F
        | 0x1F900..=0x1F9FF
        | 0x20000..=0x3FFFD => 2,
        _ => 1,
    }
}

/// How a key changed between two key→value snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvDelta {
    /// Key exists only in the new snapshot.
    Added,
    /// Key exists only in the old snapshot.
    Removed,
    /// Key exists in both with different values.
    Changed,
}

/// One differing entry of a key→value snapshot comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvDiffEntry {
    pub key: String,
    /// Value in the old snapshot (`None` for [`KvDelta::Added`]).
    pub old: Option<String>,
    /// Value in the new snapshot (`None` for [`KvDelta::Removed`]).
    pub new: Option<String>,
    pub delta: KvDelta,
}

/// Field-level comparison of two key→value snapshots (e.g. two `INFO`
/// captures). Unlike [`line_diff`] this is order-insensitive: a key that
/// merely moved produces no entry, so section reordering between
/// captures doesn't drown the real changes in noise. Unchanged pairs are
/// omitted. Entries follow the new snapshot's order, with removed keys
/// appended in old-snapshot order. Duplicate keys keep the last value.
pub fn kv_diff(old: &[(String, String)], new: &[(String, String)]) -> Vec<KvDiffEntry> {
    use std::collections::{HashMap, HashSet};

    let old_map: HashMap<&str, &str> = old.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let new_keys: HashSet<&str> = new.iter().map(|(k, _)| k.as_str()).collect();

    let mut out = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for (key, value) in new {
        // Only diff a duplicated key once, against its last value.
        if !seen.insert(key.as_str()) {
            continue;
        }
        let value = new
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or(value);
        match old_map.get(key.as_str()) {
            None => out.push(KvDiffEntry {
                key: key.clone(),
                old: None,
                new: Some(value.to_string()),
                delta: KvDelta::Added,
            }),
            Some(old_value) if *old_value != value => out.push(KvDiffEntry {
                key: key.clone(),
                old: Some((*old_value).to_string()),
                new: Some(value.to_string()),
                delta: KvDelta::Changed,
            }),
            Some(_) => {}
        }
    }
    for (key, value) in old {
        if !new_keys.contains(key.as_str()) && seen.insert(key.as_str()) {
            out.push(KvDiffEntry {
                key: key.clone(),
                old: Some(value.clone()),
                new: None,
                delta: KvDelta::Removed,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{DiffOp, KvDelta, kv_diff, line_diff, whole_patch, wrap_line};

    /// Every left line exactly once, in order, from `Equal` / `Delete`;
    /// every right line likewise from `Equal` / `Insert`; and an `Equal`
    /// pairs lines that are the same.
    fn assert_valid(ops: &[DiffOp], left: &str, right: &str) {
        let l: Vec<&str> = left.split_inclusive('\n').collect();
        let r: Vec<&str> = right.split_inclusive('\n').collect();
        let (mut next_l, mut next_r) = (0, 0);
        for op in ops {
            match *op {
                DiffOp::Equal(a, b) => {
                    assert_eq!((a, b), (next_l, next_r), "out of order at {op:?}");
                    assert_eq!(l[a], r[b], "unequal lines paired at {op:?}");
                    next_l += 1;
                    next_r += 1;
                }
                DiffOp::Delete(a) => {
                    assert_eq!(a, next_l, "out of order at {op:?}");
                    next_l += 1;
                }
                DiffOp::Insert(b) => {
                    assert_eq!(b, next_r, "out of order at {op:?}");
                    next_r += 1;
                }
            }
        }
        assert_eq!((next_l, next_r), (l.len(), r.len()), "not every line was placed");
    }

    fn changes(ops: &[DiffOp]) -> (usize, usize) {
        let deleted = ops.iter().filter(|op| matches!(op, DiffOp::Delete(_))).count();
        let inserted = ops.iter().filter(|op| matches!(op, DiffOp::Insert(_))).count();
        (deleted, inserted)
    }

    /// Pretty-printed JSON as the diff view sees it: every record's braces
    /// repeat hundreds of thousands of times, its id and name do not.
    fn records(count: usize, renamed: &[usize]) -> String {
        let mut text = String::from("[\n");
        for i in 0..count {
            let name = if renamed.contains(&i) {
                format!("renamed-{i}")
            } else {
                format!("user-{i}")
            };
            text.push_str(&format!(
                "  {{\n    \"id\": {i},\n    \"name\": \"{name}\",\n    \"active\": true\n  }},\n"
            ));
        }
        text.push_str("]\n");
        text
    }

    #[test]
    fn one_edit_in_a_large_value_is_one_line_changed() {
        // ~120,000 lines, the size a 1 MiB JSON value pretty-prints to — far
        // past any LCS table, which used to turn this into 120,000 lines
        // deleted and 120,000 inserted.
        let left = records(24_000, &[]);
        let right = records(24_000, &[12_345]);
        let ops = line_diff(&left, &right);
        assert_valid(&ops, &left, &right);
        assert_eq!(changes(&ops), (1, 1));
    }

    #[test]
    fn scattered_edits_in_a_large_value_are_each_found() {
        let renamed: Vec<usize> = (0..50).map(|k| k * 397 + 11).collect();
        let left = records(20_000, &[]);
        let right = records(20_000, &renamed);
        let ops = line_diff(&left, &right);
        assert_valid(&ops, &left, &right);
        assert_eq!(changes(&ops), (50, 50));
        // A record added and one removed, too.
        let fewer = records(20_000, &[]).replacen(
            "  {\n    \"id\": 7,\n    \"name\": \"user-7\",\n    \"active\": true\n  },\n",
            "",
            1,
        );
        let ops = line_diff(&left, &fewer);
        assert_valid(&ops, &left, &fewer);
        assert_eq!(changes(&ops), (5, 0));
    }

    /// A small xorshift, so the random cases are the same on every run.
    fn random_lines(seed: &mut u64, count: usize, alphabet: u64) -> String {
        (0..count)
            .map(|_| {
                *seed ^= *seed << 13;
                *seed ^= *seed >> 7;
                *seed ^= *seed << 17;
                format!("{}\n", *seed % alphabet)
            })
            .collect()
    }

    /// The length of a longest common subsequence of the two texts' lines.
    fn lcs_len(left: &str, right: &str) -> usize {
        let l: Vec<&str> = left.split_inclusive('\n').collect();
        let r: Vec<&str> = right.split_inclusive('\n').collect();
        let mut row = vec![0usize; r.len() + 1];
        for a in &l {
            let mut diagonal = 0;
            for (j, b) in r.iter().enumerate() {
                let above = row[j + 1];
                row[j + 1] = if a == b { diagonal + 1 } else { above.max(row[j]) };
                diagonal = above;
            }
        }
        row[r.len()]
    }

    #[test]
    fn small_inputs_still_get_a_shortest_diff() {
        let mut seed = 0x2026_0927_u64;
        for _ in 0..300 {
            let left = random_lines(&mut seed, 40, 6);
            let right = random_lines(&mut seed, 35, 6);
            let ops = line_diff(&left, &right);
            assert_valid(&ops, &left, &right);
            let equal = ops.iter().filter(|op| matches!(op, DiffOp::Equal(..))).count();
            assert_eq!(equal, lcs_len(&left, &right), "{left:?} / {right:?}");
        }
    }

    #[test]
    fn large_inputs_are_always_a_valid_diff() {
        let mut seed = 0x5eed_u64;
        // Few distinct lines (almost nothing unique to anchor on) and many.
        for alphabet in [3, 50, 5_000, 1_000_000] {
            let left = random_lines(&mut seed, 3_000, alphabet);
            let mut right = left.clone();
            right.insert_str(right.len() / 2, &random_lines(&mut seed, 1_500, alphabet));
            let ops = line_diff(&left, &right);
            assert_valid(&ops, &left, &right);
        }
    }

    /// `(start, end)` pairs as ranges — a one-range literal reads as "the
    /// whole range" to clippy.
    fn ranges(pairs: &[(usize, usize)]) -> Vec<std::ops::Range<usize>> {
        pairs.iter().map(|&(start, end)| start..end).collect()
    }

    #[test]
    fn a_long_line_wraps_by_the_columns_a_monospace_font_gives_it() {
        assert_eq!(wrap_line("", 4), ranges(&[(0, 0)]));
        assert_eq!(wrap_line("abcdefghij", 4), ranges(&[(0, 4), (4, 8), (8, 10)]));
        assert_eq!(wrap_line("abcd", 4), ranges(&[(0, 4)]));
        // Two columns each for CJK: two per piece of four.
        let text = "键名很长";
        assert_eq!(wrap_line(text, 4), ranges(&[(0, 6), (6, 12)]));
        // A wide character never splits, even in a column too narrow for it.
        assert_eq!(wrap_line("a键", 2), ranges(&[(0, 1), (1, 4)]));
    }

    #[test]
    fn a_patch_holds_every_line_and_counts_what_changed() {
        let patch = whole_patch("value", "a\nb\nc\nd\n", "a\nB\nc\nd\ne\n");
        assert_eq!(
            patch.text,
            "--- a/value\n+++ b/value\n@@ -1,4 +1,5 @@\n a\n-b\n+B\n c\n d\n+e\n"
        );
        assert_eq!((patch.removed, patch.added, patch.changes), (1, 2, 2));
        // Nothing to compare against: the hunk starts at line 0 of that side.
        let created = whole_patch("value", "", "x\ny\n");
        assert_eq!(created.text, "--- a/value\n+++ b/value\n@@ -0,0 +1,2 @@\n+x\n+y\n");
        assert_eq!((created.removed, created.added, created.changes), (0, 2, 1));
        // The same text is all context.
        let same = whole_patch("value", "a\nb", "a\nb");
        assert_eq!(same.text, "--- a/value\n+++ b/value\n@@ -1,2 +1,2 @@\n a\n b\n");
        assert_eq!((same.removed, same.added, same.changes), (0, 0, 0));
    }

    /// What a patch line cannot show is said where it is the change, and
    /// nowhere else: a value in CRLF throughout reads like any other.
    #[test]
    fn an_ending_that_changed_is_said_and_one_that_did_not_is_not() {
        let crlf = whole_patch("value", "x\r\ny\r\n", "x\r\nz\r\n");
        assert!(crlf.text.ends_with("@@\n x\n-y\u{240D}\n+z\u{240D}\n"), "{}", crlf.text);
        let to_lf = whole_patch("value", "a\r\nb\n", "a\nb\n");
        assert!(to_lf.text.ends_with("@@\n-a\u{240D}\n+a\n b\n"), "{}", to_lf.text);

        let newline_added = whole_patch("value", "a\nb", "a\nb\n");
        assert!(
            newline_added
                .text
                .ends_with("@@\n a\n-b\n\\ No newline at end of file\n+b\n"),
            "{}",
            newline_added.text
        );
        // Neither side ends in a newline, as most values do not: no remark.
        assert!(!whole_patch("value", "a\nb", "a\nc").text.contains("No newline"));
    }

    /// A value may hold lines that are patch syntax themselves; behind their
    /// mark they are content, and the hunk's counts still add up.
    #[test]
    fn a_value_that_looks_like_a_patch_is_only_lines() {
        let left = "--- a/x\n+++ b/x\n@@ -1 +1 @@\n\\ No newline at end of file\n\n";
        let right = "--- a/x\n+++ b/y\n@@ -1 +1 @@\n\\ No newline at end of file\n\n";
        let patch = whole_patch("value", left, right);
        let body: Vec<&str> = patch.text.lines().skip(3).collect();
        assert_eq!(
            body,
            [
                " --- a/x",
                "-+++ b/x",
                "++++ b/y",
                " @@ -1 +1 @@",
                " \\ No newline at end of file",
                " "
            ]
        );
        assert_eq!(patch.text.lines().nth(2), Some("@@ -1,5 +1,5 @@"));
    }

    #[test]
    fn a_line_that_differs_only_in_its_ending_is_marked() {
        let ops = line_diff("a\r\nb\n", "a\nb\n");
        assert!(
            ops.iter().any(|op| !matches!(op, DiffOp::Equal(..))),
            "CRLF against LF is a change: {ops:?}"
        );
        // And the same text is still all equal, last line with or without
        // its newline counted the way `lines()` counts it.
        assert_eq!(
            line_diff("a\nb", "a\nb"),
            vec![DiffOp::Equal(0, 0), DiffOp::Equal(1, 1)]
        );
    }

    #[test]
    fn identical_inputs_yield_only_equal_ops() {
        let ops = line_diff("a\nb\nc", "a\nb\nc");
        assert_eq!(ops, vec![DiffOp::Equal(0, 0), DiffOp::Equal(1, 1), DiffOp::Equal(2, 2)]);
    }

    #[test]
    fn pure_insert_marks_every_right_line() {
        let ops = line_diff("", "a\nb");
        assert_eq!(ops, vec![DiffOp::Insert(0), DiffOp::Insert(1)]);
    }

    #[test]
    fn pure_delete_marks_every_left_line() {
        let ops = line_diff("a\nb", "");
        assert_eq!(ops, vec![DiffOp::Delete(0), DiffOp::Delete(1)]);
    }

    #[test]
    fn mid_change_keeps_unchanged_lines_aligned() {
        // Classic single-line replacement: the surrounding lines stay
        // as Equal, the differing line becomes Delete then Insert
        // (matches `diff(1)` order so the side-by-side view shows the
        // removed line on the left, the inserted one on the right).
        let ops = line_diff("a\nold\nc", "a\nnew\nc");
        assert_eq!(
            ops,
            vec![
                DiffOp::Equal(0, 0),
                DiffOp::Delete(1),
                DiffOp::Insert(1),
                DiffOp::Equal(2, 2),
            ]
        );
    }

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn kv_diff_reports_added_removed_changed_only() {
        let old = pairs(&[("uptime", "100"), ("version", "7.2"), ("gone", "x")]);
        let new = pairs(&[("uptime", "160"), ("version", "7.2"), ("fresh", "y")]);
        let entries = kv_diff(&old, &new);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].key, "uptime");
        assert_eq!(entries[0].delta, KvDelta::Changed);
        assert_eq!(entries[0].old.as_deref(), Some("100"));
        assert_eq!(entries[0].new.as_deref(), Some("160"));
        assert_eq!(entries[1].key, "fresh");
        assert_eq!(entries[1].delta, KvDelta::Added);
        assert_eq!(entries[2].key, "gone");
        assert_eq!(entries[2].delta, KvDelta::Removed);
    }

    #[test]
    fn kv_diff_ignores_reordering() {
        let old = pairs(&[("a", "1"), ("b", "2")]);
        let new = pairs(&[("b", "2"), ("a", "1")]);
        assert!(kv_diff(&old, &new).is_empty());
    }

    #[test]
    fn kv_diff_duplicate_keys_use_last_value() {
        let old = pairs(&[("k", "1")]);
        let new = pairs(&[("k", "1"), ("k", "2")]);
        let entries = kv_diff(&old, &new);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].delta, KvDelta::Changed);
        assert_eq!(entries[0].new.as_deref(), Some("2"));
    }

    #[test]
    fn very_large_input_degrades_to_all_replace() {
        // Too large for an LCS table and without a single common line to
        // split at: shown as replaced, so the UI does not lock up. Use
        // DIFFERENT big inputs — identical ones hit the equality fast-path.
        let left_big: String = (0..2500).map(|i| format!("L{i}\n")).collect();
        let right_big: String = (0..2500).map(|i| format!("R{i}\n")).collect();
        let ops = line_diff(&left_big, &right_big);
        let dels = ops.iter().filter(|o| matches!(o, DiffOp::Delete(_))).count();
        let ins = ops.iter().filter(|o| matches!(o, DiffOp::Insert(_))).count();
        assert_eq!(dels, 2500);
        assert_eq!(ins, 2500);
    }
}
