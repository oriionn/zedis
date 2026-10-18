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

//! A report as a document — sections of facts, tables, the server's own
//! prose and lists — written out as Markdown, to paste into a ticket or a
//! chat, or as one HTML file with its styles inside, to send as it is.
//!
//! Pure, and worded by whoever builds it: nothing here is a UI string.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// The whole document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub title: String,
    /// Lines under the title: when, by what, about what.
    pub meta: Vec<String>,
    pub sections: Vec<Section>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Section {
    pub title: String,
    pub blocks: Vec<Block>,
}

/// One part of a section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    /// A heading inside a section, over the blocks after it.
    Heading(String),
    Paragraph(String),
    /// Said aside: what could not be read and why, what is left out.
    Note(String),
    /// Label and value, one pair a line.
    Facts(Vec<(String, String)>),
    Table {
        columns: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    /// Text kept as it was written — a server's own prose answer.
    Preformatted {
        caption: Option<String>,
        text: String,
    },
    List(Vec<String>),
}

impl Report {
    pub fn to_markdown(&self) -> String {
        let mut md = String::with_capacity(4096);
        let _ = writeln!(md, "# {}\n", md_text(&self.title));
        for line in &self.meta {
            let _ = writeln!(md, "{}  ", md_text(line));
        }
        if !self.meta.is_empty() {
            md.push('\n');
        }
        for section in &self.sections {
            let _ = writeln!(md, "## {}\n", md_text(&section.title));
            for block in &section.blocks {
                markdown_block(&mut md, block);
                md.push('\n');
            }
        }
        md.truncate(md.trim_end().len());
        md.push('\n');
        md
    }

    /// One HTML file that needs nothing else: its styles inside, light and
    /// dark after the reader's own setting.
    pub fn to_html(&self) -> String {
        let mut html = String::with_capacity(8192);
        let _ = write!(
            html,
            "<!doctype html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
             <title>{}</title>\n<style>{HTML_STYLE}</style>\n</head>\n<body>\n<main>\n<h1>{}</h1>\n",
            escape(&self.title),
            escape(&self.title),
        );
        if !self.meta.is_empty() {
            html.push_str("<p class=\"meta\">");
            let lines: Vec<String> = self.meta.iter().map(|line| escape(line)).collect();
            html.push_str(&lines.join("<br>"));
            html.push_str("</p>\n");
        }
        for section in &self.sections {
            let _ = writeln!(html, "<section>\n<h2>{}</h2>", escape(&section.title));
            for block in &section.blocks {
                html_block(&mut html, block);
            }
            html.push_str("</section>\n");
        }
        html.push_str("</main>\n</body>\n</html>\n");
        html
    }
}

/// A heading or a line under the title on one line, whatever it held.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Text on one Markdown line, shown as it is: a key named `a*b*c` is not
/// emphasis, and one with a backtick or a bracket is not code or a link.
fn md_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in one_line(text).chars() {
        if matches!(c, '\\' | '`' | '*' | '<' | '[' | ']') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A value inside one Markdown table cell: a pipe would end the cell and a
/// line break the row.
fn md_cell(text: &str) -> String {
    md_text(text).replace('|', "\\|")
}

fn markdown_block(md: &mut String, block: &Block) {
    match block {
        Block::Heading(text) => {
            let _ = writeln!(md, "### {}", md_text(text));
        }
        Block::Paragraph(text) => {
            let _ = writeln!(md, "{}", md_text(text));
        }
        Block::Note(text) => {
            let _ = writeln!(md, "> {}", md_text(text));
        }
        Block::Facts(facts) => {
            for (label, value) in facts {
                let _ = writeln!(md, "- **{}**: {}", md_text(label), md_text(value));
            }
        }
        Block::Table { columns, rows } => {
            let header: Vec<String> = columns.iter().map(|c| md_cell(c)).collect();
            let _ = writeln!(md, "| {} |", header.join(" | "));
            let _ = writeln!(md, "|{}", " --- |".repeat(columns.len().max(1)));
            for row in rows {
                let cells: Vec<String> = (0..columns.len())
                    .map(|ix| md_cell(row.get(ix).map(String::as_str).unwrap_or_default()))
                    .collect();
                let _ = writeln!(md, "| {} |", cells.join(" | "));
            }
        }
        Block::Preformatted { caption, text } => {
            if let Some(caption) = caption {
                let _ = writeln!(md, "**{}**\n", md_text(caption));
            }
            // A fence longer than any run of backticks inside, so the text
            // cannot close it.
            let fence = "`".repeat(longest_backtick_run(text).max(2) + 1);
            let _ = writeln!(md, "{fence}text\n{}\n{fence}", text.trim_end());
        }
        Block::List(items) => {
            for item in items {
                let _ = writeln!(md, "- {}", md_text(item));
            }
        }
    }
}

fn longest_backtick_run(text: &str) -> usize {
    let (mut longest, mut run) = (0, 0);
    for c in text.chars() {
        run = if c == '`' { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    longest
}

fn html_block(html: &mut String, block: &Block) {
    match block {
        Block::Heading(text) => {
            let _ = writeln!(html, "<h3>{}</h3>", escape(text));
        }
        Block::Paragraph(text) => {
            let _ = writeln!(html, "<p>{}</p>", escape(text));
        }
        Block::Note(text) => {
            let _ = writeln!(html, "<p class=\"note\">{}</p>", escape(text));
        }
        Block::Facts(facts) => {
            html.push_str("<table class=\"facts\">\n");
            for (label, value) in facts {
                let _ = writeln!(html, "<tr><th>{}</th><td>{}</td></tr>", escape(label), escape(value));
            }
            html.push_str("</table>\n");
        }
        Block::Table { columns, rows } => {
            html.push_str("<div class=\"scroll\"><table>\n<thead><tr>");
            for column in columns {
                let _ = write!(html, "<th>{}</th>", escape(column));
            }
            html.push_str("</tr></thead>\n<tbody>\n");
            for row in rows {
                html.push_str("<tr>");
                for ix in 0..columns.len() {
                    let _ = write!(
                        html,
                        "<td>{}</td>",
                        escape(row.get(ix).map(String::as_str).unwrap_or_default())
                    );
                }
                html.push_str("</tr>\n");
            }
            html.push_str("</tbody>\n</table></div>\n");
        }
        Block::Preformatted { caption, text } => {
            if let Some(caption) = caption {
                let _ = writeln!(html, "<p class=\"caption\">{}</p>", escape(caption));
            }
            let _ = writeln!(html, "<pre>{}</pre>", escape(text.trim_end()));
        }
        Block::List(items) => {
            html.push_str("<ul>\n");
            for item in items {
                let _ = writeln!(html, "<li>{}</li>", escape(item));
            }
            html.push_str("</ul>\n");
        }
    }
}

/// Text as HTML shows it, never as markup.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

const HTML_STYLE: &str = "\
:root{color-scheme:light dark;--fg:#1f2328;--muted:#59636e;--line:#d1d9e0;--head:#f6f8fa;--bg:#fff}\
@media (prefers-color-scheme:dark){:root{--fg:#e6edf3;--muted:#9198a1;--line:#3d444d;--head:#151b23;--bg:#0d1117}}\
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 ui-sans-serif,system-ui,-apple-system,sans-serif}\
main{max-width:1100px;margin:0 auto;padding:24px 16px 48px}\
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px;padding-bottom:4px;border-bottom:1px solid var(--line)}h3{font-size:14px;margin:18px 0 6px}\
.meta,.note,.caption{color:var(--muted)}.meta{margin:0 0 8px}.note{font-style:italic}.caption{margin:12px 0 4px;font-weight:600}\
.scroll{overflow-x:auto}table{border-collapse:collapse;margin:8px 0}th,td{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top}\
thead th,table.facts th{background:var(--head);font-weight:600}table.facts th{white-space:nowrap}\
td{font-variant-numeric:tabular-nums;overflow-wrap:anywhere}\
pre{background:var(--head);border:1px solid var(--line);border-radius:6px;padding:10px 12px;overflow-x:auto;white-space:pre-wrap;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}";

/// The `field:value` lines of an `INFO` reply, every section together.
pub fn info_fields(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once(':'))
        .map(|(field, value)| (field.to_string(), value.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Report {
        Report {
            title: "Troubleshooting report — prod".to_string(),
            meta: vec!["2026-10-18 21:00".to_string(), "Redis 7.2.4".to_string()],
            sections: vec![Section {
                title: "Overview".to_string(),
                blocks: vec![
                    Block::Facts(vec![("Memory".to_string(), "1.2G".to_string())]),
                    Block::Table {
                        columns: vec!["Command".to_string(), "Duration".to_string()],
                        rows: vec![
                            vec!["SET a|b".to_string(), "12 ms".to_string()],
                            vec!["GET".to_string()],
                        ],
                    },
                    Block::Preformatted {
                        caption: Some("node-1".to_string()),
                        text: "Hi Sam, ```fenced``` advice\n".to_string(),
                    },
                    Block::Note("unavailable: NOPERM".to_string()),
                    Block::Heading("Top keys".to_string()),
                    Block::List(vec!["one".to_string()]),
                ],
            }],
        }
    }

    /// A pipe stays inside its cell, a short row is filled to the header's
    /// width, and the server's own text cannot close the fence around it.
    #[test]
    fn markdown_keeps_cells_and_fences_whole() {
        let md = report().to_markdown();
        assert!(md.starts_with("# Troubleshooting report — prod\n\n2026-10-18 21:00  \nRedis 7.2.4  \n"));
        assert!(md.contains("- **Memory**: 1.2G\n"));
        assert!(md.contains("| Command | Duration |\n| --- | --- |\n| SET a\\|b | 12 ms |\n| GET |  |\n"));
        assert!(md.contains("**node-1**\n\n````text\nHi Sam, ```fenced``` advice\n````\n"));
        assert!(md.contains("> unavailable: NOPERM\n"));
        assert!(md.contains("### Top keys\n"));
        assert!(md.ends_with("- one\n"));
    }

    /// A key name is shown as it is spelled, whatever Markdown would make
    /// of it: `user:*` beside `order:*` on one line is not emphasis.
    #[test]
    fn markdown_shows_names_as_they_are_spelled() {
        let report = Report {
            title: "t".to_string(),
            meta: Vec::new(),
            sections: vec![Section {
                title: "s".to_string(),
                blocks: vec![
                    Block::List(vec!["user:* and order:* [x](y) `z` <b> a\\b".to_string()]),
                    Block::Table {
                        columns: vec!["Prefix".to_string()],
                        rows: vec![vec!["cache:*|tmp".to_string()]],
                    },
                ],
            }],
        };
        let md = report.to_markdown();
        assert!(
            md.contains("- user:\\* and order:\\* \\[x\\](y) \\`z\\` \\<b> a\\\\b\n"),
            "{md}"
        );
        assert!(md.contains("| cache:\\*\\|tmp |\n"), "{md}");
    }

    /// Whatever a key or a server's answer holds is shown, never run.
    #[test]
    fn html_is_one_file_and_escapes_what_it_shows() {
        let mut report = report();
        report.sections[0]
            .blocks
            .push(Block::Paragraph("<script>alert('x')</script> & co".to_string()));
        let html = report.to_html();
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("<style>") && !html.contains("<link") && !html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; co"));
        assert!(html.contains("<td>SET a|b</td><td>12 ms</td>"));
        assert!(html.contains("<tr><td>GET</td><td></td></tr>"));
        assert!(html.contains("<p class=\"note\">unavailable: NOPERM</p>"));
        assert!(html.contains("<h3>Top keys</h3>"));
    }

    #[test]
    fn info_fields_are_read_from_every_section() {
        let fields =
            info_fields("# Server\r\nredis_version:7.2.4\r\n\r\n# Keyspace\r\ndb0:keys=3,expires=1,avg_ttl=0\r\n");
        assert_eq!(fields.get("redis_version").map(String::as_str), Some("7.2.4"));
        assert_eq!(
            fields.get("db0").map(String::as_str),
            Some("keys=3,expires=1,avg_ttl=0")
        );
        assert_eq!(fields.len(), 2);
    }
}
