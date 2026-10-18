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

//! A finished online run as a troubleshooting report's section (ADR 19):
//! how it sampled, what the rules found, and the biggest prefixes and keys
//! — the tables' own cells, so the report reads like the page.

use super::*;
use crate::helpers::now_datetime;
use zedis_core::report::{Block, Section};

/// The cells of a prefix row the table draws, in its column order.
const PREFIX_COLUMNS: [&str; 6] = [
    COL_PREFIX,
    COL_KEY_COUNT,
    COL_MEMORY,
    COL_AVG_TTL,
    COL_PERM_COUNT,
    COL_TYPES,
];
const KEY_COLUMNS: [&str; 5] = [COL_KEY, COL_MEMORY, COL_TTL, COL_KEY_TYPE, COL_HEAT];

impl ZedisMemoryAnalysis {
    /// Leave this run with the server state for the report. Only an online
    /// run of the server it is the state of: an RDB file describes some
    /// other moment.
    pub(super) fn publish_report_finding(&self, cx: &mut gpui::Context<Self>) {
        if self.rdb_file.is_some() || self.status != AnalysisStatus::Finished {
            return;
        }
        let section = self.report_section(cx);
        self.server_state.update(cx, |state, _| {
            state.set_report_finding(ReportFinding::MemoryAnalysis, section);
        });
    }

    fn report_section(&self, cx: &gpui::App) -> Section {
        let k = |key: &str| i18n_memory_analysis(cx, key).to_string();
        let mut facts = vec![(i18n_troubleshoot(cx, "fact_recorded").to_string(), now_datetime())];
        if let Some((_, db)) = &self.analyzed {
            facts.push((i18n_troubleshoot(cx, "fact_database").to_string(), format!("db{db}")));
        }
        if let Some(dbsize) = self.dbsize {
            facts.push((k("dbsize").trim_end_matches(':').to_string(), group_thousands(dbsize)));
        }
        let ratio = self.run_ratio.unwrap_or(self.ratio);
        facts.push((
            k("sample_ratio").trim_end_matches(':').to_string(),
            format!("{:.0}%", ratio * 100.0),
        ));
        if !self.policy.is_empty() {
            facts.push((k("policy").trim_end_matches(':').to_string(), self.policy.to_string()));
        }
        let mut blocks = vec![Block::Facts(facts)];

        blocks.push(Block::Heading(k("reco_panel_title")));
        if self.recommendations.is_empty() {
            blocks.push(Block::Note(k("reco_healthy")));
        } else {
            blocks.push(Block::List(
                self.recommendations
                    .iter()
                    .map(|reco| {
                        let (title, subject, detail) = self.reco_text(reco, cx);
                        match subject {
                            Some(subject) => format!("{title} ({subject}): {detail}"),
                            None => format!("{title}: {detail}"),
                        }
                    })
                    .collect(),
            ));
        }

        let mut prefixes: Vec<&PrefixRow> = self.prefix_rows.iter().collect();
        prefixes.sort_by_key(|row| std::cmp::Reverse(row.memory_bytes));
        prefixes.truncate(TOP_N);
        if !prefixes.is_empty() {
            blocks.push(Block::Heading(k("prefix_table_title")));
            blocks.push(Block::Table {
                columns: PREFIX_COLUMNS.iter().map(|column| k(column)).collect(),
                rows: prefixes
                    .iter()
                    .map(|row| drawn_cells(row.cells(), PREFIX_COLUMNS.len()))
                    .collect(),
            });
        }
        let keys = &self.single_groups.by_size.items;
        if !keys.is_empty() {
            blocks.push(Block::Heading(k("single_table_title")));
            blocks.push(Block::Table {
                columns: KEY_COLUMNS.iter().map(|column| k(column)).collect(),
                rows: keys
                    .iter()
                    .take(TOP_N)
                    .map(|row| drawn_cells(row.cells(), KEY_COLUMNS.len()))
                    .collect(),
            });
        }
        Section {
            title: k("title"),
            blocks,
        }
    }
}

/// A row's drawn cells, without the payload cells after them.
fn drawn_cells(cells: Vec<SharedString>, columns: usize) -> Vec<String> {
    cells.into_iter().take(columns).map(|cell| cell.to_string()).collect()
}
