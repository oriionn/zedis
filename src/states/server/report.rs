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

//! What this session's panels found, for a troubleshooting report (ADR 19).
//! A panel that ran an analysis leaves its result here as a report section,
//! so the report has it whether or not the panel is still open — the hot
//! keys page is gone the moment another page is opened. Another server
//! forgets it with the rest of the state.

use super::ZedisServerState;
use zedis_core::report::Section;

/// Which panel a finding is from: at most one each, the latest, in this
/// order in the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReportFinding {
    MemoryAnalysis,
    Hotkeys,
}

impl ZedisServerState {
    /// Keep `section` as what `kind` found last.
    pub fn set_report_finding(&mut self, kind: ReportFinding, section: Section) {
        self.report_findings.retain(|(held, _)| *held != kind);
        self.report_findings.push((kind, section));
        self.report_findings.sort_by_key(|(held, _)| *held);
    }

    /// What this session found, for the report.
    pub fn report_findings(&self) -> Vec<Section> {
        self.report_findings
            .iter()
            .map(|(_, section)| section.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::init_ui;
    use gpui::{AppContext, TestAppContext};

    fn section(title: &str) -> Section {
        Section {
            title: title.to_string(),
            blocks: Vec::new(),
        }
    }

    /// The latest finding of each panel, in the report's order whichever
    /// ran first — and another server starts with none.
    #[gpui::test]
    fn findings_are_each_panels_latest_and_belong_to_their_server(cx: &mut TestAppContext) {
        init_ui(cx);
        let state = cx.new(|_| ZedisServerState::default());
        state.update(cx, |state, cx| {
            state.select("server-a".into(), 0, cx);
            state.set_report_finding(ReportFinding::Hotkeys, section("hot keys 1"));
            state.set_report_finding(ReportFinding::MemoryAnalysis, section("memory"));
            state.set_report_finding(ReportFinding::Hotkeys, section("hot keys 2"));
            let titles: Vec<String> = state.report_findings().into_iter().map(|s| s.title).collect();
            assert_eq!(titles, ["memory", "hot keys 2"]);

            state.select("server-b".into(), 0, cx);
            assert!(state.report_findings().is_empty());
        });
    }
}
