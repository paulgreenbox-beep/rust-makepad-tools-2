use crate::contract::{AutomationError, ErrorCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvidenceEntry {
    pub sequence: u64,
    pub timestamp_unix_ms: u128,
    pub tool: String,
    pub window_id: Option<String>,
    pub element_id: Option<String>,
    pub request: Value,
    pub execution_method: Option<String>,
    pub result: Value,
    pub resulting_state: Option<Value>,
    pub screenshot_path: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct EvidenceDraft {
    pub tool: String,
    pub window_id: Option<String>,
    pub element_id: Option<String>,
    pub request: Value,
    pub execution_method: Option<String>,
    pub result: Value,
    pub resulting_state: Option<Value>,
    pub screenshot_path: Option<String>,
}

pub struct EvidenceLog {
    next_sequence: u64,
    capacity: usize,
    dropped_entries: u64,
    entries: VecDeque<EvidenceEntry>,
}

impl EvidenceLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            next_sequence: 1,
            capacity: capacity.max(1),
            dropped_entries: 0,
            entries: VecDeque::new(),
        }
    }

    pub(crate) fn record(&mut self, draft: EvidenceDraft) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
            self.dropped_entries = self.dropped_entries.saturating_add(1);
        }
        self.entries.push_back(EvidenceEntry {
            sequence,
            timestamp_unix_ms: now_unix_ms(),
            tool: draft.tool,
            window_id: draft.window_id,
            element_id: draft.element_id,
            request: draft.request,
            execution_method: draft.execution_method,
            result: draft.result,
            resulting_state: draft.resulting_state,
            screenshot_path: draft.screenshot_path,
        });
        sequence
    }

    pub fn entries_since(
        &self,
        since_sequence: Option<u64>,
        limit: Option<usize>,
    ) -> Vec<EvidenceEntry> {
        let since = since_sequence.unwrap_or(0);
        let limit = limit.unwrap_or(self.capacity).min(self.capacity);
        self.entries
            .iter()
            .filter(|entry| entry.sequence > since)
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn dropped_entries(&self) -> u64 {
        self.dropped_entries
    }

    pub fn write_json(&self, path: impl AsRef<Path>) -> Result<(), AutomationError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(io_error)?;
        }
        let payload = serde_json::to_vec_pretty(&self.entries_since(None, None))
            .map_err(|error| AutomationError::new(ErrorCode::BackendFailure, error.to_string()))?;
        fs::write(path, payload).map_err(io_error)
    }
}

impl Default for EvidenceLog {
    fn default() -> Self {
        Self::new(4096)
    }
}

pub fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn io_error(error: std::io::Error) -> AutomationError {
    let code = if error.kind() == std::io::ErrorKind::PermissionDenied {
        ErrorCode::PermissionDenied
    } else {
        ErrorCode::BackendFailure
    };
    AutomationError::new(code, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn evidence_is_ordered_and_bounded() {
        let mut log = EvidenceLog::new(2);
        for index in 0..3 {
            log.record(EvidenceDraft {
                tool: "test".into(),
                request: json!({"index": index}),
                result: json!({"ok": true}),
                ..Default::default()
            });
        }
        let entries = log.entries_since(None, None);
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.sequence)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(log.dropped_entries(), 1);
        assert_eq!(log.entries_since(Some(2), None).len(), 1);
    }
}
