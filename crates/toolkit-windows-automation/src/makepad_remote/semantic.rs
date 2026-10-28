//! Source-only app semantic contract on the EXISTING Remote adapter.
//!
//! This is not UIA Invoke/SetValue and installs no app IPC, route or MCP tool.
//! Native platform owners remain unsupported until an authenticated app producer
//! and its source/fixture policy are reviewed. Tests below are pure composition.
use super::protocol::{RemoteError, Result, classify_reply, encode};
use super::{MakepadRemoteAdapter, RemotePlatform, SessionBinding};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const CONTRACT_SCHEMA: &str = "toolkit-app-semantic-contract-v1";
pub const OBSERVATION_SCHEMA: &str = "toolkit-app-semantic-observation-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Read,
    Focus,
    TypeText,
    SelectAll,
    Backspace,
    Invoke,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WidgetKind {
    TextInput,
    Button,
}
impl WidgetKind {
    fn snapshot_type(self) -> &'static str {
        match self {
            Self::TextInput => "TextInput",
            Self::Button => "Button",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WidgetBinding {
    pub automation_id: String,
    pub widget_id: String,
    pub kind: WidgetKind,
    pub actions: BTreeSet<Action>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppContract {
    pub schema: String,
    pub contract_id: String,
    pub source_manifest_sha256: String,
    pub widgets: Vec<WidgetBinding>,
    /// Only approved readback keys; no URLs, commands, paths or expressions.
    pub domain_keys: BTreeSet<String>,
}

fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|v| v.is_ascii_hexdigit())
}
fn require(ok: bool, code: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(RemoteError::refused(code))
    }
}

impl AppContract {
    pub fn validate(&self) -> Result<()> {
        require(
            self.schema == CONTRACT_SCHEMA
                && bounded(&self.contract_id, 128)
                && digest(&self.source_manifest_sha256)
                && !self.widgets.is_empty()
                && self.widgets.len() <= 128
                && self.domain_keys.len() <= 32
                && self.domain_keys.iter().all(|k| bounded(k, 128)),
            "APP_SEMANTIC_CONTRACT_INVALID",
        )?;
        let (mut ids, mut widgets) = (BTreeSet::new(), BTreeSet::new());
        for item in &self.widgets {
            require(
                bounded(&item.automation_id, 512)
                    && bounded(&item.widget_id, 4096)
                    && ids.insert(&item.automation_id)
                    && widgets.insert(&item.widget_id)
                    && item.actions.contains(&Action::Read)
                    && item.actions.iter().all(|action| match item.kind {
                        WidgetKind::TextInput => *action != Action::Invoke,
                        WidgetKind::Button => matches!(action, Action::Read | Action::Invoke),
                    }),
                "APP_SEMANTIC_BINDING_INVALID",
            )?;
        }
        Ok(())
    }
    fn widget(&self, automation_id: &str, action: Action) -> Result<&WidgetBinding> {
        let widget = self
            .widgets
            .iter()
            .find(|w| w.automation_id == automation_id)
            .ok_or_else(|| RemoteError::refused("UNKNOWN_APPROVED_AUTOMATION_ID"))?;
        require(
            widget.actions.contains(&action),
            "UNSUPPORTED_APP_SEMANTIC_ACTION",
        )?;
        Ok(widget)
    }
}

/// Only minted after existing owner/session authorization. Not deserializable
/// from MCP arguments. This approval is scoped to one adapter generation.
#[derive(Clone, Debug)]
pub struct Registration {
    binding: SessionBinding,
    contract: AppContract,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub runtime_instance: String,
    pub document_id: String,
    pub document_generation: u64,
    pub object_id: String,
    pub object_generation: u64,
}
impl Context {
    fn valid(&self) -> bool {
        bounded(&self.runtime_instance, 128)
            && bounded(&self.document_id, 256)
            && self.document_generation > 0
            && bounded(&self.object_id, 256)
            && self.object_generation > 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationRequest {
    pub binding: SessionBinding,
    pub contract_id: String,
    pub source_manifest_sha256: String,
    pub challenge: u64,
    pub automation_id: String,
    pub widget_id: String,
    pub kind: WidgetKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionObservation {
    pub sequence: u64,
    pub authorization_challenge: u64,
    pub automation_id: String,
    pub widget_uid: u64,
    pub action: Action,
}

/// Envelope authentication belongs to the EXISTING process/channel owner.
/// App hooks must sample Cx focus, live WidgetUid and domain identity on its UI
/// thread. They must not echo this struct from a caller-supplied JSON object.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppObservation {
    pub schema: String,
    pub request: ObservationRequest,
    pub observation_sequence: u64,
    pub widget_uid: u64,
    pub binding_generation: u64,
    pub enabled: bool,
    pub visible: bool,
    pub focused: bool,
    pub value: Option<String>,
    /// UTF-8 byte offsets, ordered; producer must use the widget's real selection.
    pub selection: Option<[usize; 2]>,
    pub context: Context,
    pub model_revision: u64,
    pub action_sequence: u64,
    pub last_action: Option<ActionObservation>,
    pub domain: BTreeMap<String, String>,
}
impl AppObservation {
    /// Optional decoder for an approved producer: strict duplicate-key parser,
    /// bounded bytes, then strict typed schema. No new transport is introduced.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self> {
        require(bytes.len() <= 65536, "APP_SEMANTIC_OBSERVATION_BUDGET")?;
        let value = classify_reply(200, bytes, false)?;
        let parsed: Self = serde_json::from_value(value.clone())
            .map_err(|_| RemoteError::refused("APP_SEMANTIC_OBSERVATION_INVALID"))?;
        require(
            serde_json::to_value(&parsed).ok().as_ref() == Some(&value),
            "APP_SEMANTIC_OBSERVATION_INVALID",
        )?;
        Ok(parsed)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct WidgetState {
    contract_id: String,
    source_manifest_sha256: String,
    pub snapshot_row: Value,
    pub observation: AppObservation,
}

/// Required for Button business success. The trusted caller chooses an exact
/// expected domain context, including an intentional document transition.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Postcondition {
    pub context: Context,
    pub domain_key: String,
    pub expected_value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionAuthorization {
    pub request: ObservationRequest,
    pub widget_uid: u64,
    pub binding_generation: u64,
    pub context: Context,
    pub model_revision: u64,
    /// Must be revalidated before the widget handles the native event, not
    /// only later in the app's domain action handler.
    pub expected_focused: bool,
    pub expected_value: Option<String>,
    pub expected_selection: Option<[usize; 2]>,
    pub expected_domain: BTreeMap<String, String>,
    pub action: Action,
    pub text: Option<String>,
    pub postcondition: Option<Postcondition>,
}

impl<P: RemotePlatform> MakepadRemoteAdapter<P> {
    pub fn register_app_semantics(
        &mut self,
        session: &str,
        owner: &str,
        contract: AppContract,
    ) -> Result<Registration> {
        self.authorize(session, owner, self.binding.window_id)?;
        contract.validate()?;
        Ok(Registration {
            binding: self.binding.clone(),
            contract,
        })
    }

    fn check_registration(&mut self, session: &str, registration: &Registration) -> Result<()> {
        self.authorize(
            session,
            &registration.binding.owner,
            registration.binding.window_id,
        )?;
        require(
            registration.binding == self.binding,
            "APP_SEMANTIC_REGISTRATION_STALE",
        )
    }

    pub fn app_semantic_state(
        &mut self,
        session: &str,
        registration: &Registration,
        automation_id: &str,
    ) -> Result<WidgetState> {
        self.check_registration(session, registration)?;
        let widget = registration
            .contract
            .widget(automation_id, Action::Read)?
            .clone();
        let row = self.find_widget(session, self.binding.window_id, &widget.widget_id)?;
        require(
            row["ty"].as_str() == Some(widget.kind.snapshot_type()),
            "APP_SEMANTIC_WIDGET_TYPE_MISMATCH",
        )?;
        self.semantic_challenge = self
            .semantic_challenge
            .checked_add(1)
            .ok_or_else(|| RemoteError::refused("APP_SEMANTIC_SEQUENCE_EXHAUSTED"))?;
        let request = ObservationRequest {
            binding: self.binding.clone(),
            contract_id: registration.contract.contract_id.clone(),
            source_manifest_sha256: registration.contract.source_manifest_sha256.clone(),
            challenge: self.semantic_challenge,
            automation_id: widget.automation_id.clone(),
            widget_id: widget.widget_id.clone(),
            kind: widget.kind,
        };
        let observed = self.platform.observe_app_semantics(&request)?;
        self.check_registration(session, registration)?;
        require(
            serde_json::to_vec(&observed).is_ok_and(|bytes| bytes.len() <= 65536),
            "APP_SEMANTIC_OBSERVATION_BUDGET",
        )?;
        require(
            observed.schema == OBSERVATION_SCHEMA
                && observed.request == request
                && observed.observation_sequence > self.semantic_observation_sequence
                && observed.widget_uid > 0
                && observed.binding_generation > 0
                && observed.enabled
                && observed.visible
                && observed.context.valid()
                && observed.value.as_ref().is_none_or(|v| v.len() <= 16384)
                && observed.domain.len() <= 32
                && observed
                    .domain
                    .iter()
                    .all(|(k, v)| registration.contract.domain_keys.contains(k) && v.len() <= 4096),
            "APP_SEMANTIC_OBSERVATION_INVALID",
        )?;
        match widget.kind {
            WidgetKind::TextInput => {
                let value = observed
                    .value
                    .as_deref()
                    .ok_or_else(|| RemoteError::refused("APP_SEMANTIC_VALUE_MISSING"))?;
                require(
                    row["val"].as_str() == Some(value),
                    "APP_SEMANTIC_VALUE_MISMATCH",
                )?;
                require(
                    observed.selection.is_none_or(|[a, b]| {
                        a <= b
                            && b <= value.len()
                            && value.is_char_boundary(a)
                            && value.is_char_boundary(b)
                    }),
                    "APP_SEMANTIC_SELECTION_INVALID",
                )?;
            }
            WidgetKind::Button => require(
                observed.value.is_none() && observed.selection.is_none(),
                "APP_SEMANTIC_WIDGET_TYPE_MISMATCH",
            )?,
        }
        let fresh = self.find_widget(session, self.binding.window_id, &widget.widget_id)?;
        require(fresh == row, "STALE_WIDGET_LAYOUT")?;
        self.semantic_observation_sequence = observed.observation_sequence;
        Ok(WidgetState {
            contract_id: registration.contract.contract_id.clone(),
            source_manifest_sha256: registration.contract.source_manifest_sha256.clone(),
            snapshot_row: row,
            observation: observed,
        })
    }

    /// Uses only approved existing /click, /t and /k routes. An Invoke intent is
    /// a verified Button action from app Remote input, NEVER UIA InvokePattern.
    /// Owns exactly one existing lease and releases before public projection.
    pub fn app_semantic_action(
        &mut self,
        session: &str,
        registration: &Registration,
        previous: &WidgetState,
        action: Action,
        text: Option<&str>,
        postcondition: Option<&Postcondition>,
    ) -> Result<Value> {
        self.check_registration(session, registration)?;
        let aid = &previous.observation.request.automation_id;
        let widget = registration.contract.widget(aid, action)?.clone();
        require(
            action != Action::Read
                && previous.contract_id == registration.contract.contract_id
                && previous.source_manifest_sha256 == registration.contract.source_manifest_sha256
                && previous.observation.request.binding == self.binding,
            "APP_SEMANTIC_REGISTRATION_STALE",
        )?;
        require(
            (action == Action::TypeText) == text.is_some()
                && text.is_none_or(|t| {
                    !t.is_empty() && t.len() <= 4096 && !t.chars().any(char::is_control)
                }),
            "APP_SEMANTIC_INPUT_INVALID",
        )?;
        require(
            (action == Action::Invoke) == postcondition.is_some(),
            "APP_SEMANTIC_POSTCONDITION_REQUIRED",
        )?;
        if let Some(p) = postcondition {
            require(
                p.context.valid()
                    && registration.contract.domain_keys.contains(&p.domain_key)
                    && p.expected_value.len() <= 4096,
                "APP_SEMANTIC_POSTCONDITION_INVALID",
            )?;
        }
        // Probe BEFORE acquisition: a platform without the independent producer
        // refuses without input. Probe again inside the lease before dispatch.
        let before = self.app_semantic_state(session, registration, aid)?;
        same_target(previous, &before)?;
        if let Some(p) = postcondition {
            require(
                p.context.runtime_instance == before.observation.context.runtime_instance,
                "APP_SEMANTIC_RUNTIME_INSTANCE_CHANGED",
            )?;
            require(
                before.observation.domain.get(&p.domain_key) != Some(&p.expected_value),
                "APP_SEMANTIC_POSTCONDITION_ALREADY_SATISFIED",
            )?;
        }
        let token = self.acquire_input(session)?;
        let result = self.app_semantic_action_with_lease(
            session,
            registration,
            &before,
            &widget,
            action,
            text,
            postcondition,
            &token,
        );
        let release = self.release_input(session, &token);
        if release.is_err() {
            self.fence_mutations();
        }
        match (result, release) {
            (Err(mut error), Err(cleanup)) => {
                error.details["lease_cleanup_error"] = json!(cleanup);
                Err(error)
            }
            (Err(error), _) => Err(error),
            (Ok(observed), Err(cleanup)) => {
                let mut error = RemoteError::unknown("POST_ACTION_LEASE_RELEASE_UNVERIFIED");
                error.details = json!({"observed_action":observed,"lease_cleanup_error":cleanup});
                Err(error)
            }
            (Ok(observed), Ok(())) => Ok(observed),
        }
    }

    fn app_semantic_action_with_lease(
        &mut self,
        session: &str,
        registration: &Registration,
        before: &WidgetState,
        widget: &WidgetBinding,
        action: Action,
        text: Option<&str>,
        postcondition: Option<&Postcondition>,
        token: &str,
    ) -> Result<Value> {
        let window = self.binding.window_id;
        self.mutation_guard(session, window, token)?;
        let current = self.app_semantic_state(session, registration, &widget.automation_id)?;
        same_target(before, &current)?;
        if let Some(p) = postcondition {
            require(
                current.observation.domain.get(&p.domain_key) != Some(&p.expected_value),
                "APP_SEMANTIC_POSTCONDITION_ALREADY_SATISFIED",
            )?;
        }
        if matches!(
            action,
            Action::TypeText | Action::SelectAll | Action::Backspace
        ) {
            require(
                current.observation.focused,
                "WIDGET_KEY_FOCUS_NOT_CONFIRMED",
            )?;
        }
        if action == Action::TypeText {
            require(
                current.observation.value.as_deref() == Some("")
                    && current.observation.selection == Some([0, 0]),
                "UNSUPPORTED_CARET_SELECTION_OBSERVATION",
            )?;
        }
        if action == Action::Backspace {
            let value = current.observation.value.as_deref().unwrap_or_default();
            require(
                current.observation.selection == Some([0, value.len()]),
                "UNSUPPORTED_CARET_SELECTION_OBSERVATION",
            )?;
        }
        let route = match action {
            Action::Focus | Action::Invoke => {
                let r = &current.snapshot_row["r"];
                let (x, y) = (
                    r[0].as_f64().unwrap() + r[2].as_f64().unwrap() / 2.0,
                    r[1].as_f64().unwrap() + r[3].as_f64().unwrap() / 2.0,
                );
                format!("/click?w={window}&x={x}&y={y}&wait=1")
            }
            Action::TypeText => format!("/t?w={window}&t={}&wait=1", encode(text.unwrap())),
            Action::SelectAll => format!("/k?w={window}&k=press&c=KeyA&ctrl=1&wait=1"),
            Action::Backspace => format!("/k?w={window}&k=press&c=Backspace&ctrl=0&wait=1"),
            Action::Read => return Err(RemoteError::refused("UNSUPPORTED_APP_SEMANTIC_ACTION")),
        };
        let authorization = ActionAuthorization {
            request: current.observation.request.clone(),
            widget_uid: current.observation.widget_uid,
            binding_generation: current.observation.binding_generation,
            context: current.observation.context.clone(),
            model_revision: current.observation.model_revision,
            expected_focused: current.observation.focused,
            expected_value: current.observation.value.clone(),
            expected_selection: current.observation.selection,
            expected_domain: current.observation.domain.clone(),
            action,
            text: text.map(str::to_owned),
            postcondition: postcondition.cloned(),
        };
        require(
            serde_json::to_vec(&authorization).is_ok_and(|bytes| bytes.len() <= 65536),
            "APP_SEMANTIC_AUTHORIZATION_BUDGET",
        )?;
        // Default ports refuse here. A concrete app producer may arm only the
        // exact source-reviewed handler; never substitute a generic raw click.
        if let Err(mut cause) = self.platform.arm_app_semantics(&authorization) {
            if cause.outcome != "NOT_DISPATCHED" {
                self.fence_mutations();
                cause.details["guard_cleanup"] =
                    json!(self.platform.disarm_app_semantics(&authorization));
            }
            return Err(cause);
        }
        let result = self.app_semantic_dispatch_and_observe(
            session,
            registration,
            &current,
            widget,
            &authorization,
            route,
            token,
        );
        let cleanup = self.platform.disarm_app_semantics(&authorization);
        if cleanup.is_err() {
            self.fence_mutations();
        }
        match (result, cleanup) {
            (Err(mut cause), Err(cleanup)) => {
                if cause.outcome == "NOT_DISPATCHED" {
                    let mut error = RemoteError::unknown("APP_SEMANTIC_GUARD_CLEANUP_UNVERIFIED");
                    error.details = json!({"cause":cause,"guard_cleanup_error":cleanup});
                    return Err(error);
                }
                cause.details["guard_cleanup_error"] = json!(cleanup);
                Err(cause)
            }
            (Err(cause), _) => Err(cause),
            (Ok(observed), Err(cleanup)) => {
                let mut error = RemoteError::unknown("APP_SEMANTIC_GUARD_CLEANUP_UNVERIFIED");
                error.details = json!({"observed_action":observed,"guard_cleanup_error":cleanup});
                Err(error)
            }
            (Ok(observed), Ok(())) => Ok(observed),
        }
    }

    fn app_semantic_dispatch_and_observe(
        &mut self,
        session: &str,
        registration: &Registration,
        current: &WidgetState,
        widget: &WidgetBinding,
        authorization: &ActionAuthorization,
        route: String,
        token: &str,
    ) -> Result<Value> {
        let (action, text, postcondition) = (
            authorization.action,
            authorization.text.as_deref(),
            authorization.postcondition.as_ref(),
        );
        let ack = self.mutate(session, self.binding.window_id, token, route)?;
        let mut observations = json!({"ack":ack,"before":current});
        let verified = (|| {
            let after = self.app_semantic_state(session, registration, &widget.automation_id)?;
            observations["after"] = json!(after);
            let health = self.inspect_window(session)?;
            observations["runtime"] = health;
            let old = &current.observation;
            let new = &after.observation;
            require(
                new.widget_uid == old.widget_uid
                    && new.binding_generation == old.binding_generation
                    && new.context.runtime_instance == old.context.runtime_instance,
                "APP_SEMANTIC_LIVE_BINDING_CHANGED",
            )?;
            let expected_seq = old
                .action_sequence
                .checked_add(1)
                .ok_or_else(|| RemoteError::refused("APP_SEMANTIC_SEQUENCE_EXHAUSTED"))?;
            require(
                new.action_sequence == expected_seq
                    && new.last_action.as_ref().is_some_and(|a| {
                        a.sequence == expected_seq
                            && a.authorization_challenge == authorization.request.challenge
                            && a.automation_id == widget.automation_id
                            && a.widget_uid == old.widget_uid
                            && a.action == action
                    }),
                "APP_SEMANTIC_ACTION_NOT_OBSERVED",
            )?;
            match action {
                Action::Invoke => {
                    let p = postcondition.unwrap();
                    require(
                        new.context == p.context
                            && new.domain.get(&p.domain_key) == Some(&p.expected_value)
                            && (new.context != old.context
                                || new.model_revision >= old.model_revision),
                        "APP_SEMANTIC_DOMAIN_POSTCONDITION_MISMATCH",
                    )?;
                }
                _ => {
                    require(
                        new.context == old.context
                            && new.model_revision >= old.model_revision
                            && new.focused,
                        "APP_SEMANTIC_CONTEXT_OR_FOCUS_CHANGED",
                    )?;
                    match action {
                        Action::TypeText => {
                            require(new.value.as_deref() == text, "VALUE_READBACK_MISMATCH")?
                        }
                        Action::SelectAll => require(
                            new.value == old.value
                                && new.selection
                                    == Some([0, new.value.as_ref().map_or(0, String::len)]),
                            "APP_SEMANTIC_SELECTION_NOT_VERIFIED",
                        )?,
                        Action::Backspace => require(
                            new.value.as_deref() == Some("") && new.selection == Some([0, 0]),
                            "VALUE_READBACK_MISMATCH",
                        )?,
                        _ => (),
                    }
                }
            }
            observations["mechanism"] = json!(if action == Action::Invoke {
                "APP_REMOTE_BUTTON_CLICK_WITH_APP_READBACK"
            } else {
                "APP_REMOTE_INPUT_WITH_APP_READBACK"
            });
            observations["semantic_uia_invoke_or_setvalue"] = json!(false);
            observations["postcondition_verified"] = json!(true);
            Ok(observations.clone())
        })();
        verified.map_err(|cause: RemoteError| {
            self.fence_mutations();
            let mut error = RemoteError::unknown("APP_SEMANTIC_POST_ACTION_UNVERIFIED");
            error.details =
                json!({"cause":cause,"observations":observations,"automatic_retry_allowed":false});
            error
        })
    }
}

fn same_target(before: &WidgetState, after: &WidgetState) -> Result<()> {
    let (a, b) = (&before.observation, &after.observation);
    require(
        a.request.binding == b.request.binding
            && a.request.automation_id == b.request.automation_id
            && a.request.widget_id == b.request.widget_id
            && a.widget_uid == b.widget_uid
            && a.binding_generation == b.binding_generation
            && a.context == b.context
            && a.model_revision == b.model_revision
            && a.action_sequence == b.action_sequence
            && a.value == b.value
            && a.selection == b.selection
            && a.focused == b.focused
            && a.domain == b.domain
            && before.snapshot_row == after.snapshot_row,
        "APP_SEMANTIC_PRESTATE_CHANGED",
    )
}

#[cfg(test)]
mod tests;
