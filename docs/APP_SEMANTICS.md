# Makepad App Semantics

## Scope

App Semantics is a typed, opt-in layer on the existing Makepad Remote adapter. It does not add a service, transport, route, or MCP tool. It is separate from the existing `WindowsAccessibilityBridge` UI Automation tree and patterns; this API does not use UIA `InvokePattern` or `ValuePattern.SetValue`.

## Bindings and limits

An `AppContract` allowlists at most 128 widgets and maps each approved `AutomationId` to its actual Makepad Remote snapshot `WidgetId`, exact widget kind, and permitted actions. Supported kinds are `TextInput` and `Button`: a `TextInput` may allow `Read`, `Focus`, `TypeText`, `SelectAll`, and `Backspace`; a `Button` may allow only `Read` and `Invoke`. The current snapshot row, window, and type must match. An independent app observation must also identify the live `WidgetUid` and binding generation; a source declaration or caller-supplied observation is not proof of a live binding.

The app producer samples actual `Cx` key focus, value, and selection on the UI thread. Selection offsets are UTF-8 byte offsets and must match the widget's real selection. Domain readback is restricted to at most 32 approved keys. An observation is limited to 64 KiB. `TypeText` accepts 1 to 4,096 UTF-8 bytes and rejects control characters, including LF. It requires an empty, focused input with observed selection `[0, 0]`. `Backspace` is supported only when the actual selection covers the full current value; `SelectAll` requires independent selection readback.

## Required consumer hooks

The existing authenticated owner channel must provide app observations; MCP arguments must not be able to impersonate the app. The app must resolve allowlisted IDs through its live widget registry, then report the actual UID, type, enabled/visible state, binding generation, focus, value, selection, document/object context, and domain revision from one UI-thread observation with a monotonically increasing sequence.

For a mutation, the app must arm a one-shot authorization for that exact owner, widget UID, context, revision, action, and payload. Recheck the expected focus/value/selection before the widget handles its event, then recheck the approved domain prestate and target before any domain mutation. Consume the authorization once through the ordinary widget and domain action path. Disarm that exact authorization on success, refusal, timeout, cancellation, or disconnect. A request echo, click acknowledgement, foreground state, or snapshot alone is not proof of focus or action.

Every handled semantic action must produce an `ActionObservation` with the next action sequence, the authorization challenge (nonce), exact `AutomationId`, `WidgetUid`, and action. For Button `Invoke`, success additionally requires the approved domain key/value in the exact expected post-action context. If post-dispatch evidence is missing or contradictory, the outcome is unknown: retain that status, fence further mutation, and do not automatically replay. Cancellation must still retire the one-shot authorization; it does not prove that an event was not dispatched.

Button `Invoke` means `APP_REMOTE_BUTTON_CLICK_WITH_APP_READBACK`: deliver the existing app Remote click and verify the one-shot action witness plus the explicit domain postcondition. It is not UIA `InvokePattern`, a direct handler call, or `SetValue`.

## Availability and verification boundary

The concrete production observation hook refuses with `UNSUPPORTED_APP_SEMANTIC_OBSERVATION`; arm and disarm refuse with `UNSUPPORTED_APP_SEMANTIC_ACTION_GUARD`. No Windows or WSLC app-semantic producer is installed. The Button MCP router projection is `NOT_WIRED`; the existing configured widget projection remains TextInput-only. This contract adds no tools or transport, so consumers cannot invoke Button semantics through MCP yet.

A consumer integration requires source review of its app hooks, ABI/build binding, authenticated owner channel, and live registry/action path. A declared source digest alone does not verify the compiled source. Existing `WindowsAccessibilityBridge` UIA semantics remain a separate capability.

The semantic patch passed 19 focused and 308 owning-crate unit tests in isolated source-only verification. Those results do not qualify the published package's consumer integration or establish native-runtime, WSLC, or GPU acceptance.

