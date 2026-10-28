//! Source-bound fixture observation only, not a general App Remote feature.
use super::protocol::{RemoteError, Result};
use serde_json::Value;

pub(super) fn validate_sample(
    value: &Value,
    pid: u32,
    window: u64,
    require_current: bool,
) -> Result<bool> {
    let refuse = RemoteError::refused;
    let object = value
        .as_object()
        .ok_or_else(|| refuse("FOCUS_PROBE_SCHEMA_INVALID"))?;
    let fields = [
        "schema",
        "pid",
        "sample_seq",
        "window_id",
        "window_index",
        "widget_id",
        "focused",
        "widget_uid",
    ];
    if object.len() != fields.len()
        || !fields.iter().all(|key| object.contains_key(*key))
        || value["schema"] != "toolkit-remote-focus-probe-v1"
        || value["pid"].as_u64() != Some(u64::from(pid))
        || value["widget_id"].as_str() != Some("input_singleline")
        || !value["sample_seq"].as_u64().is_some_and(|v| v > 0)
        || !value["focused"].is_boolean()
    {
        return Err(refuse("FOCUS_PROBE_SCHEMA_INVALID"));
    }
    let current = value["window_id"].as_str() == Some("main_window")
        && value["window_index"].as_u64() == Some(window)
        && value["widget_uid"].as_u64().is_some_and(|v| v > 0);
    if require_current && !current {
        return Err(refuse("FOCUS_PROBE_TARGET_UNAVAILABLE"));
    }
    if !require_current
        && !((value["window_id"].is_null() || value["window_id"].as_str() == Some("main_window"))
            && (value["window_index"].is_null() || value["window_index"].as_u64() == Some(window))
            && (value["widget_uid"].is_null()
                || value["widget_uid"].as_u64().is_some_and(|v| v > 0))
            && (current || value["focused"] == false))
    {
        return Err(refuse("FOCUS_PROBE_SCHEMA_INVALID"));
    }
    Ok(current && value["focused"] == true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn sample() -> Value {
        json!({"schema":"toolkit-remote-focus-probe-v1","pid":17,"sample_seq":1,
        "window_id":"main_window","window_index":0,"widget_id":"input_singleline","focused":true,"widget_uid":18})
    }
    #[test]
    fn fixture_focus_is_exact_not_window_activation_or_historical_sample() {
        assert!(validate_sample(&sample(), 17, 0, true).unwrap());
        let mut value = sample();
        value["focused"] = json!(false);
        assert!(!validate_sample(&value, 17, 0, true).unwrap());
        for (key, v) in [
            ("pid", json!(18)),
            ("window_index", json!(1)),
            ("widget_id", json!("neighbor")),
            ("widget_uid", json!(0)),
            ("sample_seq", json!(0)),
            ("focused", json!(1)),
            ("extra", json!(true)),
        ] {
            let mut invalid = sample();
            invalid[key] = v;
            assert!(validate_sample(&invalid, 17, 0, true).is_err());
        }
    }
    #[test]
    fn unavailable_fixture_target_can_only_seed_counter_never_focus() {
        let mut value = sample();
        for key in ["window_id", "window_index", "widget_uid"] {
            value[key] = Value::Null;
        }
        value["focused"] = json!(false);
        assert!(!validate_sample(&value, 17, 0, false).unwrap());
        assert!(validate_sample(&value, 17, 0, true).is_err());
        value["focused"] = json!(true);
        assert!(validate_sample(&value, 17, 0, false).is_err());
    }
}
