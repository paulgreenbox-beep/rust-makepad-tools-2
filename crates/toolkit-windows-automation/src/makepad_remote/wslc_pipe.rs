//! JSONL pipe extracted from the retained linux-adapter Pipe, not its semantic engine.
//! The owner admits the executable/helper/configuration and interprets valid replies.
//! The helper MUST independently enforce a 30s idle/protocol-I/O TTL and finally cleanup.
//! Disconnect requests EOF, but a stalled writer retains stdin until its I/O ends.
//! Caller deadlines do not prove immediate EOF or cleanup; this module never kills.

use super::protocol::{RemoteError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::OpenOptions,
    io::{self, BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
    thread,
    time::{Duration, Instant},
};

// Includes the terminating LF. HTTP body limits remain the owner's responsibility.
const MAX_REPLY_FRAME: usize = 32 * 1024 * 1024;
const MAX_REQUEST_FRAME: usize = 64 * 1024;
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const REPLY_TIMEOUT: Duration = Duration::from_secs(110);
const FINISH_TIMEOUT: Duration = Duration::from_secs(110);

#[derive(Serialize)]
struct Request<'a> {
    version: u8,
    sequence: u64,
    operation: &'a str,
    arguments: Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SuccessReply {
    version: u64,
    sequence: u64,
    ok: bool,
    result: Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FailureReply {
    version: u64,
    sequence: u64,
    ok: bool,
    error: HelperError,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HelperError {
    code: String,
    dispatched: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum Reply {
    Success(SuccessReply),
    Failure(FailureReply),
}

impl Reply {
    fn correlated(self, expected: u64) -> Result<Value> {
        let (version, sequence, valid_outcome) = match &self {
            Self::Success(reply) => (reply.version, reply.sequence, reply.ok),
            Self::Failure(reply) => (reply.version, reply.sequence, !reply.ok),
        };
        if !valid_outcome {
            return Err(RemoteError::unknown("WSLC_PIPE_ENVELOPE"));
        }
        if version != 1 {
            return Err(RemoteError::unknown("WSLC_PIPE_VERSION"));
        }
        if sequence == 0 || sequence != expected {
            return Err(RemoteError::unknown("WSLC_PIPE_SEQUENCE"));
        }
        serde_json::to_value(self).map_err(|_| RemoteError::unknown("WSLC_PIPE_ENVELOPE"))
    }
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "JSONL size limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn next_sequence(sequence: u64) -> Result<u64> {
    sequence.checked_add(1).ok_or_else(|| RemoteError::unknown("WSLC_PIPE_SEQUENCE_EXHAUSTED"))
}

fn encode_request(sequence: u64, operation: &str, arguments: Value, limit: usize) -> Result<Vec<u8>> {
    let mut writer = BoundedWriter { bytes: Vec::new(), limit: limit.saturating_sub(1) };
    let request = Request { version: 1, sequence, operation, arguments };
    serde_json::to_writer(&mut writer, &request)
        .map_err(|_| RemoteError::unknown("WSLC_PIPE_REQUEST_TOO_LARGE"))?;
    if limit == 0 {
        return Err(RemoteError::unknown("WSLC_PIPE_REQUEST_TOO_LARGE"));
    }
    writer.bytes.push(b'\n');
    Ok(writer.bytes)
}

fn read_reply(reader: &mut impl BufRead, limit: usize) -> Result<Option<Reply>> {
    let mut bytes = Vec::new();
    let count = reader.take(limit as u64 + 1).read_until(b'\n', &mut bytes)
        .map_err(|_| RemoteError::unknown("WSLC_PIPE_READ"))?;
    if count == 0 {
        return Ok(None);
    }
    if bytes.len() > limit {
        return Err(RemoteError::unknown("WSLC_PIPE_REPLY_TOO_LARGE"));
    }
    if bytes.last() != Some(&b'\n') {
        return Err(RemoteError::unknown("WSLC_PIPE_TRUNCATED_FRAME"));
    }
    let value = serde_json::from_slice::<super::protocol::UniqueJson>(&bytes)
        .map_err(|_| RemoteError::unknown("WSLC_PIPE_ENVELOPE"))?;
    serde_json::from_value(value.0).map(Some)
        .map_err(|_| RemoteError::unknown("WSLC_PIPE_ENVELOPE"))
}

#[derive(Debug)]
struct WriteJob {
    frame: Vec<u8>,
    ack: SyncSender<Result<()>>,
}

// Only the detached worker performs potentially blocking stdin I/O. Returning
// false stops the worker and drops stdin; no write or flush is replayed here.
fn write_job(input: &mut impl Write, job: WriteJob) -> bool {
    let result = input.write_all(&job.frame).and_then(|_| input.flush())
        .map_err(|_| RemoteError::unknown("WSLC_PIPE_WRITE"));
    let failed = result.is_err();
    // Each fresh bounded ack channel receives exactly one result, never a queue
    // of retries. A caller timeout drops its receiver; then the worker exits.
    job.ack.try_send(result).is_ok() && !failed
}

fn writer_loop(mut input: impl Write, jobs: Receiver<WriteJob>) {
    while let Ok(job) = jobs.recv() {
        if !write_job(&mut input, job) {
            break;
        }
    }
    // stdin is dropped here, possibly AFTER the caller's deadline/Drop.
}

fn send_packet(jobs: &SyncSender<WriteJob>, frame: Vec<u8>, timeout: Duration) -> Result<()> {
    let (ack, receipt) = mpsc::sync_channel(1);
    jobs.try_send(WriteJob { frame, ack }).map_err(|error| RemoteError::unknown(match error {
        TrySendError::Full(_) => "WSLC_PIPE_WRITER_BUSY",
        TrySendError::Disconnected(_) => "WSLC_PIPE_WRITER_CLOSED",
    }))?;
    receipt.recv_timeout(timeout).map_err(|error| RemoteError::unknown(match error {
        RecvTimeoutError::Timeout => "WSLC_PIPE_WRITE_TIMEOUT",
        RecvTimeoutError::Disconnected => "WSLC_PIPE_WRITE_ACK_LOST",
    }))?
}

pub(super) struct WslcPipe {
    child: Child,
    writer: Option<SyncSender<WriteJob>>,
    replies: Option<Receiver<Result<Reply>>>,
    sequence: u64,
    poisoned: bool,
    close_requested_at: Option<Instant>,
}

impl WslcPipe {
    pub(super) fn spawn(python: &Path, helper: &Path, config: &Path, stderr: &Path) -> Result<Self> {
        if [python, helper, config].iter().any(|p| !p.is_absolute() || !p.is_file())
            || !stderr.is_absolute()
        {
            return Err(RemoteError::refused("WSLC_PIPE_SPAWN_PATH"));
        }
        let log = OpenOptions::new().create_new(true).write(true).open(stderr)
            .map_err(|_| RemoteError::refused("WSLC_PIPE_STDERR_CREATE"))?;
        let mut command = Command::new(python);
        command.arg("-I").arg("-B").arg("-u").arg(helper).arg(config)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(log);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        let mut child = command.spawn().map_err(|_| RemoteError::refused("WSLC_PIPE_SPAWN"))?;
        let input = child.stdin.take().ok_or_else(|| RemoteError::unknown("WSLC_PIPE_STDIN"))?;
        let output = child.stdout.take().ok_or_else(|| RemoteError::unknown("WSLC_PIPE_STDOUT"))?;
        let (sender, replies) = mpsc::sync_channel(1);
        thread::Builder::new().name("makepad-wslc-pipe-reader".into()).spawn(move || {
            let mut reader = BufReader::new(output);
            loop {
                let reply = match read_reply(&mut reader, MAX_REPLY_FRAME) {
                    Ok(None) => break,
                    Ok(Some(reply)) => Ok(reply),
                    Err(error) => Err(error),
                };
                let invalid = reply.is_err();
                if sender.send(reply).is_err() || invalid {
                    break;
                }
            }
        }).map_err(|_| RemoteError::unknown("WSLC_PIPE_READER_SPAWN"))?;
        let (writer, jobs) = mpsc::sync_channel(1);
        thread::Builder::new().name("makepad-wslc-pipe-writer".into())
            .spawn(move || writer_loop(input, jobs))
            .map_err(|_| RemoteError::unknown("WSLC_PIPE_WRITER_SPAWN"))?;
        Ok(Self { child, writer: Some(writer), replies: Some(replies), sequence: 0, poisoned: false, close_requested_at: None })
    }

    fn close_writer(&mut self) {
        self.writer.take();
        // This anchors a disconnect REQUEST, not observed EOF. The helper's
        // independent TTL must unblock stalled I/O and own finally cleanup.
        self.close_requested_at.get_or_insert_with(Instant::now);
    }

    pub(super) fn exchange(&mut self, operation: &str, arguments: Value) -> Result<Value> {
        if self.poisoned {
            return Err(RemoteError::unknown("WSLC_PIPE_POISONED"));
        }
        if self.writer.is_none() {
            return Err(RemoteError::unknown("WSLC_PIPE_CLOSED"));
        }
        let result = self.exchange_once(operation, arguments);
        if result.is_err() {
            self.poisoned = true;
            self.close_writer();
            self.replies.take(); // No late reply can be consumed by a later call.
        }
        result
    }

    fn exchange_once(&mut self, operation: &str, arguments: Value) -> Result<Value> {
        let sequence = next_sequence(self.sequence)?;
        let request = encode_request(sequence, operation, arguments, MAX_REQUEST_FRAME)?;
        self.sequence = sequence; // Never reuse an attempted request's sequence.
        let writer = self.writer.as_ref().ok_or_else(|| RemoteError::unknown("WSLC_PIPE_CLOSED"))?;
        send_packet(writer, request, WRITE_TIMEOUT)?;
        let reply = self.replies.as_ref().ok_or_else(|| RemoteError::unknown("WSLC_PIPE_CLOSED"))?
            .recv_timeout(REPLY_TIMEOUT).map_err(|error| RemoteError::unknown(match error {
                RecvTimeoutError::Timeout => "WSLC_PIPE_REPLY_TIMEOUT",
                RecvTimeoutError::Disconnected => "WSLC_PIPE_REPLY_EOF",
            }))??;
        reply.correlated(sequence)
    }

    /// Observes helper exit only, not independent guest/App cleanup or action commit.
    pub(super) fn finish(&mut self) -> Result<()> {
        self.close_writer();
        self.replies.take();
        let close_requested_at = self.close_requested_at.expect("close_writer records its anchor");
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(_)) => return Err(RemoteError::unknown("WSLC_PIPE_HELPER_EXIT")),
                Err(_) => return Err(RemoteError::unknown("WSLC_PIPE_HELPER_WAIT")),
                Ok(None) => {}
            }
            let remaining = FINISH_TIMEOUT.checked_sub(close_requested_at.elapsed())
                .ok_or_else(|| RemoteError::unknown("WSLC_PIPE_HELPER_WAIT_TIMEOUT"))?;
            if remaining.is_zero() {
                return Err(RemoteError::unknown("WSLC_PIPE_HELPER_WAIT_TIMEOUT"));
            }
            thread::sleep(remaining.min(Duration::from_millis(25)));
        }
    }
}

impl Drop for WslcPipe {
    fn drop(&mut self) {
        // No wait/kill. A stalled worker may still own stdin after this returns.
        self.writer.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{cell::RefCell, io::Cursor, rc::Rc};

    #[derive(Default)]
    struct WriteState {
        bytes: Vec<u8>,
        writes: usize,
        flushes: usize,
        dropped: bool,
    }

    struct FakeWriter {
        state: Rc<RefCell<WriteState>>,
        fail_write: bool,
        fail_flush: bool,
    }

    impl Write for FakeWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let mut state = self.state.borrow_mut();
            state.writes += 1;
            if self.fail_write {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "synthetic write failure"));
            }
            state.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.state.borrow_mut().flushes += 1;
            if self.fail_flush {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "synthetic flush failure"));
            }
            Ok(())
        }
    }

    impl Drop for FakeWriter {
        fn drop(&mut self) {
            self.state.borrow_mut().dropped = true;
        }
    }

    fn fake_writer(fail_write: bool, fail_flush: bool) -> (FakeWriter, Rc<RefCell<WriteState>>) {
        let state = Rc::new(RefCell::new(WriteState::default()));
        (FakeWriter { state: state.clone(), fail_write, fail_flush }, state)
    }

    fn decode(bytes: &[u8], sequence: u64) -> Result<Value> {
        read_reply(&mut Cursor::new(bytes), MAX_REPLY_FRAME)?.ok_or_else(|| RemoteError::unknown("WSLC_PIPE_REPLY_EOF"))?
            .correlated(sequence)
    }

    #[test]
    fn request_has_exact_fixed_envelope_and_newline() {
        let bytes = encode_request(7, "inspect", json!({"body_utf8":"строка\n"}), MAX_REQUEST_FRAME).unwrap();
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert_eq!(bytes.iter().filter(|b| **b == b'\n').count(), 1);
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), json!({
            "version":1,"sequence":7,"operation":"inspect","arguments":{"body_utf8":"строка\n"}
        }));
    }

    #[test]
    fn request_bound_includes_newline_and_escaped_bytes() {
        let args = json!({"body_utf8":"\u{0001}".repeat(MAX_REQUEST_FRAME / 6)});
        assert_eq!(encode_request(1, "request", args, MAX_REQUEST_FRAME).unwrap_err().code, "WSLC_PIPE_REQUEST_TOO_LARGE");
        let bytes = encode_request(1, "inspect", Value::Null, MAX_REQUEST_FRAME).unwrap();
        assert!(encode_request(1, "inspect", Value::Null, bytes.len()).is_ok());
        assert!(encode_request(1, "inspect", Value::Null, bytes.len() - 1).is_err());
    }

    #[test]
    fn reply_bound_includes_newline_and_does_not_consume_next_frame() {
        let bytes = b"{\"version\":1,\"sequence\":1,\"ok\":true,\"result\":null}\n";
        let joined = [bytes.as_slice(), bytes.as_slice()].concat();
        let mut reader = Cursor::new(joined);
        assert!(read_reply(&mut reader, bytes.len()).unwrap().is_some());
        assert_eq!(reader.position(), bytes.len() as u64);
        assert_eq!(read_reply(&mut Cursor::new(bytes), bytes.len() - 1).unwrap_err().code, "WSLC_PIPE_REPLY_TOO_LARGE");
        let mut reader = Cursor::new(vec![b'x'; 1024]);
        assert!(read_reply(&mut reader, 32).is_err());
        assert_eq!(reader.position(), 33);
    }

    #[test]
    fn empty_eof_and_partial_frame_are_distinct() {
        assert!(read_reply(&mut Cursor::new(b""), MAX_REPLY_FRAME).unwrap().is_none());
        assert_eq!(decode(b"{}", 1).unwrap_err().code, "WSLC_PIPE_TRUNCATED_FRAME");
    }

    #[test]
    fn strict_envelope_rejects_unknown_duplicate_missing_and_wrong_types() {
        for text in [
            r#"{"version":1,"sequence":1,"ok":true}"#,
            r#"{"version":1,"sequence":1,"result":null}"#,
            r#"{"version":1,"sequence":1,"ok":true,"result":null,"extra":0}"#,
            r#"{"version":1,"sequence":1,"sequence":1,"ok":true,"result":null}"#,
            r#"{"version":1,"sequence":1,"ok":true,"result":null,"result":0}"#,
            r#"{"version":"1","sequence":1,"ok":true,"result":null}"#,
            r#"{"version":1,"sequence":1.0,"ok":true,"result":null}"#,
            r#"{"version":1,"sequence":1,"ok":1,"result":null}"#,
        ] {
            assert_eq!(decode(format!("{text}\n").as_bytes(), 1).unwrap_err().code, "WSLC_PIPE_ENVELOPE", "{text}");
        }
    }

    #[test]
    fn nested_duplicate_identity_and_value_keys_are_rejected() {
        for text in [
            r#"{"version":1,"sequence":1,"ok":true,"result":{"identity":{"pid":7,"pid":8}}}"#,
            r#"{"version":1,"sequence":1,"ok":true,"result":{"identity":{"executable":"a","executable":"b"}}}"#,
            r#"{"version":1,"sequence":1,"ok":true,"result":{"widgets":[{"value":"ALPHA","value":"BRAVO"}]}}"#,
            r#"{"version":1,"sequence":1,"ok":true,"result":{"widgets":[{"value":"ALPHA","\u0076alue":"BRAVO"}]}}"#,
        ] {
            let error = decode(format!("{text}\n").as_bytes(), 1).unwrap_err();
            assert_eq!(error.code, "WSLC_PIPE_ENVELOPE", "{text}");
            assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
            assert!(!error.retry_safe);
        }
        let reply = json!({"version":1,"sequence":1,"ok":true,"result":{
            "identity":{"pid":7},"widgets":[{"value":"ALPHA"},{"value":"BRAVO"}]
        }});
        assert_eq!(decode(format!("{reply}\n").as_bytes(), 1).unwrap(), reply);
    }

    #[test]
    fn success_and_error_are_exclusive_and_helper_errors_are_not_classified() {
        assert_eq!(decode(b"{\"version\":1,\"sequence\":1,\"ok\":true,\"result\":null}\n", 1).unwrap()["result"], Value::Null);
        for dispatched in [false, true] {
            let reply = json!({"version":1,"sequence":1,"ok":false,"error":{"code":"OWNER_DECIDES","dispatched":dispatched}});
            assert_eq!(decode(format!("{reply}\n").as_bytes(), 1).unwrap(), reply);
        }
        for text in [
            r#"{"version":1,"sequence":1,"ok":false,"result":null}"#,
            r#"{"version":1,"sequence":1,"ok":true,"error":{"code":"X","dispatched":false}}"#,
            r#"{"version":1,"sequence":1,"ok":false,"result":null,"error":{"code":"X","dispatched":false}}"#,
            r#"{"version":1,"sequence":1,"ok":false,"error":{"code":"X"}}"#,
            r#"{"version":1,"sequence":1,"ok":false,"error":{"code":"X","dispatched":0}}"#,
            r#"{"version":1,"sequence":1,"ok":false,"error":{"code":"X","code":"X","dispatched":false}}"#,
            r#"{"version":1,"sequence":1,"ok":false,"error":{"code":"X","dispatched":false,"extra":0}}"#,
        ] {
            assert_eq!(decode(format!("{text}\n").as_bytes(), 1).unwrap_err().code, "WSLC_PIPE_ENVELOPE", "{text}");
        }
    }

    #[test]
    fn correlation_rejects_wrong_version_zero_and_mismatched_sequence() {
        for (version, sequence, expected_code) in [(2, 1, "WSLC_PIPE_VERSION"), (1, 0, "WSLC_PIPE_SEQUENCE"), (1, 2, "WSLC_PIPE_SEQUENCE")] {
            let bytes = format!("{}\n", json!({"version":version,"sequence":sequence,"ok":true,"result":{}}));
            let error = decode(bytes.as_bytes(), 1).unwrap_err();
            assert_eq!(error.code, expected_code);
            assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
            assert!(!error.retry_safe);
        }
    }

    #[test]
    fn sequence_exhaustion_never_wraps() {
        assert_eq!(next_sequence(0).unwrap(), 1);
        assert_eq!(next_sequence(u64::MAX - 1).unwrap(), u64::MAX);
        assert_eq!(next_sequence(u64::MAX).unwrap_err().code, "WSLC_PIPE_SEQUENCE_EXHAUSTED");
    }

    #[test]
    fn strict_json_rejects_invalid_utf8_trailing_json_and_unpaired_surrogates() {
        for bytes in [
            b"\xff\n".as_slice(),
            b"{} {}\n".as_slice(),
            b"{\"version\":1,\"sequence\":1,\"ok\":true,\"result\":\"\\uD800\"}\n".as_slice(),
        ] {
            assert_eq!(decode(bytes, 1).unwrap_err().code, "WSLC_PIPE_ENVELOPE");
        }
    }

    #[test]
    fn writer_flushes_exact_encoded_packet_before_success_ack() {
        let frame = encode_request(1, "inspect", Value::Null, MAX_REQUEST_FRAME).unwrap();
        let (sender, jobs) = mpsc::sync_channel(1);
        let (ack, receipt) = mpsc::sync_channel(1);
        sender.try_send(WriteJob { frame: frame.clone(), ack }).unwrap();
        drop(sender); // Inline pure worker cannot wait for another job.
        let (input, state) = fake_writer(false, false);
        writer_loop(input, jobs);
        receipt.try_recv().unwrap().unwrap();
        let state = state.borrow();
        assert_eq!(state.bytes, frame);
        assert_eq!((state.writes, state.flushes), (1, 1));
        assert!(state.dropped);
    }

    #[test]
    fn writer_packet_write_or_flush_error_is_unknown_and_not_retried() {
        for (fail_write, fail_flush) in [(true, false), (false, true)] {
            let (mut input, state) = fake_writer(fail_write, fail_flush);
            let (ack, receipt) = mpsc::sync_channel(1);
            assert!(!write_job(&mut input, WriteJob { frame: b"packet\n".to_vec(), ack }));
            let error = receipt.try_recv().unwrap().unwrap_err();
            assert_eq!(error.code, "WSLC_PIPE_WRITE");
            assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
            assert!(!error.retry_safe);
            assert_eq!(state.borrow().writes, 1);
            assert_eq!(state.borrow().flushes, if fail_write { 0 } else { 1 });
        }
    }

    #[test]
    fn writer_ack_timeout_drops_receipt_and_allows_only_late_single_completion() {
        let (sender, jobs) = mpsc::sync_channel(1);
        let frame = b"packet\n".to_vec();
        // No worker/thread runs before this zero-timeout call returns.
        let error = send_packet(&sender, frame.clone(), Duration::ZERO).unwrap_err();
        assert_eq!(error.code, "WSLC_PIPE_WRITE_TIMEOUT");
        assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
        assert!(!error.retry_safe);
        drop(sender); // Same disconnect request used by the owner's poison path.
        let (input, state) = fake_writer(false, false);
        writer_loop(input, jobs); // Any accepted job may finish after timeout.
        let state = state.borrow();
        assert_eq!(state.bytes, frame);
        assert_eq!((state.writes, state.flushes), (1, 1));
        assert!(state.dropped);
    }

    #[test]
    fn writer_busy_or_disconnected_channel_refuses_without_blocking_or_requeue() {
        let (sender, jobs) = mpsc::sync_channel(1);
        let (ack, _receipt) = mpsc::sync_channel(1);
        sender.try_send(WriteJob { frame: b"first\n".to_vec(), ack }).unwrap();
        let error = send_packet(&sender, b"second\n".to_vec(), Duration::ZERO).unwrap_err();
        assert_eq!(error.code, "WSLC_PIPE_WRITER_BUSY");
        assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
        assert_eq!(jobs.try_recv().unwrap().frame, b"first\n");
        assert!(matches!(jobs.try_recv(), Err(mpsc::TryRecvError::Empty)));
        drop(jobs);
        let error = send_packet(&sender, b"third\n".to_vec(), Duration::ZERO).unwrap_err();
        assert_eq!(error.code, "WSLC_PIPE_WRITER_CLOSED");
        assert_eq!(error.outcome, "OUTCOME_UNKNOWN");
        assert!(!error.retry_safe);
    }

    #[test]
    fn writer_stops_after_abandoned_ack_receiver() {
        let (mut input, state) = fake_writer(false, false);
        let (ack, receipt) = mpsc::sync_channel(1);
        drop(receipt);
        assert!(!write_job(&mut input, WriteJob { frame: b"packet\n".to_vec(), ack }));
        assert!(!state.borrow().dropped); // The worker still owns stdin until it exits.
        drop(input);
        assert!(state.borrow().dropped);
        assert_eq!(state.borrow().writes, 1);
    }
}
