//! Bounded read-only FDL probing and shared Unix subprocess handling.
use crate::pac::{PacEntry, PacFile};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub(crate) const MIB: u64 = 1024 * 1024;

pub(crate) fn loader_entries(pac: &PacFile) -> Result<Vec<(&PacEntry, u32)>> {
    ensure!(
        pac.product == "ums512_1h10",
        "Unsupported product: {:?}",
        pac.product
    );
    let xml = pac.xml_text()?;
    let document = roxmltree::Document::parse(&xml).context("Invalid PAC XML")?;
    let mut result = Vec::new();
    for (name, expected) in [("FDL", 0x5500), ("FDL2", 0x9efffe00)] {
        let entries = pac.entries_for_id(name);
        let nodes: Vec<_> = document
            .descendants()
            .filter(|node| {
                node.has_tag_name("File")
                    && node.children().any(|child| {
                        child.has_tag_name("ID") && child.text().map(str::trim) == Some(name)
                    })
            })
            .collect();
        ensure!(
            entries.len() == 1 && nodes.len() == 1,
            "Exactly one {name} image and XML entry are required"
        );
        let base = nodes[0]
            .children()
            .find(|n| n.has_tag_name("Block"))
            .and_then(|n| n.children().find(|n| n.has_tag_name("Base")))
            .and_then(|n| n.text())
            .context("Loader base address missing")?
            .trim();
        let address =
            if let Some(hex) = base.strip_prefix("0x").or_else(|| base.strip_prefix("0X")) {
                u32::from_str_radix(hex, 16)
            } else {
                base.parse()
            }
            .context("Invalid loader base address")?;
        ensure!(
            address == expected,
            "Unrecognized {name} address: {address:#x}"
        );
        ensure!(
            entries[0].size > 0 && entries[0].size <= 16 * MIB,
            "Unreasonable {name} size"
        );
        result.push((entries[0], address));
    }
    Ok(result)
}

pub(crate) fn validate_wait(wait: u32) -> Result<()> {
    ensure!(
        (1..=120).contains(&wait),
        "wait must be between 1 and 120 seconds"
    );
    Ok(())
}

pub(crate) fn validate_backend(path: &Path) -> Result<PathBuf> {
    let backend = path.canonicalize().context("Backend does not exist")?;
    let metadata = backend.metadata()?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        "Backend must be an executable regular file"
    );
    Ok(backend)
}

pub(crate) fn private_directory(path: &Path) -> Result<PathBuf> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .with_context(|| format!("Output directory must be new: {}", path.display()))?;
    Ok(path.canonicalize()?)
}

pub(crate) fn private_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("Refusing to overwrite output: {}", path.display()))
}

pub(crate) fn save_json(path: &Path, value: &Value) -> Result<()> {
    let mut name = path
        .file_name()
        .context("Missing report filename")?
        .to_os_string();
    name.push(".tmp");
    let temporary = path.with_file_name(name);
    let mut stream = private_file(&temporary)?;
    let result = (|| {
        serde_json::to_writer_pretty(&mut stream, value)?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        stream.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[derive(Debug, Clone)]
pub(crate) struct BackendCommand {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    #[cfg(test)]
    pub env: Vec<(OsString, OsString)>,
}

impl BackendCommand {
    pub fn new(program: PathBuf) -> Self {
        Self {
            program,
            args: Vec::new(),
            #[cfg(test)]
            env: Vec::new(),
        }
    }
    pub fn words(&mut self, words: &[&str]) {
        self.args.extend(words.iter().map(OsString::from));
    }
    pub fn path(&mut self, path: &Path) {
        self.args.push(path.as_os_str().to_owned());
    }
}

pub(crate) enum OutputEvent {
    Data(Vec<u8>),
    End,
    Timeout,
}

struct SignalState {
    received: AtomicUsize,
    active: AtomicUsize,
    lifecycle: Mutex<()>,
}

struct ProcessSignals {
    state: Arc<SignalState>,
    _handlers: Vec<signal_hook::SigId>,
}

impl ProcessSignals {
    fn install() -> Result<Self> {
        let state = Arc::new(SignalState {
            received: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            lifecycle: Mutex::new(()),
        });
        let mut handlers = Vec::new();
        for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
            // Query only: do not restore raw dispositions around sessions. signal-hook
            // chains the existing custom action; an existing SIG_IGN stays ignored while idle.
            let mut previous = std::mem::MaybeUninit::<libc::sigaction>::uninit();
            ensure!(
                unsafe { libc::sigaction(signal, std::ptr::null(), previous.as_mut_ptr()) } == 0,
                "Reading signal disposition failed: {}",
                io::Error::last_os_error()
            );
            let was_default = unsafe { previous.assume_init() }.sa_sigaction == libc::SIG_DFL;
            let state = Arc::clone(&state);
            // SAFETY: the callback only uses lock-free atomics and signal-hook's
            // async-signal-safe default emulation. It never takes the lifecycle mutex.
            handlers.push(unsafe {
                signal_hook::low_level::register(signal, move || {
                    loop {
                        let active = state.active.load(Ordering::SeqCst);
                        if active == usize::MAX {
                            return;
                        } // Another idle signal is terminating.
                        if active > 0 {
                            state.received.store(signal as usize, Ordering::SeqCst);
                            return;
                        }
                        if !was_default {
                            return;
                        }
                        // Reserve termination before emulating the default: another thread
                        // must not start a backend between observing zero and process exit.
                        if state
                            .active
                            .compare_exchange(0, usize::MAX, Ordering::SeqCst, Ordering::SeqCst)
                            .is_ok()
                        {
                            let _ = signal_hook::low_level::emulate_default_handler(signal);
                            return;
                        }
                    }
                })?
            });
        }
        Ok(Self {
            state,
            _handlers: handlers,
        })
    }
}

static PROCESS_SIGNALS: OnceLock<std::result::Result<ProcessSignals, String>> = OnceLock::new();

/// Keep one process-wide action: unregistering the last signal-hook action would
/// silently ignore later signals. While sessions exist, flags drive cleanup; with
/// none, a disposition that was originally default gets its normal termination.
/// Pre-existing custom/ignored dispositions continue through signal-hook's chaining.
pub(crate) struct SessionSignals {
    state: Arc<SignalState>,
}

impl SessionSignals {
    pub fn new() -> Result<Self> {
        let process = PROCESS_SIGNALS
            .get_or_init(|| ProcessSignals::install().map_err(|e| format!("{e:#}")))
            .as_ref()
            .map_err(|error| anyhow::anyhow!("Signal initialization failed: {error}"))?;
        let state = Arc::clone(&process.state);
        {
            let _lock = state
                .lifecycle
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let count = state.active.load(Ordering::SeqCst);
            ensure!(
                count < usize::MAX - 1,
                "Process is terminating or too many backend sessions are active"
            );
            // Reset only between session groups. Concurrent sessions all observe a stop.
            if count == 0 {
                state.received.store(0, Ordering::SeqCst);
            }
            // The handler can reserve idle termination without the lifecycle mutex.
            ensure!(
                state
                    .active
                    .compare_exchange(count, count + 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok(),
                "Process termination interrupted backend session startup"
            );
        }
        let signals = Self { state };
        signals.check()?;
        Ok(signals)
    }

    pub fn check(&self) -> Result<()> {
        let signal = self.state.received.load(Ordering::SeqCst);
        ensure!(
            signal == 0,
            "USB operation interrupted by {}; no automatic retry or reset",
            if signal == signal_hook::consts::SIGINT as usize {
                "SIGINT"
            } else {
                "SIGTERM"
            }
        );
        Ok(())
    }
}

impl Drop for SessionSignals {
    fn drop(&mut self) {
        let _lock = self
            .state
            .lifecycle
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        self.state.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// One pipe preserves stdout/stderr ordering, including prompts without newlines.
/// The parent uses nonblocking poll; no reader thread can be stranded at shutdown.
pub(crate) struct BackendProcess {
    child: Child,
    output: File,
    input: Option<ChildStdin>,
    completed: bool,
}

impl BackendProcess {
    pub fn spawn(spec: &BackendCommand, interactive: bool) -> Result<Self> {
        let mut descriptors = [0; 2];
        // SAFETY: pipe initializes both descriptors on success; OwnedFd owns each once.
        ensure!(
            unsafe { libc::pipe(descriptors.as_mut_ptr()) } == 0,
            "Creating backend output pipe failed: {}",
            io::Error::last_os_error()
        );
        let read = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        for fd in [&read, &write] {
            ensure!(
                unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } >= 0,
                "Setting close-on-exec failed: {}",
                io::Error::last_os_error()
            );
        }
        let flags = unsafe { libc::fcntl(read.as_raw_fd(), libc::F_GETFL) };
        ensure!(
            flags >= 0
                && unsafe {
                    libc::fcntl(read.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
                } >= 0,
            "Setting nonblocking output failed: {}",
            io::Error::last_os_error()
        );
        let error_write = write.try_clone()?;
        let mut command = Command::new(&spec.program);
        command
            .args(&spec.args)
            .stdin(if interactive {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::from(write))
            .stderr(Stdio::from(error_write))
            .process_group(0);
        // SAFETY: only the async-signal-safe umask syscall runs between fork/exec.
        // Keep C fopen-created backup/readback files private without changing the parent.
        unsafe {
            command.pre_exec(|| {
                libc::umask(0o077);
                Ok(())
            });
        }
        #[cfg(test)]
        command.envs(spec.env.iter().map(|(key, value)| (key, value)));
        let mut child = command.spawn().context("Starting USB backend failed")?;
        let input = child.stdin.take();
        Ok(Self {
            child,
            input,
            output: File::from(read),
            completed: false,
        })
    }

    pub fn next_output(
        &mut self,
        timeout: Duration,
        signals: &SessionSignals,
    ) -> Result<OutputEvent> {
        signals.check()?;
        let millis = timeout.as_millis().clamp(1, 1000) as libc::c_int;
        let mut descriptor = libc::pollfd {
            fd: self.output.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let count = unsafe { libc::poll(&mut descriptor, 1, millis) };
        signals.check()?;
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(OutputEvent::Timeout);
            }
            return Err(error).context("Polling USB backend failed");
        }
        if count == 0 {
            return Ok(OutputEvent::Timeout);
        }
        ensure!(
            descriptor.revents & libc::POLLNVAL == 0,
            "Backend output descriptor became invalid"
        );
        let mut bytes = vec![0; 65536];
        match self.output.read(&mut bytes) {
            Ok(0) => Ok(OutputEvent::End),
            Ok(size) => {
                bytes.truncate(size);
                Ok(OutputEvent::Data(bytes))
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(OutputEvent::Timeout)
            }
            Err(error) => Err(error).context("Reading USB backend failed"),
        }
    }

    pub fn answer(&mut self, bytes: &[u8], signals: &SessionSignals) -> Result<()> {
        signals.check()?;
        // At most thirteen short, state-checked answers are sent in an installation.
        ensure!(bytes.len() <= 128, "Oversized backend response");
        let input = self
            .input
            .as_mut()
            .context("Read-only backend has no confirmation channel")?;
        input
            .write_all(bytes)
            .context("Sending backend confirmation failed")?;
        input.flush()?;
        Ok(())
    }

    pub fn finish(&mut self, timeout: Duration, signals: &SessionSignals) -> Result<ExitStatus> {
        let started = Instant::now();
        loop {
            signals.check()?;
            if let Some(status) = self.child.try_wait()? {
                self.completed = true;
                return Ok(status);
            }
            ensure!(
                started.elapsed() < timeout,
                "Backend did not exit after closing output"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn terminate(&mut self) {
        if self.completed {
            return;
        }
        // This process group was created only for our backend. Also end test/backend
        // descendants that might keep the output pipe open after their parent exits.
        unsafe {
            libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.completed = true;
    }
}

impl Drop for BackendProcess {
    fn drop(&mut self) {
        self.terminate();
    }
}

pub(crate) fn remaining_timeout(
    started: Instant,
    last_io: Instant,
    total: Duration,
    idle: Duration,
) -> Result<Duration> {
    let total_left = total.checked_sub(started.elapsed());
    let idle_left = idle.checked_sub(last_io.elapsed());
    match (total_left, idle_left) {
        (Some(total_left), Some(idle_left)) if !total_left.is_zero() && !idle_left.is_zero() => {
            Ok(total_left.min(idle_left).min(Duration::from_secs(1)))
        }
        _ => bail!("USB operation timed out; no automatic retry or reset"),
    }
}

pub(crate) fn echo_log(log: &mut File, bytes: &[u8]) -> Result<()> {
    log.write_all(bytes)?;
    log.flush()?;
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(bytes)?;
    stdout.flush()?;
    Ok(())
}

fn run_bounded(
    command: &BackendCommand,
    out: &Path,
    total: Duration,
    idle: Duration,
) -> Result<()> {
    let mut log = private_file(&out.join("probe.log"))?;
    let signals = SessionSignals::new()?;
    let mut process = BackendProcess::spawn(command, false)?;
    let started = Instant::now();
    let mut last_io = started;
    let mut written = 0usize;
    loop {
        let remaining = remaining_timeout(started, last_io, total, idle)?;
        match process.next_output(remaining, &signals)? {
            OutputEvent::Data(bytes) => {
                last_io = Instant::now();
                written += bytes.len();
                ensure!(written <= 4 * MIB as usize, "Unexpectedly large USB log");
                echo_log(&mut log, &bytes)?;
            }
            OutputEvent::End => break,
            OutputEvent::Timeout => {}
        }
    }
    let status = process.finish(Duration::from_secs(5), &signals)?;
    signals.check()?;
    ensure!(
        status.success(),
        "USB backend exited {status}; see {}",
        out.join("probe.log").display()
    );
    Ok(())
}

fn probe_arguments(
    pac: &PacFile,
    out: &Path,
    backend: PathBuf,
    wait: u32,
) -> Result<BackendCommand> {
    let mut command = BackendCommand::new(backend);
    command.words(&[
        "--read-only",
        "--wait",
        &wait.to_string(),
        "timeout",
        "15000",
    ]);
    for (index, (entry, address)) in loader_entries(pac)?.into_iter().enumerate() {
        let path = out.join(format!("fdl{}.bin", index + 1));
        pac.extract(entry, &path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        command.words(&["fdl"]);
        command.path(&path);
        command.words(&[&format!("{address:#x}")]);
    }
    command.words(&["disable_transcode", "partition_list"]);
    command.path(&out.join("partitions.xml"));
    command.words(&["read_part", "boot_a", "0", "1048576"]);
    command.path(&out.join("boot_a-first-1MiB.bin"));
    command.words(&["power_off"]);
    Ok(command)
}

fn validate_probe_output(out: &Path, state: &mut Value) -> Result<()> {
    let table = out.join("partitions.xml");
    let metadata = table.metadata().context("Missing partition table")?;
    ensure!(
        metadata.is_file() && metadata.len() <= MIB,
        "Missing or unreasonable partition table"
    );
    let xml = fs::read_to_string(&table)?;
    let document = roxmltree::Document::parse(&xml).context("Invalid partition table")?;
    for expected in ["super", "boot_a", "userdata"] {
        ensure!(
            document.descendants().any(|node| node
                .attribute("id")
                .or_else(|| node.attribute("name"))
                == Some(expected)),
            "Partition table does not describe the expected layout"
        );
    }
    let sample = out.join("boot_a-first-1MiB.bin");
    ensure!(
        sample.metadata()?.len() == MIB,
        "Incomplete boot partition sample"
    );
    state["status"] = json!("read_completed");
    state["sample_sha256"] = json!(hex::encode(Sha256::digest(fs::read(sample)?)));
    state["sample_bytes"] = json!(MIB);
    state["device_identity_verified"] = json!(false);
    state["limitation"] = json!(
        "Compare the sample hash and complete partition layout with a trusted baseline before any write."
    );
    Ok(())
}

pub fn probe(pac: &PacFile, out: &Path, backend: &Path, wait: u32) -> Result<Value> {
    validate_wait(wait)?;
    let backend = validate_backend(backend)?;
    pac.ensure_unchanged()?;
    let out = private_directory(out)?;
    let mut state = json!({"status": "running", "writes_to_device_storage": false,
        "ram_loader_execution": true, "product": pac.product});
    let result = (|| {
        let command = probe_arguments(pac, &out, backend, wait)?;
        run_bounded(
            &command,
            &out,
            Duration::from_secs(150u64.max(wait as u64 + 90)),
            Duration::from_secs(45u64.max(wait as u64 + 5)),
        )?;
        validate_probe_output(&out, &mut state)
    })();
    if let Err(error) = &result {
        state["status"] = json!("failed");
        state["error"] = json!(format!("{error:#}"));
    }
    save_json(&out.join("probe-result.json"), &state)?;
    result?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn private_outputs_refuse_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        assert!(private_directory(directory.path()).is_err());
        let path = directory.path().join("evidence");
        let mut first = private_file(&path).unwrap();
        first.write_all(b"keep").unwrap();
        assert!(private_file(&path).is_err());
        assert_eq!(fs::read(path).unwrap(), b"keep");
    }

    #[test]
    fn wait_is_bounded() {
        assert!(validate_wait(0).is_err());
        assert!(validate_wait(121).is_err());
        validate_wait(120).unwrap();
    }

    #[test]
    fn probe_output_is_not_identity_verification() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("partitions.xml"),
            b"<Partitions><Partition id='super'/><Partition id='boot_a'/><Partition id='userdata'/></Partitions>").unwrap();
        let sample = directory.path().join("boot_a-first-1MiB.bin");
        fs::write(&sample, vec![b'A'; MIB as usize]).unwrap();
        let mut state = json!({});
        validate_probe_output(directory.path(), &mut state).unwrap();
        assert_eq!(state["status"], "read_completed");
        assert_eq!(state["device_identity_verified"], false);
        fs::write(sample, b"short").unwrap();
        assert!(validate_probe_output(directory.path(), &mut state).is_err());
    }

    fn shell(script: &str) -> BackendCommand {
        let mut command = BackendCommand::new(PathBuf::from("/bin/sh"));
        command.words(&["-c", script]);
        command
    }

    #[test]
    fn bounded_probe_never_answers_storage_prompts() {
        let directory = tempfile::tempdir().unwrap();
        let command = shell(
            "printf 'Answer yes: '; if read answer; then exit 9; fi; printf '\\nstdin is closed\\n'",
        );
        run_bounded(
            &command,
            directory.path(),
            Duration::from_secs(2),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(
            fs::read_to_string(directory.path().join("probe.log"))
                .unwrap()
                .contains("stdin is closed")
        );
    }

    #[test]
    fn bounded_probe_handles_nonzero_and_timeout() {
        for script in ["printf 'failed\\n'; exit 7", "printf 'ready\\n'; sleep 10"] {
            let directory = tempfile::tempdir().unwrap();
            let started = Instant::now();
            assert!(
                run_bounded(
                    &shell(script),
                    directory.path(),
                    Duration::from_millis(150),
                    Duration::from_millis(100)
                )
                .is_err()
            );
            assert!(started.elapsed() < Duration::from_secs(2));
        }
    }

    #[test]
    fn existing_probe_log_prevents_subprocess_launch() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("probe.log"), b"keep").unwrap();
        let marker = directory.path().join("must-not-exist");
        let mut command = shell("touch \"$1\"");
        command.words(&["sh"]);
        command.path(&marker);
        assert!(
            run_bounded(
                &command,
                directory.path(),
                Duration::from_secs(1),
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(!marker.exists());
        assert_eq!(
            fs::read(directory.path().join("probe.log")).unwrap(),
            b"keep"
        );
    }

    #[test]
    #[ignore = "subprocess-only signal disposition runner"]
    fn signal_lifecycle_child() {
        let Ok(mode) = std::env::var("RGROTATE_SIGNAL_LIFECYCLE") else {
            return;
        };
        let signal: libc::c_int = std::env::var("RGROTATE_SIGNAL_NUMBER")
            .unwrap()
            .parse()
            .unwrap();
        assert!(matches!(signal, libc::SIGINT | libc::SIGTERM));
        let custom = Arc::new(AtomicUsize::new(0));
        if mode == "custom" {
            signal_hook::flag::register_usize(signal, Arc::clone(&custom), signal as usize)
                .unwrap();
        } else if mode == "ignored" {
            // Only this freshly exec'd fixture changes its initial disposition.
            assert_ne!(
                unsafe { libc::signal(signal, libc::SIG_IGN) },
                libc::SIG_ERR
            );
        }
        let first = SessionSignals::new().unwrap();
        let second = SessionSignals::new().unwrap();
        assert_eq!(first.state.active.load(Ordering::SeqCst), 2);
        signal_hook::low_level::raise(signal).unwrap();
        assert!(first.check().is_err() && second.check().is_err());
        // A concurrent session must not clear an already pending interruption.
        assert!(SessionSignals::new().is_err());
        assert_eq!(first.state.active.load(Ordering::SeqCst), 2);
        drop(first);
        assert_eq!(second.state.active.load(Ordering::SeqCst), 1);
        assert!(second.check().is_err());
        let shared = Arc::clone(&second.state);
        drop(second);
        assert_eq!(shared.active.load(Ordering::SeqCst), 0);
        let next = SessionSignals::new().unwrap();
        next.check().unwrap();
        drop(next);
        // Also complete a real bounded subprocess session before testing idle behavior.
        let directory = tempfile::tempdir().unwrap();
        run_bounded(
            &shell("printf 'done\\n'"),
            directory.path(),
            Duration::from_secs(2),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(shared.active.load(Ordering::SeqCst), 0);
        custom.store(0, Ordering::SeqCst);
        signal_hook::low_level::raise(signal).unwrap();
        assert_ne!(
            mode, "default",
            "idle signal incorrectly survived its default termination"
        );
        if mode == "custom" {
            assert_eq!(custom.load(Ordering::SeqCst), signal as usize);
        } else {
            assert_eq!(custom.load(Ordering::SeqCst), 0);
        }
        // Idle custom/ignored signals must not poison the next independent session.
        let next = SessionSignals::new().unwrap();
        next.check().unwrap();
        drop(next);
    }

    #[test]
    fn isolated_post_session_default_custom_and_ignored_signal_behavior() {
        for signal in [libc::SIGINT, libc::SIGTERM] {
            for mode in ["default", "custom", "ignored"] {
                let mut child = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--ignored",
                        "--exact",
                        "transport::tests::signal_lifecycle_child",
                        "--nocapture",
                        "--quiet",
                    ])
                    .env("RGROTATE_SIGNAL_LIFECYCLE", mode)
                    .env("RGROTATE_SIGNAL_NUMBER", signal.to_string())
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                let started = Instant::now();
                let status = loop {
                    if let Some(status) = child.try_wait().unwrap() {
                        break status;
                    }
                    if started.elapsed() > Duration::from_secs(4) {
                        let _ = child.kill();
                        let _ = child.wait();
                        panic!("isolated signal lifecycle test timed out");
                    }
                    std::thread::sleep(Duration::from_millis(5));
                };
                if mode == "default" {
                    assert_eq!(status.signal(), Some(signal));
                } else {
                    assert!(status.success(), "{mode} signal {signal}: {status}");
                }
            }
        }
    }
}
