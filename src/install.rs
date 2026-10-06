//! Guarded Full installation: preserve the layout/boot chain and verify every write.
use crate::pac::PacFile;
use crate::target::{
    ValidatedPac, patch_misc, required_before_reads, sha256_file, validate_pac, validate_preflight,
};
use crate::transport::{
    BackendCommand, BackendProcess, MIB, OutputEvent, SessionSignals, echo_log, loader_entries,
    private_directory, private_file, remaining_timeout, save_json, validate_backend, validate_wait,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const WRITE_ORDER: [&str; 6] = [
    "super",
    "vbmeta_system_a",
    "vbmeta_system_ext_a",
    "vbmeta_vendor_a",
    "vbmeta_product_a",
    "misc",
];
const WRITE_PROMPT: &[u8] = b"Answer \"yes\" to confirm the \"write partition\" command: ";

#[derive(Clone, Debug)]
struct ImageSpec {
    size: u64,
    sha256: String,
}

trait PreflightValidation {
    fn validate(&self, out: &Path) -> Result<Value>;
}
impl PreflightValidation for ValidatedPac<'_> {
    fn validate(&self, out: &Path) -> Result<Value> {
        validate_preflight(self, out)
    }
}

fn verify_file(path: &Path, size: u64, digest: &str) -> Result<Value> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("Incomplete file: {}", path.display()))?;
    ensure!(
        metadata.is_file() && metadata.len() == size,
        "Incomplete file: {}",
        path.display()
    );
    let actual = sha256_file(path)?;
    ensure!(actual == digest, "SHA-256 mismatch: {}", path.display());
    Ok(json!({"bytes": size, "sha256": actual}))
}

struct InstallSession<'a> {
    preflight: &'a dyn PreflightValidation,
    out: PathBuf,
    images: BTreeMap<String, ImageSpec>,
    preflight_ok: bool,
    confirmed: usize,
    verified: usize,
    state: Value,
}

impl<'a> InstallSession<'a> {
    fn new(
        preflight: &'a dyn PreflightValidation,
        out: PathBuf,
        images: BTreeMap<String, ImageSpec>,
    ) -> Result<Self> {
        // Reserve the first report atomically, including against dangling symlinks.
        // Later saves only replace this session's own report.
        let _report = private_file(&out.join("install-result.json"))?;
        let result = Self {
            preflight,
            out,
            images,
            preflight_ok: false,
            confirmed: 0,
            verified: 0,
            state: json!({"status": "prepared", "writes_started": false,
                "verified_partitions": {}, "restore_user_data": false,
                "factory_reset_requested": false, "boot_verified": false,
                "scope": "Full OS over FDL, preserve layout and boot chain, Recovery wipe"}),
        };
        result.save()?;
        Ok(result)
    }
    fn save(&self) -> Result<()> {
        save_json(&self.out.join("install-result.json"), &self.state)
    }

    fn checkpoint(&mut self, token: &str) -> Result<Vec<u8>> {
        ensure!(
            !token.is_empty()
                && token.len() <= 64
                && token
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'),
            "Invalid checkpoint token"
        );
        if token == "preflight" {
            ensure!(
                !self.preflight_ok && self.confirmed == 0,
                "Duplicate or late preflight checkpoint"
            );
            self.state["preflight"] = self.preflight.validate(&self.out)?;
            let before = fs::read(self.out.join("before/misc.bin"))?;
            let patched = patch_misc(&before)?;
            let target = self.out.join("images/misc.bin");
            let mut stream = private_file(&target)?;
            stream.write_all(&patched)?;
            stream.flush()?;
            stream.sync_all()?;
            self.images.insert(
                "misc".to_owned(),
                ImageSpec {
                    size: patched.len() as u64,
                    sha256: sha256_file(&target)?,
                },
            );
            self.preflight_ok = true;
            self.state["status"] = json!("preflight_verified");
        } else {
            ensure!(
                self.preflight_ok && self.verified < WRITE_ORDER.len(),
                "Unexpected verification checkpoint"
            );
            let part = WRITE_ORDER[self.verified];
            ensure!(
                token == format!("verified_{part}") && self.confirmed == self.verified + 1,
                "Out-of-order checkpoint: {token}"
            );
            let image = self
                .images
                .get(part)
                .context("Missing image specification")?;
            let after = self.out.join(format!("after/{part}.bin"));
            let checked = verify_file(&after, image.size, &image.sha256)?;
            if part == "misc" {
                let original = fs::read(self.out.join("before/misc.bin"))?;
                ensure!(
                    fs::read(&after)? == patch_misc(&original)?,
                    "misc readback changed unrelated fields"
                );
                self.state["factory_reset_requested"] = json!(true);
            }
            self.state["verified_partitions"][part] = checked;
            self.verified += 1;
            self.state["status"] = json!(format!("verified_{part}"));
        }
        self.save()?;
        Ok(format!("continue {token}\n").into_bytes())
    }

    fn confirm_write(&mut self) -> Result<&'static [u8]> {
        ensure!(
            self.preflight_ok
                && self.confirmed == self.verified
                && self.confirmed < WRITE_ORDER.len(),
            "Unexpected write prompt; no confirmation sent"
        );
        let part = WRITE_ORDER[self.confirmed];
        let spec = self
            .images
            .get(part)
            .context("Missing image specification")?;
        verify_file(
            &self.out.join(format!("images/{part}.bin")),
            spec.size,
            &spec.sha256,
        )?;
        self.state["status"] = json!(format!("writing_{part}"));
        self.state["writes_started"] = json!(true);
        self.state["current_partition"] = json!(part);
        self.save()?;
        self.confirmed += 1;
        Ok(b"yes\n")
    }

    fn progress(&mut self, line: &[u8], elapsed: Duration) -> Result<()> {
        let line = std::str::from_utf8(line).context("Invalid progress encoding")?;
        ensure!(line.is_ascii(), "Invalid progress encoding");
        let fields: Vec<_> = line.split(' ').collect();
        ensure!(
            fields.len() == 5 && fields[0] == "PROGRESS" && matches!(fields[1], "read" | "write"),
            "Malformed backend progress"
        );
        let (operation, part) = (fields[1], fields[2]);
        ensure!(
            !part.is_empty()
                && part.len() <= 35
                && part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'),
            "Invalid progress partition"
        );
        let done: u64 = fields[3].parse().context("Invalid progress byte count")?;
        let total: u64 = fields[4].parse().context("Invalid progress size")?;
        ensure!(total > 0 && done <= total, "Invalid progress range");
        let stage = if self.preflight_ok {
            ensure!(
                self.verified < WRITE_ORDER.len() && self.confirmed == self.verified + 1,
                "Progress outside an approved write/readback"
            );
            let expected = WRITE_ORDER[self.verified];
            ensure!(
                part == expected
                    && self
                        .images
                        .get(part)
                        .is_some_and(|image| image.size == total),
                "Unexpected progress partition or length"
            );
            if operation == "read" {
                format!("reading_{part}")
            } else {
                format!("writing_{part}")
            }
        } else {
            ensure!(
                operation == "read" && self.confirmed == 0,
                "Write progress before preflight approval"
            );
            format!("reading_preflight_{part}")
        };
        if self.state["status"] != stage {
            self.state["status"] = json!(stage);
            self.state["current_partition"] = json!(part);
            self.save()?;
        }
        save_json(
            &self.out.join("progress.json"),
            &json!({"line": line,
            "elapsed_seconds": (elapsed.as_secs_f64() * 10.0).round() / 10.0,
            "stage": stage, "operation": operation, "partition": part,
            "bytes": done, "total_bytes": total}),
        )
    }

    fn completed(&mut self) -> Result<()> {
        ensure!(
            self.confirmed == WRITE_ORDER.len() && self.verified == WRITE_ORDER.len(),
            "Backend exited before all writes were verified"
        );
        self.state["status"] = json!("storage_verified_awaiting_recovery_boot");
        self.state["power_off_acknowledged"] = json!(true);
        self.save()
    }

    fn failed(&mut self, error: &anyhow::Error) -> Result<()> {
        self.state["status"] = json!("failed");
        self.state["error"] = json!(format!("{error:#}"));
        self.state["automatic_retry"] = json!(false);
        self.save()
    }
}

fn free_space(path: &Path) -> Result<u64> {
    let name = CString::new(path.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(name.as_ptr(), stat.as_mut_ptr()) } == 0,
        "Checking free disk space failed: {}",
        io::Error::last_os_error()
    );
    let stat = unsafe { stat.assume_init() };
    (stat.f_bavail as u64)
        .checked_mul(stat.f_frsize)
        .context("Free space overflow")
}

fn prepare_images(
    validated: &ValidatedPac<'_>,
    out: &Path,
    backend: PathBuf,
    wait: u32,
) -> Result<(BackendCommand, BTreeMap<String, ImageSpec>)> {
    let images = &validated.images;
    let image_bytes = images.values().try_fold(0u64, |sum, image| {
        sum.checked_add(image.size).context("Image sizes overflow")
    })?;
    let before = required_before_reads();
    let before_bytes = before.values().try_fold(0u64, |sum, size| {
        sum.checked_add(*size).context("Backup sizes overflow")
    })?;
    let needed = image_bytes
        .checked_mul(2)
        .and_then(|v| v.checked_add(before_bytes))
        .and_then(|v| v.checked_add(2 * 1024 * MIB))
        .context("Disk space requirement overflow")?;
    ensure!(
        free_space(out)? >= needed,
        "Insufficient free disk space for images and complete readback"
    );
    let mut command = BackendCommand::new(backend);
    command.words(&["--wait", &wait.to_string(), "timeout", "15000"]);
    for (index, (entry, address)) in loader_entries(validated.pac)?.into_iter().enumerate() {
        let path = out.join(format!("fdl{}.bin", index + 1));
        validated.pac.extract(entry, &path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        command.words(&["fdl"]);
        command.path(&path);
        command.words(&[&format!("{address:#x}")]);
    }
    let mut specs = BTreeMap::new();
    for (part, image) in images {
        let target = out.join(format!("images/{part}.bin"));
        validated.pac.extract(&image.entry, &target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        verify_file(&target, image.size, &image.sha256)?;
        println!("Prepared {part}: {} bytes", image.size);
        specs.insert(
            part.clone(),
            ImageSpec {
                size: image.size,
                sha256: image.sha256.clone(),
            },
        );
    }
    command.words(&["disable_transcode", "blk_size", "32768", "partition_list"]);
    command.path(&out.join("partitions.xml"));
    for (part, size) in before {
        command.words(&["read_part", &part, "0", &size.to_string()]);
        command.path(&out.join(format!("before/{part}.bin")));
    }
    let super_size = images.get("super").context("Full PAC missing super")?.size;
    let tail = super_size.checked_sub(MIB).context("Invalid super size")?;
    command.words(&["read_part", "super", &tail.to_string(), &MIB.to_string()]);
    command.path(&out.join("before/super-tail.bin"));
    command.words(&["checkpoint", "preflight"]);
    for part in WRITE_ORDER {
        let size = if part == "misc" {
            MIB
        } else {
            images.get(part).context("Missing install image")?.size
        };
        command.words(&["blk_size", "4096", "write_part", part]);
        command.path(&out.join(format!("images/{part}.bin")));
        command.words(&[
            "blk_size",
            "32768",
            "read_part",
            part,
            "0",
            &size.to_string(),
        ]);
        command.path(&out.join(format!("after/{part}.bin")));
        command.words(&["checkpoint", &format!("verified_{part}")]);
    }
    command.words(&["power_off"]);
    Ok((command, specs))
}

fn run_session(
    command: &BackendCommand,
    session: &mut InstallSession<'_>,
    total: Duration,
    idle: Duration,
) -> Result<Value> {
    // Reserve the log before launching anything. Existing evidence is untouched.
    let mut log = private_file(&session.out.join("install.log"))?;
    let signals = match SessionSignals::new() {
        Ok(signals) => signals,
        Err(error) => {
            session.failed(&error)?;
            return Err(error);
        }
    };
    let mut process = match BackendProcess::spawn(command, true) {
        Ok(process) => process,
        Err(error) => {
            session.failed(&error)?;
            return Err(error);
        }
    };
    let started = Instant::now();
    let mut last_io = started;
    let mut pending = Vec::new();
    let mut written = 0usize;
    let result = (|| {
        loop {
            let remaining = remaining_timeout(started, last_io, total, idle)?;
            match process.next_output(remaining, &signals)? {
                OutputEvent::Data(bytes) => {
                    last_io = Instant::now();
                    written += bytes.len();
                    ensure!(
                        written <= 8 * MIB as usize,
                        "Unexpectedly large backend log"
                    );
                    echo_log(&mut log, &bytes)?;
                    pending.extend_from_slice(&bytes);
                    while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
                        signals.check()?;
                        let line: Vec<_> = pending.drain(..=end).collect();
                        let line = &line[..line.len() - 1];
                        if let Some(token) = line.strip_prefix(b"CHECKPOINT ") {
                            let token = std::str::from_utf8(token)
                                .context("Invalid checkpoint encoding")?;
                            let answer = session.checkpoint(token)?;
                            // Verification can hash several GiB; it must not escape the total bound.
                            ensure!(
                                started.elapsed() < total,
                                "Installation timed out during verification"
                            );
                            process.answer(&answer, &signals)?;
                            last_io = Instant::now();
                        } else if line.starts_with(b"PROGRESS ") {
                            session.progress(line, started.elapsed())?;
                        }
                    }
                    if pending == WRITE_PROMPT {
                        signals.check()?;
                        let answer = session.confirm_write()?;
                        ensure!(
                            started.elapsed() < total,
                            "Installation timed out during source verification"
                        );
                        process.answer(answer, &signals)?;
                        pending.clear();
                        last_io = Instant::now();
                    } else {
                        ensure!(
                            pending.len() <= 65536,
                            "Oversized unterminated backend output"
                        );
                    }
                }
                OutputEvent::End => break,
                OutputEvent::Timeout => {}
            }
        }
        let status = process.finish(Duration::from_secs(5), &signals)?;
        signals.check()?;
        ensure!(
            status.success(),
            "USB backend exited {status}; inspect install.log before reconnecting"
        );
        ensure!(pending.is_empty(), "Incomplete backend output at exit");
        session.completed()
    })();
    if let Err(error) = result {
        process.terminate();
        session.failed(&error)?;
        return Err(error);
    }
    Ok(session.state.clone())
}

pub fn install(pac: &PacFile, out: &Path, backend: &Path, wait: u32) -> Result<Value> {
    validate_wait(wait)?;
    let backend = validate_backend(backend)?;
    let out = private_directory(out)?;
    for directory in ["before", "after", "images"] {
        private_directory(&out.join(directory))?;
    }
    println!("Checking pinned Full PAC and preparing local images...");
    let validated = validate_pac(pac)?;
    let (command, images) = prepare_images(&validated, &out, backend, wait)?;
    let mut session = InstallSession::new(&validated, out, images)?;
    println!(
        "Ready: waiting up to {wait} seconds for powered-off RG Rotate with Back held and USB connected."
    );
    run_session(
        &command,
        &mut session,
        Duration::from_secs(7200),
        Duration::from_secs(180),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;

    struct TestPreflight {
        fail: bool,
        wait_for_signal: bool,
    }
    impl PreflightValidation for TestPreflight {
        fn validate(&self, out: &Path) -> Result<Value> {
            ensure!(!self.fail, "wrong target identity");
            if self.wait_for_signal {
                fs::write(out.join("signal-ready"), b"preflight")?;
                let started = Instant::now();
                while !out.join("signal-release").exists() {
                    ensure!(
                        started.elapsed() < Duration::from_secs(5),
                        "test signal release missing"
                    );
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
            Ok(json!({"identity_verified": true}))
        }
    }

    fn good_misc() -> Vec<u8> {
        let mut data = vec![0; MIB as usize];
        data[32..45].copy_from_slice(b"legacy-status");
        data[1100..1106].copy_from_slice(b"vendor");
        data[2048..2080].copy_from_slice(
            &hex::decode("5f61000042434142010200009f008e000000000000000000000000008532b0a3")
                .unwrap(),
        );
        data[32768] = 2;
        data[32769..32773].copy_from_slice(&0x56740ab0u32.to_le_bytes());
        data
    }

    struct Fixture {
        directory: tempfile::TempDir,
        preflight: TestPreflight,
    }
    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            for name in ["before", "images", "after"] {
                fs::create_dir(directory.path().join(name)).unwrap();
            }
            fs::write(directory.path().join("before/misc.bin"), good_misc()).unwrap();
            for part in WRITE_ORDER.into_iter().filter(|part| *part != "misc") {
                let mut bytes = part.as_bytes().to_vec();
                bytes.resize(64, b'_');
                fs::write(directory.path().join(format!("images/{part}.bin")), bytes).unwrap();
            }
            Self {
                directory,
                preflight: TestPreflight {
                    fail: false,
                    wait_for_signal: false,
                },
            }
        }
        fn out(&self) -> &Path {
            self.directory.path()
        }
        fn session(&self) -> InstallSession<'_> {
            let mut images = BTreeMap::new();
            for part in WRITE_ORDER.into_iter().filter(|part| *part != "misc") {
                images.insert(
                    part.to_owned(),
                    ImageSpec {
                        size: 64,
                        sha256: sha256_file(&self.out().join(format!("images/{part}.bin")))
                            .unwrap(),
                    },
                );
            }
            InstallSession::new(&self.preflight, self.out().to_owned(), images).unwrap()
        }
        fn command(&self, mode: &str) -> BackendCommand {
            let mut command = BackendCommand::new(std::env::current_exe().unwrap());
            command.words(&[
                "--ignored",
                "--exact",
                "install::tests::fake_backend",
                "--nocapture",
                "--quiet",
            ]);
            command.env = vec![
                (
                    "RGROTATE_TEST_OUT".into(),
                    self.out().as_os_str().to_owned(),
                ),
                ("RGROTATE_TEST_MODE".into(), mode.into()),
            ];
            command
        }
        fn events(&self) -> Vec<Value> {
            let path = self.out().join("backend-events.jsonl");
            if !path.exists() {
                return vec![];
            }
            fs::read_to_string(path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
        fn answers(&self) -> Vec<String> {
            self.events()
                .iter()
                .filter(|event| event["kind"] == "answer")
                .map(|event| event["value"].as_str().unwrap().to_owned())
                .collect()
        }
        fn state(&self) -> Value {
            serde_json::from_slice(&fs::read(self.out().join("install-result.json")).unwrap())
                .unwrap()
        }
        fn run(&self, mode: &str, session: &mut InstallSession<'_>) -> Result<Value> {
            run_session(
                &self.command(mode),
                session,
                Duration::from_secs(5),
                Duration::from_secs(2),
            )
        }
        fn failed(&self, writes: bool) {
            let state = self.state();
            assert_eq!(state["status"], "failed");
            assert_eq!(state["writes_started"], writes);
            assert_eq!(state["automatic_retry"], false);
            assert_ne!(state["power_off_acknowledged"], true);
            assert_eq!(state["boot_verified"], false);
        }
    }

    fn event(file: &mut fs::File, kind: &str, value: &str) {
        // One short write keeps an interrupted fixture from leaving half a JSON event.
        let mut bytes = serde_json::to_vec(&json!({"kind": kind, "value": value})).unwrap();
        bytes.push(b'\n');
        file.write_all(&bytes).unwrap();
        file.flush().unwrap();
    }
    fn emit(mode: &str, bytes: &[u8]) {
        let mut stdout = io::stdout().lock();
        if mode == "split_success" {
            for chunk in bytes.chunks(3) {
                stdout.write_all(chunk).unwrap();
                stdout.flush().unwrap();
                std::thread::sleep(Duration::from_millis(1));
            }
        } else {
            stdout.write_all(bytes).unwrap();
            stdout.flush().unwrap();
        }
    }
    fn answer(events: &mut fs::File) -> String {
        let mut answer = String::new();
        io::stdin().lock().read_line(&mut answer).unwrap();
        event(events, "answer", &answer);
        assert!(!answer.is_empty(), "parent closed stdin");
        answer
    }
    fn fake_checkpoint(mode: &str, events: &mut fs::File, token: &str) {
        event(events, "checkpoint", token);
        emit(mode, format!("CHECKPOINT {token}\n").as_bytes());
        assert_eq!(answer(events), format!("continue {token}\n"));
    }
    fn fake_prompt(mode: &str, events: &mut fs::File) {
        event(events, "prompt", "write");
        emit(mode, WRITE_PROMPT);
        assert_eq!(answer(events), "yes\n");
        emit(mode, b"\n");
    }

    /// Re-exec this Rust test binary as a protocol peer; never invoke Python or USB.
    #[test]
    #[ignore = "subprocess-only protocol peer"]
    fn fake_backend() {
        let Some(out) = std::env::var_os("RGROTATE_TEST_OUT") else {
            return;
        };
        let out = PathBuf::from(out);
        let mode = std::env::var("RGROTATE_TEST_MODE").unwrap();
        let mut events = private_file(&out.join("backend-events.jsonl")).unwrap();
        fs::write(out.join("backend.pid"), std::process::id().to_string()).unwrap();
        if matches!(mode.as_str(), "idle_timeout" | "total_timeout") {
            emit(&mode, b"BACKEND_READY\n");
            loop {
                if mode == "total_timeout" {
                    emit(&mode, b"still reading\n");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        if mode == "close_output_then_hang" {
            unsafe {
                libc::close(1);
                libc::close(2);
            }
            loop {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        if mode == "premature_prompt" {
            fake_prompt(&mode, &mut events);
            std::process::exit(36);
        }
        if mode == "bad_checkpoint_encoding" {
            emit(&mode, b"CHECKPOINT \xff\n");
            let _ = answer(&mut events);
            std::process::exit(37);
        }
        fake_checkpoint(&mode, &mut events, "preflight");
        if mode == "premature_exit" {
            std::process::exit(0);
        }
        if mode == "source_mutation" {
            let path = out.join("images/super.bin");
            let mut bytes = fs::read(&path).unwrap();
            bytes[0] ^= 1;
            fs::write(path, bytes).unwrap();
        }
        for part in WRITE_ORDER {
            fake_prompt(&mode, &mut events);
            if mode == "signal_wait" && part == "super" {
                fs::write(out.join("signal-ready"), b"after_write").unwrap();
                let started = Instant::now();
                while !out.join("signal-release").exists() {
                    assert!(
                        started.elapsed() < Duration::from_secs(5),
                        "test signal release missing"
                    );
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
            if mode == "double_prompt" && part == "super" {
                fake_prompt(&mode, &mut events);
                std::process::exit(38);
            }
            let mut bytes = fs::read(out.join(format!("images/{part}.bin"))).unwrap();
            if part == "super" {
                if mode == "bad_readback" {
                    bytes[0] ^= 1;
                }
                if mode == "short_readback" {
                    bytes.pop();
                }
            }
            fs::write(out.join(format!("after/{part}.bin")), &bytes).unwrap();
            // The expected total is the image length even when simulating a short read.
            let expected = fs::metadata(out.join(format!("images/{part}.bin")))
                .unwrap()
                .len();
            emit(
                &mode,
                format!("PROGRESS read {part} {} {expected}\n", bytes.len()).as_bytes(),
            );
            if mode == "out_of_order_checkpoint" && part == "super" {
                fake_checkpoint(&mode, &mut events, "verified_vbmeta_vendor_a");
                std::process::exit(39);
            }
            fake_checkpoint(&mode, &mut events, &format!("verified_{part}"));
        }
        event(&mut events, "power_off", "ack");
        emit(&mode, b"POWER_OFF_ACK\n");
        std::process::exit(if mode == "nonzero_after_verification" {
            7
        } else {
            0
        });
    }

    fn complete_flow(mode: &str) {
        let fixture = Fixture::new();
        let mut session = fixture.session();
        let state = fixture.run(mode, &mut session).unwrap();
        let mut expected = vec!["continue preflight\n".to_owned()];
        for part in WRITE_ORDER {
            expected.push("yes\n".to_owned());
            expected.push(format!("continue verified_{part}\n"));
        }
        assert_eq!(fixture.answers(), expected);
        assert_eq!(state, fixture.state());
        assert_eq!(state["status"], "storage_verified_awaiting_recovery_boot");
        assert_eq!(state["verified_partitions"].as_object().unwrap().len(), 6);
        assert_eq!((session.confirmed, session.verified), (6, 6));
        assert_eq!(state["power_off_acknowledged"], true);
        assert_eq!(state["factory_reset_requested"], true);
        assert_eq!(state["restore_user_data"], false);
        assert_eq!(state["boot_verified"], false);
        assert_eq!(
            fixture.events().last().unwrap(),
            &json!({"kind": "power_off", "value": "ack"})
        );
        let progress: Value =
            serde_json::from_slice(&fs::read(fixture.out().join("progress.json")).unwrap())
                .unwrap();
        assert_eq!(progress["stage"], "reading_misc");
        assert_eq!(progress["operation"], "read");
        assert_eq!(progress["bytes"], MIB);
        for filename in ["backend.pid", "after/super.bin", "after/misc.bin"] {
            // fs::write opens with 0666, like the C backend's fopen; child umask must restrict it.
            assert_eq!(
                fs::metadata(fixture.out().join(filename))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn complete_six_write_flow() {
        complete_flow("success");
    }
    #[test]
    fn split_prompts_and_checkpoints() {
        complete_flow("split_success");
    }

    #[test]
    fn failed_preflight_sends_no_continue_or_yes() {
        let mut fixture = Fixture::new();
        fixture.preflight.fail = true;
        let mut session = fixture.session();
        assert!(
            fixture
                .run("success", &mut session)
                .unwrap_err()
                .to_string()
                .contains("wrong target identity")
        );
        assert!(fixture.answers().is_empty());
        fixture.failed(false);
    }

    #[test]
    fn failed_hash_and_short_read_stop_before_next_yes() {
        for (mode, message) in [
            ("bad_readback", "SHA-256 mismatch"),
            ("short_readback", "Incomplete file"),
        ] {
            let fixture = Fixture::new();
            let mut session = fixture.session();
            assert!(
                fixture
                    .run(mode, &mut session)
                    .unwrap_err()
                    .to_string()
                    .contains(message)
            );
            assert_eq!(fixture.answers(), ["continue preflight\n", "yes\n"]);
            assert_eq!((session.confirmed, session.verified), (1, 0));
            fixture.failed(true);
        }
    }

    #[test]
    fn source_hash_rechecked_before_yes() {
        let fixture = Fixture::new();
        let mut session = fixture.session();
        assert!(
            fixture
                .run("source_mutation", &mut session)
                .unwrap_err()
                .to_string()
                .contains("SHA-256 mismatch")
        );
        assert_eq!(fixture.answers(), ["continue preflight\n"]);
        fixture.failed(false);
    }

    #[test]
    fn premature_prompt_is_refused() {
        let fixture = Fixture::new();
        let mut session = fixture.session();
        assert!(
            fixture
                .run("premature_prompt", &mut session)
                .unwrap_err()
                .to_string()
                .contains("Unexpected write prompt")
        );
        assert!(fixture.answers().is_empty());
        fixture.failed(false);
    }

    #[test]
    fn out_of_order_prompt_or_checkpoint_is_refused() {
        for mode in ["double_prompt", "out_of_order_checkpoint"] {
            let fixture = Fixture::new();
            let mut session = fixture.session();
            assert!(fixture.run(mode, &mut session).is_err());
            assert_eq!(fixture.answers(), ["continue preflight\n", "yes\n"]);
            fixture.failed(true);
        }
    }

    #[test]
    fn nonzero_exit_and_early_zero_exit_are_failures() {
        for mode in ["nonzero_after_verification", "premature_exit"] {
            let fixture = Fixture::new();
            let mut session = fixture.session();
            assert!(fixture.run(mode, &mut session).is_err());
            fixture.failed(mode == "nonzero_after_verification");
        }
    }

    #[test]
    fn timeouts_kill_and_reap_owned_backend() {
        for mode in ["idle_timeout", "total_timeout"] {
            let fixture = Fixture::new();
            let mut session = fixture.session();
            let (total, idle) = if mode == "idle_timeout" {
                (Duration::from_secs(2), Duration::from_millis(100))
            } else {
                (Duration::from_millis(150), Duration::from_secs(2))
            };
            let error = run_session(&fixture.command(mode), &mut session, total, idle).unwrap_err();
            assert!(error.to_string().contains("timed out"));
            let pid: libc::pid_t = fs::read_to_string(fixture.out().join("backend.pid"))
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
            let mut status = 0;
            assert_eq!(
                unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
                -1
            );
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
            fixture.failed(false);
        }
    }

    #[test]
    fn existing_log_does_not_launch_backend() {
        let fixture = Fixture::new();
        let mut session = fixture.session();
        fs::write(fixture.out().join("install.log"), b"keep evidence").unwrap();
        assert!(fixture.run("success", &mut session).is_err());
        assert!(!fixture.out().join("backend.pid").exists());
        assert_eq!(
            fs::read(fixture.out().join("install.log")).unwrap(),
            b"keep evidence"
        );
    }

    #[test]
    fn existing_misc_and_state_are_preserved() {
        let fixture = Fixture::new();
        let mut session = fixture.session();
        fs::write(fixture.out().join("images/misc.bin"), b"keep evidence").unwrap();
        assert!(fixture.run("success", &mut session).is_err());
        assert!(fixture.answers().is_empty());
        assert_eq!(
            fs::read(fixture.out().join("images/misc.bin")).unwrap(),
            b"keep evidence"
        );
        let previous = fs::read(fixture.out().join("install-result.json")).unwrap();
        assert!(
            InstallSession::new(
                &fixture.preflight,
                fixture.out().to_owned(),
                BTreeMap::new()
            )
            .is_err()
        );
        assert_eq!(
            fs::read(fixture.out().join("install-result.json")).unwrap(),
            previous
        );
    }

    #[test]
    fn invalid_checkpoint_encoding_is_refused() {
        let fixture = Fixture::new();
        let mut session = fixture.session();
        assert!(
            fixture
                .run("bad_checkpoint_encoding", &mut session)
                .is_err()
        );
        assert!(fixture.answers().is_empty());
        fixture.failed(false);
    }

    #[test]
    fn checkpoint_does_not_replace_write_confirmation() {
        let fixture = Fixture::new();
        let mut session = fixture.session();
        assert_eq!(
            session.checkpoint("preflight").unwrap(),
            b"continue preflight\n"
        );
        assert_eq!(session.confirmed, 0);
        assert!(session.checkpoint("verified_super").is_err());
        assert!(session.checkpoint("preflight").is_err());
        assert!(session.checkpoint("wrong token").is_err());
    }

    #[test]
    fn progress_changes_writing_to_reading_without_advancing_approval() {
        let fixture = Fixture::new();
        let mut session = fixture.session();
        session.checkpoint("preflight").unwrap();
        session.confirm_write().unwrap();
        session
            .progress(b"PROGRESS write super 32 64", Duration::from_secs(1))
            .unwrap();
        assert_eq!(session.state["status"], "writing_super");
        session
            .progress(b"PROGRESS read super 32 64", Duration::from_secs(2))
            .unwrap();
        assert_eq!(session.state["status"], "reading_super");
        assert_eq!((session.confirmed, session.verified), (1, 0));
        assert!(session.confirm_write().is_err());
        assert!(
            session
                .progress(b"PROGRESS read other 32 64", Duration::from_secs(2))
                .is_err()
        );
    }

    /// A separately exec'd runner receives signals, never the parent cargo test process.
    #[test]
    #[ignore = "subprocess-only signal runner"]
    fn signal_runner() {
        let Some(out) = std::env::var_os("RGROTATE_SIGNAL_OUT") else {
            return;
        };
        let out = PathBuf::from(out);
        let phase = std::env::var("RGROTATE_SIGNAL_PHASE").unwrap();
        let preflight = TestPreflight {
            fail: false,
            wait_for_signal: phase == "preflight",
        };
        let mut images = BTreeMap::new();
        for part in WRITE_ORDER.into_iter().filter(|part| *part != "misc") {
            images.insert(
                part.to_owned(),
                ImageSpec {
                    size: 64,
                    sha256: sha256_file(&out.join(format!("images/{part}.bin"))).unwrap(),
                },
            );
        }
        let mut session = InstallSession::new(&preflight, out.clone(), images).unwrap();
        let mut command = BackendCommand::new(std::env::current_exe().unwrap());
        command.words(&[
            "--ignored",
            "--exact",
            "install::tests::fake_backend",
            "--nocapture",
            "--quiet",
        ]);
        command.env = vec![
            ("RGROTATE_TEST_OUT".into(), out.as_os_str().to_owned()),
            (
                "RGROTATE_TEST_MODE".into(),
                if phase == "preflight" {
                    "success"
                } else {
                    "signal_wait"
                }
                .into(),
            ),
        ];
        let result = run_session(
            &command,
            &mut session,
            Duration::from_secs(8),
            Duration::from_secs(6),
        );
        let error = result.expect_err("signal must stop the runner");
        assert!(
            error.to_string().contains("interrupted by SIG"),
            "{error:#}"
        );
        let pid: libc::pid_t = fs::read_to_string(out.join("backend.pid"))
            .unwrap()
            .parse()
            .unwrap();
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    struct SignalTestChild {
        child: std::process::Child,
        backend_pid: Option<libc::pid_t>,
    }
    impl Drop for SignalTestChild {
        fn drop(&mut self) {
            // Both IDs come only from the subprocesses created by this test fixture.
            if let Some(pid) = self.backend_pid.take() {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[test]
    fn isolated_sigint_sigterm_kill_backend_and_record_failure_without_extra_approval() {
        for signal in [libc::SIGINT, libc::SIGTERM] {
            for phase in ["preflight", "after_write"] {
                let fixture = Fixture::new();
                let child = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--ignored",
                        "--exact",
                        "install::tests::signal_runner",
                        "--nocapture",
                        "--quiet",
                    ])
                    .env("RGROTATE_SIGNAL_OUT", fixture.out())
                    .env("RGROTATE_SIGNAL_PHASE", phase)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap();
                let mut runner = SignalTestChild {
                    child,
                    backend_pid: None,
                };
                let started = Instant::now();
                while !fixture.out().join("signal-ready").exists() {
                    assert!(
                        runner.child.try_wait().unwrap().is_none(),
                        "signal runner exited before ready"
                    );
                    assert!(
                        started.elapsed() < Duration::from_secs(5),
                        "signal runner did not become ready"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                let pid: libc::pid_t = fs::read_to_string(fixture.out().join("backend.pid"))
                    .unwrap()
                    .parse()
                    .unwrap();
                assert!(pid > 0 && pid != std::process::id() as libc::pid_t);
                runner.backend_pid = Some(pid);
                assert_eq!(
                    unsafe { libc::kill(runner.child.id() as libc::pid_t, signal) },
                    0
                );
                fs::write(
                    fixture.out().join("signal-release"),
                    b"continue test validation",
                )
                .unwrap();
                let deadline = Instant::now();
                let status = loop {
                    if let Some(status) = runner.child.try_wait().unwrap() {
                        break status;
                    }
                    assert!(
                        deadline.elapsed() < Duration::from_secs(3),
                        "interrupted runner did not exit"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                };
                assert!(status.success(), "isolated runner failed: {status}");
                assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
                runner.backend_pid = None;
                fixture.failed(phase == "after_write");
                let expected = if phase == "preflight" {
                    vec![]
                } else {
                    vec!["continue preflight\n".to_owned(), "yes\n".to_owned()]
                };
                assert_eq!(fixture.answers(), expected);
                assert!(fixture.state()["error"].as_str().unwrap().contains(
                    if signal == libc::SIGINT {
                        "SIGINT"
                    } else {
                        "SIGTERM"
                    }
                ));
            }
        }
    }
}
