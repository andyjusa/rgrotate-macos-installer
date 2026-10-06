use anyhow::{Result, bail};
use clap::{ArgGroup, Parser};
use rgrotate::{install, pac::PacFile, plan, transport};
use serde_json::Value;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(
    name = "rgrotate",
    version,
    about = "Inspect an RG Rotate PAC, probe official RAM loaders, or explicitly install pinned Full firmware."
)]
#[command(group(ArgGroup::new("action").args(["plan", "probe", "flash", "dump_xml", "dump_firmware"])))]
#[command(group(ArgGroup::new("mode").args(["full_flash", "preserve_layout"])))]
struct Args {
    /// Official RG Rotate PAC file
    pac: PathBuf,
    /// Inspect offline (the default); no USB access
    #[arg(long)]
    plan: bool,
    /// Load official FDLs into RAM and perform read-only checks
    #[arg(long)]
    probe: bool,
    /// Explicitly request firmware writes
    #[arg(long)]
    flash: bool,
    /// Print the validated PAC XML without opening USB
    #[arg(long)]
    dump_xml: bool,
    /// Reserved firmware-dump action; currently refused
    #[arg(long)]
    dump_firmware: bool,
    /// Request generic full-PAC replay; currently refused
    #[arg(long)]
    full_flash: bool,
    /// Keep the existing partition layout and compatible boot chain
    #[arg(long)]
    preserve_layout: bool,
    /// Authorize Recovery factory reset after verified Full installation
    #[arg(long)]
    wipe_data: bool,
    /// Audited native spd_dump executable
    #[arg(long)]
    backend: Option<PathBuf>,
    /// New private directory for results and complete readbacks
    #[arg(long)]
    out: Option<PathBuf>,
    /// USB discovery timeout in seconds
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u32).range(1..=120))]
    wait: u32,
    /// Also save the JSON result to a new file; existing files are refused
    #[arg(long)]
    output_json: Option<PathBuf>,
}

fn normalize(mut argv: Vec<OsString>) -> (Vec<OsString>, bool) {
    let action = argv.get(1).and_then(|s| s.to_str()).map(str::to_owned);
    match action.as_deref() {
        Some("flash") => {
            argv.remove(1);
            (argv, true)
        }
        Some(command @ ("plan" | "probe" | "dump-xml" | "dump-firmware")) => {
            argv[1] = format!("--{command}").into();
            (argv, false)
        }
        _ => (argv, false),
    }
}

fn validate_args(args: &Args, flash_command: bool) -> Result<()> {
    if flash_command && !args.flash {
        bail!("flash requires a separate --flash marker and an explicit mode");
    }
    if args.flash && !(args.full_flash || args.preserve_layout) {
        bail!("--flash requires --full-flash or --preserve-layout");
    }
    if (args.full_flash || args.preserve_layout) && !args.flash {
        bail!("flash mode options require --flash");
    }
    if args.wipe_data && !(args.flash && args.preserve_layout) {
        bail!("--wipe-data requires --flash --preserve-layout");
    }
    if args.flash && args.preserve_layout && !args.wipe_data {
        bail!("Full installation requires --wipe-data; keeping old user data is unsupported");
    }
    let device_action = args.probe || (args.flash && args.preserve_layout);
    if device_action && (args.backend.is_none() || args.out.is_none()) {
        bail!("device actions require --backend and --out");
    }
    if !device_action && (args.backend.is_some() || args.out.is_some()) {
        bail!("--backend and --out require --probe or --flash --preserve-layout");
    }
    if let Some(path) = &args.output_json {
        match path.symlink_metadata() {
            Ok(_) => bail!("--output-json must name a new file"),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        if args.dump_xml {
            bail!("--output-json cannot be combined with --dump-xml");
        }
    }
    Ok(())
}

fn save_report(file: &mut File, value: &Value) -> Result<()> {
    let text = format!("{}\n", serde_json::to_string_pretty(value)?);
    file.rewind()?;
    file.set_len(0)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn reserve_report(path: Option<&Path>) -> Result<Option<File>> {
    path.map(|path| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        save_report(&mut file, &serde_json::json!({"status": "pending"}))?;
        Ok(file)
    })
    .transpose()
}

fn report(value: &Value, file: Option<&mut File>) -> Result<()> {
    let text = format!("{}\n", serde_json::to_string_pretty(value)?);
    if let Some(file) = file {
        save_report(file, value)?;
    }
    io::stdout().lock().write_all(text.as_bytes())?;
    Ok(())
}

fn execute(args: Args, flash_command: bool) -> Result<()> {
    // Reject incomplete write authorization before reading a PAC or opening USB.
    validate_args(&args, flash_command)?;
    // Reserve and test report output before any device work. This also rejects
    // a result path inside the not-yet-created --out directory.
    let mut output = reserve_report(args.output_json.as_deref())?;
    match execute_action(&args) {
        Ok(Some(result)) => report(&result, output.as_mut()),
        Ok(None) => Ok(()),
        Err(error) => {
            if let Some(file) = output.as_mut() {
                let _ = save_report(
                    file,
                    &serde_json::json!({"status": "failed", "error": format!("{error:#}")}),
                );
            }
            Err(error)
        }
    }
}

fn execute_action(args: &Args) -> Result<Option<Value>> {
    let pac = PacFile::new(&args.pac)?;
    let plan = plan::build_plan(&pac)?;
    if args.dump_xml {
        let xml = pac.xml_text()?;
        print!("{xml}");
        if !xml.ends_with('\n') {
            println!();
        }
        return Ok(None);
    }
    if args.flash {
        if args.full_flash {
            plan::require_flash_ready(&plan)?;
            bail!("generic full-PAC execution is not implemented");
        }
        let result = install::install(
            &pac,
            args.out.as_deref().unwrap(),
            args.backend.as_deref().unwrap(),
            args.wait,
        )?;
        return Ok(Some(result));
    }
    if args.dump_firmware {
        bail!("firmware dump is not implemented; no USB or storage write was attempted");
    }
    let result = if args.probe {
        transport::probe(
            &pac,
            args.out.as_deref().unwrap(),
            args.backend.as_deref().unwrap(),
            args.wait,
        )?
    } else {
        plan
    };
    Ok(Some(result))
}

fn main() {
    let (argv, flash_command) = normalize(std::env::args_os().collect());
    let args = Args::parse_from(argv);
    if let Err(error) = execute(args, flash_command) {
        eprintln!("error: {error:#}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checked(values: &[&str]) -> Result<Args> {
        let (argv, flash_command) = normalize(values.iter().map(OsString::from).collect());
        let args = Args::try_parse_from(argv)?;
        validate_args(&args, flash_command)?;
        Ok(args)
    }

    #[test]
    fn incomplete_write_requests_fail_before_pac_access() {
        let cases: &[&[&str]] = &[
            &["rgrotate", "flash", "missing.pac"],
            &["rgrotate", "missing.pac", "--flash"],
            &["rgrotate", "missing.pac", "--full-flash"],
            &[
                "rgrotate",
                "flash",
                "missing.pac",
                "--flash",
                "--preserve-layout",
            ],
            &[
                "rgrotate",
                "flash",
                "missing.pac",
                "--flash",
                "--preserve-layout",
                "--wipe-data",
            ],
            &["rgrotate", "plan", "missing.pac", "--wipe-data"],
            &["rgrotate", "probe", "missing.pac", "--wipe-data"],
        ];
        for case in cases {
            assert!(checked(case).is_err(), "{case:?}");
        }
    }

    #[test]
    fn correct_install_request_requires_all_explicit_markers() {
        let args = checked(&[
            "rgrotate",
            "flash",
            "missing.pac",
            "--flash",
            "--preserve-layout",
            "--wipe-data",
            "--backend",
            "/fake/backend",
            "--out",
            "/fake/new-output",
            "--wait",
            "120",
        ])
        .unwrap();
        assert!(args.flash && args.preserve_layout && args.wipe_data);
        assert_eq!(args.wait, 120);
    }

    #[test]
    fn plan_default_and_action_group() {
        let args = checked(&["rgrotate", "missing.pac"]).unwrap();
        assert!(!args.flash && !args.probe);
        assert!(checked(&["rgrotate", "plan", "missing.pac", "--probe"]).is_err());
        assert!(checked(&["rgrotate", "missing.pac", "--wait", "121"]).is_err());
        assert!(checked(&["rgrotate", "missing.pac", "--wait", "0"]).is_err());
    }

    #[test]
    fn output_json_cannot_overwrite_regular_or_dangling_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("result.json");
        std::fs::write(&path, "preserve").unwrap();
        for _ in 0..2 {
            assert!(
                checked(&[
                    "rgrotate",
                    "missing.pac",
                    "--output-json",
                    path.to_str().unwrap()
                ])
                .is_err()
            );
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(tmp.path().join("missing"), &path).unwrap();
        }
    }

    #[test]
    fn report_destination_is_checked_before_device_action() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("new-run");
        let report = out.join("install-result.json");
        assert!(reserve_report(Some(&report)).is_err());
        assert!(!out.exists());
        let report = tmp.path().join("summary.json");
        let mut file = reserve_report(Some(&report)).unwrap().unwrap();
        assert!(reserve_report(Some(&report)).is_err());
        save_report(&mut file, &serde_json::json!({"status": "done"})).unwrap();
        let value: Value = serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
        assert_eq!(value["status"], "done");
    }
}
