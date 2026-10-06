//! Optional integration against user-supplied firmware and saved preflight reads.
//! These tests never open USB or modify the supplied inputs.
use rgrotate::pac::PacFile;
use rgrotate::target::{patch_misc, validate_pac, validate_preflight};
use std::path::PathBuf;

#[test]
fn pinned_full_pac_and_saved_device_preflight() {
    let Ok(path) = std::env::var("RGROTATE_TEST_PAC") else {
        eprintln!("Set RGROTATE_TEST_PAC to enable pinned Full validation");
        return;
    };
    let pac = PacFile::new(path).unwrap();
    let validated = validate_pac(&pac).unwrap();
    assert_eq!(validated.images.len(), 5);
    assert_eq!(validated.images["super"].size, 5_872_025_600);
    if let Ok(path) = std::env::var("RGROTATE_TEST_PREFLIGHT") {
        let out = PathBuf::from(path);
        let checked = validate_preflight(&validated, &out).unwrap();
        assert_eq!(checked["misc"]["active_slot"], "a");
        assert_eq!(checked["misc"]["snapshot_status"], "none");
        let before = std::fs::read(out.join("before/misc.bin")).unwrap();
        let expected = std::fs::read(out.join("images/misc.bin")).unwrap();
        assert_eq!(patch_misc(&before).unwrap(), expected);
    }
}
