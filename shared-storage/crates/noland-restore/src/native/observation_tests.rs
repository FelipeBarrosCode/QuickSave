// SPDX-License-Identifier: GPL-3.0-only
//! Wire compatibility tests use synthetic observations, never host accounts.
use super::*;

fn legacy_json() -> &'static str {
    r#"{"id":{"device":7,"file_id":[19,0]},"kind":"file","size":11,"mode":33184,"mtime_ns":1200,"ctime_ns":1300,"links":1,"uid":501,"gid":20,"symlink_target":null,"target_is_directory":null}"#
}

#[test]
fn v1_unix_observation_preserves_exact_device_mac_bytes() {
    let observation: NativeEntryObservation = serde_json::from_str(legacy_json()).unwrap();
    assert_eq!(observation.mode, Some(33184));
    assert_eq!(observation.uid, Some(501));
    assert_eq!(observation.gid, Some(20));
    assert!(observation.windows.is_none());
    let encoded = serde_json::to_vec(&observation).unwrap();
    assert_eq!(encoded, legacy_json().as_bytes());
    let synthetic_device_key = [37; 32];
    assert_eq!(
        blake3::keyed_hash(&synthetic_device_key, &encoded),
        blake3::keyed_hash(&synthetic_device_key, legacy_json().as_bytes())
    );
    #[cfg(unix)]
    observation.validate_platform().unwrap();
    #[cfg(windows)]
    assert!(observation.validate_platform().is_err());
}

#[test]
fn nullable_observation_does_not_invent_unix_authority() {
    let mut value: serde_json::Value = serde_json::from_str(legacy_json()).unwrap();
    for key in ["mode", "uid", "gid"] {
        value[key] = serde_json::Value::Null;
    }
    let observation: NativeEntryObservation = serde_json::from_value(value.clone()).unwrap();
    assert!(observation.validate_platform().is_err());
    for key in ["mode", "uid", "gid"] {
        value.as_object_mut().unwrap().remove(key);
    }
    let observation: NativeEntryObservation = serde_json::from_value(value).unwrap();
    assert!(observation.validate_platform().is_err());
}

#[test]
fn windows_observation_binds_full_identity_and_native_owner_frame() {
    let mut observation: NativeEntryObservation = serde_json::from_str(legacy_json()).unwrap();
    observation.mode = None;
    observation.uid = None;
    observation.gid = None;
    observation.id.file_id = [19, 0xfedc_ba98_7654_3210];
    observation.windows = Some(NativeWindowsObservation {
        version: 1,
        attributes: 0x20,
        creation_time: 116_444_736_000_000_000,
        reparse_tag: 0,
        reparse_data: None,
        security: NativeWindowsSecurity {
            current_user_sid: [7; 32],
            owner_sid: [7; 32],
            dacl: [9; 32],
        },
    });
    let encoded = serde_json::to_vec(&observation).unwrap();
    assert_eq!(
        serde_json::from_slice::<NativeEntryObservation>(&encoded).unwrap(),
        observation
    );
    #[cfg(unix)]
    assert!(observation.validate_platform().is_err());
    #[cfg(windows)]
    {
        observation.validate_platform().unwrap();
        observation.windows.as_mut().unwrap().security.owner_sid = [8; 32];
        assert!(observation.validate_platform().is_err());
        observation.windows.as_mut().unwrap().security.owner_sid = [7; 32];
        observation.uid = Some(0);
        assert!(observation.validate_platform().is_err());
    }
    let mut changed = observation.clone();
    changed.id.file_id[1] ^= 1;
    assert_ne!(
        bounded_digest(&observation).unwrap(),
        bounded_digest(&changed).unwrap()
    );
}
