//! Release notices: what each release changes, and which agents should move
//! to it by when.
//!
//! The deployer writes one JSON file per environment (`ATTESTOR_RELEASES_FILE`)
//! and adds an entry at every release. An entry names the images it replaces
//! and the end of their transition period (`until`): until then agents on an
//! old image keep running, and owners are told to reset them onto the new one;
//! after it the deployer may delist the old image, and an agent still on it
//! gets no key until it is reset. `urgent` marks an image that may be delisted
//! before `until` (a security fix).
//!
//! The file is read again when it changes on disk (its modification time,
//! size or inode), so a new entry needs no restart; mount its directory, not
//! the file, and replace the file atomically (write a temporary file, then
//! rename it), so the container sees each edit whole. A file that does not
//! parse, or is gone, is logged and the last good content is kept.

use alloy::primitives::B256;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// How long before `until` an owner is told every day instead of every week,
/// and gets the email reminder.
pub const REMINDER_DAYS: i64 = 7;

const MAX_VERSION: usize = 64;
const MAX_NOTES: usize = 4000;
const MAX_FRAMEWORK: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    /// The release's version, e.g. "0.5.0". Unique in the file.
    pub version: String,
    pub published_at: DateTime<Utc>,
    /// What changed and what owners should do, in English.
    pub notes: String,
    /// The same in Chinese.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes_zh: Option<String>,
    /// The images this release replaces.
    #[serde(default)]
    pub migrate: Vec<Migration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Migration {
    /// The framework whose image this is (informational).
    pub framework: String,
    /// The old image's hash, as on the trust registry's image list.
    pub image_hash: B256,
    /// End of the transition period: the deployer delists the image no
    /// earlier than this, unless `urgent`.
    pub until: DateTime<Utc>,
    /// The image may be delisted before `until` (a security fix).
    #[serde(default)]
    pub urgent: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseFile {
    releases: Vec<Release>,
}

/// Parse and check a release file; releases come back newest first.
pub fn parse(json: &str) -> anyhow::Result<Vec<Release>> {
    let file: ReleaseFile = serde_json::from_str(json)?;
    let mut releases = file.releases;
    let mut versions = std::collections::HashSet::new();
    for r in &releases {
        anyhow::ensure!(
            !r.version.is_empty()
                && r.version.len() <= MAX_VERSION
                && r.version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)),
            "release version must be 1-{MAX_VERSION} of A-Z a-z 0-9 . _ + -"
        );
        anyhow::ensure!(
            versions.insert(r.version.clone()),
            "release {} appears twice",
            r.version
        );
        anyhow::ensure!(
            !r.notes.trim().is_empty() && r.notes.len() <= MAX_NOTES,
            "release {}: notes must be 1-{MAX_NOTES} bytes",
            r.version
        );
        if let Some(zh) = &r.notes_zh {
            anyhow::ensure!(
                zh.len() <= MAX_NOTES,
                "release {}: notes_zh is over {MAX_NOTES} bytes",
                r.version
            );
        }
        let mut images = std::collections::HashSet::new();
        for m in &r.migrate {
            anyhow::ensure!(
                !m.framework.trim().is_empty() && m.framework.len() <= MAX_FRAMEWORK,
                "release {}: framework must be 1-{MAX_FRAMEWORK} characters",
                r.version
            );
            anyhow::ensure!(
                m.image_hash != B256::ZERO,
                "release {}: image_hash is zero",
                r.version
            );
            anyhow::ensure!(
                images.insert(m.image_hash),
                "release {}: image {:#x} appears twice",
                r.version,
                m.image_hash
            );
            anyhow::ensure!(
                m.until > r.published_at,
                "release {}: until must be after published_at",
                r.version
            );
        }
    }
    releases.sort_by(|a, b| b.published_at.cmp(&a.published_at));
    Ok(releases)
}

/// Where an agent stands in its image's transition period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationState {
    /// More than [`REMINDER_DAYS`] left.
    Recommended,
    /// [`REMINDER_DAYS`] or less left.
    Soon,
    /// The transition period is over; the image may be delisted any time.
    Overdue,
}

/// What an owner is told about one agent: the release that replaces its
/// image, and by when it should move.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrationNotice {
    pub version: String,
    pub framework: String,
    pub until: DateTime<Utc>,
    pub urgent: bool,
    pub state: MigrationState,
}

pub fn state_at(until: DateTime<Utc>, now: DateTime<Utc>) -> MigrationState {
    if now >= until {
        MigrationState::Overdue
    } else if until - now <= Duration::days(REMINDER_DAYS) {
        MigrationState::Soon
    } else {
        MigrationState::Recommended
    }
}

/// The notice for an agent running `image_hash`, from the published releases
/// that list it: an urgent entry first, then the earliest `until`. The
/// version, date and urgency all come from that one entry, so an email names
/// the release whose notes explain them. None when no published release
/// replaces the image.
pub fn migration_for(
    releases: &[Release],
    image_hash: B256,
    now: DateTime<Utc>,
) -> Option<MigrationNotice> {
    let mut best: Option<(&Release, &Migration)> = None;
    for r in releases.iter().filter(|r| r.published_at <= now) {
        for m in r.migrate.iter().filter(|m| m.image_hash == image_hash) {
            let better = match best {
                None => true,
                Some((_, b)) => {
                    (m.urgent, std::cmp::Reverse(m.until)) > (b.urgent, std::cmp::Reverse(b.until))
                }
            };
            if better {
                best = Some((r, m));
            }
        }
    }
    best.map(|(r, m)| MigrationNotice {
        version: r.version.clone(),
        framework: m.framework.clone(),
        until: m.until,
        urgent: m.urgent,
        state: state_at(m.until, now),
    })
}

/// What identifies one version of the file on disk: modification time, size
/// and (on Unix) inode, so an atomic replace or a write that finishes within
/// the same timestamp tick is still seen.
type Stamp = Option<(SystemTime, u64, u64)>;
type Cached = (Stamp, Arc<Vec<Release>>);

fn stamp_of(path: &std::path::Path) -> Stamp {
    let m = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    let ino = std::os::unix::fs::MetadataExt::ino(&m);
    #[cfg(not(unix))]
    let ino = 0;
    Some((m.modified().ok()?, m.len(), ino))
}

fn cache() -> &'static Mutex<HashMap<PathBuf, Cached>> {
    static CACHE: std::sync::OnceLock<Mutex<HashMap<PathBuf, Cached>>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The releases in the file at `path`, newest first; empty for an empty
/// path. Read again when the file changes on disk ([`Stamp`]). A missing or
/// malformed file is logged (once per change) and the last good content kept.
pub fn load(path: &str) -> Arc<Vec<Release>> {
    if path.trim().is_empty() {
        return Arc::new(Vec::new());
    }
    let path = PathBuf::from(path);
    let stamp = stamp_of(&path);
    let mut cache = cache().lock().unwrap_or_else(|e| e.into_inner());
    if let Some((seen, releases)) = cache.get(&path) {
        if *seen == stamp {
            return releases.clone();
        }
    }
    let last_good = cache.get(&path).map(|(_, r)| r.clone()).unwrap_or_default();
    let fresh = match std::fs::read_to_string(&path) {
        Ok(text) => match parse(&text) {
            Ok(r) => Arc::new(r),
            Err(e) => {
                tracing::error!(path = %path.display(), error = %e, "release file not valid; keeping its last good content");
                last_good
            }
        },
        Err(e) => {
            tracing::error!(path = %path.display(), error = %e, "release file not readable; keeping its last good content");
            last_good
        }
    };
    // Read the stamp again: a write that was still going on when the stamp
    // above was taken is then read on the next call.
    cache.insert(
        path.clone(),
        (stamp.filter(|s| Some(*s) == stamp_of(&path)), fresh.clone()),
    );
    fresh
}

fn day(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M UTC").to_string()
}

/// The email to one owner about the agents a release asks to move.
/// `agents` is `(agent, notice)`; `reminder` is the one sent in the last
/// [`REMINDER_DAYS`] days.
pub fn owner_email(
    release: &Release,
    agents: &[(String, MigrationNotice)],
    reminder: bool,
) -> (String, String) {
    let until = agents
        .iter()
        .map(|(_, n)| n.until)
        .min()
        .unwrap_or(release.published_at);
    let urgent = agents.iter().any(|(_, n)| n.urgent);
    let names = agents
        .iter()
        .map(|(a, _)| a.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let subject = if reminder {
        format!(
            "Reminder: move agent(s) {names} to AgentDNA {} by {}",
            release.version,
            day(until)
        )
    } else {
        format!(
            "AgentDNA {}: please move agent(s) {names} by {}",
            release.version,
            day(until)
        )
    };
    let mut text = format!(
        "AgentDNA {} is out.\n\n{}\n\n",
        release.version,
        release.notes.trim()
    );
    if let Some(zh) = release.notes_zh.as_deref().filter(|z| !z.trim().is_empty()) {
        text.push_str(zh.trim());
        text.push_str("\n\n");
    }
    text.push_str("These agents of yours still run the previous version:\n\n");
    for (agent, n) in agents {
        text.push_str(&format!(
            "  agent {agent} ({}): move it by {}\n",
            n.framework,
            day(n.until)
        ));
    }
    text.push_str(
        "\nThey keep running until then. To move one, reset it (its persona, skills, settings and \
         memory stay; the conversation starts fresh): run 0g-agentdna, then at its prompt\n\n  \
         reset <agent>\n\n\
         After that date the previous version may be retired: an agent still on it keeps running \
         until its container next boots, and that boot is then refused until the agent is reset.\n",
    );
    if urgent {
        text.push_str(
            "\nThis release fixes a security issue: the previous version may be retired before that \
             date. Please move your agents soon.\n",
        );
    }
    text.push_str(
        "\nYou get this because you registered this address for notifications. \
         To stop: 0g-agentdna cred notify off\n",
    );
    (subject, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const H1: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const H2: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";

    fn t(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    fn sample() -> String {
        format!(
            r#"{{"releases":[
              {{"version":"0.5.0","published_at":"2026-11-20T00:00:00Z","notes":"New things.","notes_zh":"新东西。",
                "migrate":[{{"framework":"0g-harness","image_hash":"{H1}","until":"2026-12-20T00:00:00Z"}}]}},
              {{"version":"0.5.1","published_at":"2026-12-01T00:00:00Z","notes":"A fix.",
                "migrate":[{{"framework":"0g-harness","image_hash":"{H1}","until":"2026-12-10T00:00:00Z","urgent":true}},
                           {{"framework":"openclaw","image_hash":"{H2}","until":"2027-01-01T00:00:00Z"}}]}}
            ]}}"#
        )
    }

    #[test]
    fn parses_newest_first() {
        let r = parse(&sample()).unwrap();
        assert_eq!(
            r.iter().map(|r| r.version.as_str()).collect::<Vec<_>>(),
            ["0.5.1", "0.5.0"]
        );
        assert_eq!(r[1].notes_zh.as_deref(), Some("新东西。"));
        assert!(r[0].migrate[0].urgent && !r[0].migrate[1].urgent);
    }

    #[test]
    fn refuses_bad_files() {
        let one = |release: &str| format!(r#"{{"releases":[{release}]}}"#);
        for bad in [
            "not json".to_string(),
            r#"{"releases":[],"extra":1}"#.to_string(),
            one(r#"{"version":"","published_at":"2026-11-20T00:00:00Z","notes":"x"}"#),
            one(r#"{"version":"1","published_at":"2026-11-20T00:00:00Z","notes":" "}"#),
            one(&format!(
                r#"{{"version":"1","published_at":"2026-11-20T00:00:00Z","notes":"x","migrate":[{{"framework":"f","image_hash":"{H1}","until":"2026-11-19T00:00:00Z"}}]}}"#
            )),
            one(&format!(
                r#"{{"version":"1","published_at":"2026-11-20T00:00:00Z","notes":"x","migrate":[{{"framework":"f","image_hash":"{H1}","until":"2026-12-19T00:00:00Z"}},{{"framework":"f","image_hash":"{H1}","until":"2026-12-19T00:00:00Z"}}]}}"#
            )),
            one(r#"{"version":"1","published_at":"2026-11-20T00:00:00Z","notes":"x","typo":true}"#),
            one(r#"{"version":"0.5.0 ","published_at":"2026-11-20T00:00:00Z","notes":"x"}"#),
            one(r#"{"version":"0.5/0","published_at":"2026-11-20T00:00:00Z","notes":"x"}"#),
            format!(
                r#"{{"releases":[{{"version":"1","published_at":"2026-11-20T00:00:00Z","notes":"x"}},{{"version":"1","published_at":"2026-11-21T00:00:00Z","notes":"y"}}]}}"#
            ),
        ] {
            assert!(parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_earliest_until_of_published_releases_counts() {
        let r = parse(&sample()).unwrap();
        let h1: B256 = H1.parse().unwrap();
        // Before 0.5.1 is published, only 0.5.0's period applies.
        let n = migration_for(&r, h1, t("2026-11-25T00:00:00Z")).unwrap();
        assert_eq!(
            (n.version.as_str(), n.until, n.urgent, n.state),
            (
                "0.5.0",
                t("2026-12-20T00:00:00Z"),
                false,
                MigrationState::Recommended
            )
        );
        // Once it is, its earlier, urgent date counts.
        let n = migration_for(&r, h1, t("2026-12-05T00:00:00Z")).unwrap();
        assert_eq!(
            (n.version.as_str(), n.until, n.urgent, n.state),
            (
                "0.5.1",
                t("2026-12-10T00:00:00Z"),
                true,
                MigrationState::Soon
            )
        );
        assert_eq!(
            migration_for(&r, h1, t("2026-12-10T00:00:00Z"))
                .unwrap()
                .state,
            MigrationState::Overdue
        );
        // Before any release is published, or for an image no release names: nothing.
        assert!(migration_for(&r, h1, t("2026-11-19T00:00:00Z")).is_none());
        assert!(migration_for(&r, B256::repeat_byte(9), t("2026-12-05T00:00:00Z")).is_none());
        // An urgent entry wins over an earlier ordinary one, and the version,
        // date and urgency all come from it.
        let both = parse(&format!(
            r#"{{"releases":[
              {{"version":"a","published_at":"2026-11-20T00:00:00Z","notes":"x","migrate":[{{"framework":"f","image_hash":"{H1}","until":"2026-12-01T00:00:00Z"}}]}},
              {{"version":"b","published_at":"2026-11-21T00:00:00Z","notes":"y","migrate":[{{"framework":"f","image_hash":"{H1}","until":"2026-12-09T00:00:00Z","urgent":true}}]}}
            ]}}"#
        ))
        .unwrap();
        let n = migration_for(&both, h1, t("2026-11-22T00:00:00Z")).unwrap();
        assert_eq!(
            (n.version.as_str(), n.until, n.urgent),
            ("b", t("2026-12-09T00:00:00Z"), true)
        );
    }

    #[test]
    fn states() {
        let until = t("2026-12-20T00:00:00Z");
        assert_eq!(
            state_at(until, t("2026-12-12T23:59:59Z")),
            MigrationState::Recommended
        );
        assert_eq!(
            state_at(until, t("2026-12-13T00:00:00Z")),
            MigrationState::Soon
        );
        assert_eq!(state_at(until, until), MigrationState::Overdue);
    }

    #[test]
    fn loads_reloads_and_keeps_the_last_good_content() {
        let dir = std::env::temp_dir().join(format!("releases-{}-{}", std::process::id(), line!()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("releases.json");
        let p = path.to_str().unwrap();
        assert!(load("").is_empty());
        assert!(load(p).is_empty(), "a missing file serves nothing");
        std::fs::write(&path, sample()).unwrap();
        assert_eq!(load(p).len(), 2);
        // A broken edit keeps what was served. (Set a distinct mtime: some
        // filesystems keep one-second resolution.)
        std::fs::write(&path, "{ broken").unwrap();
        let later = SystemTime::now() + std::time::Duration::from_secs(5);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(later)
            .unwrap();
        assert_eq!(load(p).len(), 2);
        // A broken read cached under one modification time does not hide the
        // finished write in the same tick (the size differs).
        let tick = SystemTime::now() + std::time::Duration::from_secs(7);
        std::fs::write(&path, "{ half").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(tick)
            .unwrap();
        assert_eq!(load(p).len(), 2);
        std::fs::write(
            &path,
            r#"{"releases":[{"version":"8","published_at":"2026-11-20T00:00:00Z","notes":"x"}]}"#,
        )
        .unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(tick)
            .unwrap();
        assert_eq!(load(p)[0].version, "8");
        // An atomic replace (a new inode) is picked up too.
        let tmp = dir.join("releases.json.tmp");
        std::fs::write(
            &tmp,
            r#"{"releases":[{"version":"7","published_at":"2026-11-20T00:00:00Z","notes":"x"}]}"#,
        )
        .unwrap();
        std::fs::File::options()
            .write(true)
            .open(&tmp)
            .unwrap()
            .set_modified(tick)
            .unwrap();
        std::fs::rename(&tmp, &path).unwrap();
        assert_eq!(load(p)[0].version, "7");
        // A deleted file keeps the last good content.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(load(p)[0].version, "7");
        // A good edit is picked up.
        std::fs::write(
            &path,
            r#"{"releases":[{"version":"9","published_at":"2026-11-20T00:00:00Z","notes":"x"}]}"#,
        )
        .unwrap();
        let later = SystemTime::now() + std::time::Duration::from_secs(10);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(later)
            .unwrap();
        assert_eq!(load(p)[0].version, "9");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn email_names_the_agents_and_the_way_out() {
        let r = parse(&sample()).unwrap();
        let h1: B256 = H1.parse().unwrap();
        let n = migration_for(&r, h1, t("2026-11-25T00:00:00Z")).unwrap();
        let (subject, text) = owner_email(
            &r[1],
            &[("625".into(), n.clone()), ("528".into(), n)],
            false,
        );
        assert_eq!(
            subject,
            "AgentDNA 0.5.0: please move agent(s) 625, 528 by 2026-12-20 00:00 UTC"
        );
        for want in [
            "New things.",
            "新东西。",
            "agent 625 (0g-harness): move it by 2026-12-20 00:00 UTC",
            "  reset <agent>",
            "cred notify off",
        ] {
            assert!(text.contains(want), "{want} in {text}");
        }
        assert!(!text.contains("security"));
        let urgent = migration_for(&r, h1, t("2026-12-05T00:00:00Z")).unwrap();
        let (subject, text) = owner_email(&r[0], &[("625".into(), urgent)], true);
        assert!(subject.starts_with("Reminder: move agent(s) 625 to AgentDNA 0.5.1 by 2026-12-10"));
        assert!(text.contains("security issue"));
    }
}
