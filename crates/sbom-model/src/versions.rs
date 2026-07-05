//! version parsing and comparison utilities.
//!
//! provides lenient version parsing for SBOM component versions, supporting
//! semver, dot-separated numeric strings, Debian/RPM-style epoch/revision
//! versions, and opaque version strings.

use std::cmp::Ordering;

/// parsed version representation for lenient comparison.
///
/// covers the common version formats found in SBOMs:
/// - Standard semver (possibly with `v` prefix or fewer than three parts)
/// - Dot-separated numeric (e.g., date-based `2024.01.15` or four-part `1.2.3.4`)
/// - Debian/RPM-style `epoch:upstream-revision` (dominant in OS/container SBOMs)
/// - Opaque strings that cannot be compared
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version {
    /// parseable as semver (with lenient parsing: `v`/`V` prefix stripped,
    /// one- or two-part versions padded to three parts).
    Semver(semver::Version),
    /// dot-separated numeric segments that don't qualify as semver
    /// (e.g., four-part versions or versions with leading zeros).
    Numeric(Vec<u64>),
    /// Debian/RPM-style version with an optional numeric epoch and a trailing
    /// revision, compared with the Debian `dpkg` algorithm. covers
    /// `epoch:upstream-revision` (Debian), `epoch:version-release` (RPM), and
    /// PEP440 `epoch!version` forms that don't parse as clean semver but whose
    /// ordering is still well-defined. an absent epoch is `0` and an absent
    /// revision is the empty string.
    Deb {
        epoch: u64,
        upstream: String,
        revision: String,
    },
    /// non-parseable version string where ordering cannot be determined.
    Opaque(String),
}

impl Version {
    /// parses a version string leniently.
    ///
    /// tries semver first (stripping `v`/`V` prefix and padding one- or
    /// two-part versions), then dot-separated numeric, then Debian/RPM-style
    /// epoch/revision versions, then falls back to [`Opaque`](Version::Opaque).
    ///
    /// # Examples
    ///
    /// ```
    /// use sbom_model::versions::Version;
    ///
    /// assert!(matches!(Version::parse_lenient("1.2.3"), Version::Semver(_)));
    /// assert!(matches!(Version::parse_lenient("v1.2"), Version::Semver(_)));
    /// assert!(matches!(Version::parse_lenient("2024.01.15"), Version::Numeric(_)));
    /// assert!(matches!(Version::parse_lenient("2:1.0-3"), Version::Deb { .. }));
    /// assert!(matches!(Version::parse_lenient("abc"), Version::Opaque(_)));
    /// ```
    pub fn parse_lenient(s: &str) -> Self {
        let stripped = s
            .strip_prefix('v')
            .or_else(|| s.strip_prefix('V'))
            .unwrap_or(s);

        if let Ok(v) = semver::Version::parse(stripped) {
            return Version::Semver(v);
        }

        // try padding: "1.0" -> "1.0.0", "1" -> "1.0.0"
        let parts: Vec<&str> = stripped.splitn(3, '.').collect();
        let padded = match parts.len() {
            1 => Some(format!("{}.0.0", parts[0])),
            2 => Some(format!("{}.{}.0", parts[0], parts[1])),
            _ => None,
        };
        if let Some(ref padded) = padded {
            if let Ok(v) = semver::Version::parse(padded) {
                return Version::Semver(v);
            }
        }

        if let Some(segments) = parse_numeric(stripped) {
            return Version::Numeric(segments);
        }

        if let Some(deb) = parse_deb(stripped) {
            return deb;
        }

        Version::Opaque(s.to_string())
    }

    /// returns `true` if `new` is a downgrade from `self`.
    ///
    /// comparison strategy depends on the variant pair:
    /// - **Semver vs Semver**: semver *precedence* ordering (including
    ///   pre-release; build metadata is ignored per SemVer §10)
    /// - **Numeric vs Numeric**: segment-by-segment with implicit zero padding
    /// - **Semver vs Numeric** (either direction): extracts `[major, minor, patch]`
    ///   from the semver side and compares as numeric segments
    /// - **Deb vs Deb**: epoch (numeric), then upstream, then revision, via the
    ///   Debian `dpkg` version-comparison algorithm
    /// - **Any other pair** (including any Opaque, or a Deb against a
    ///   semver/numeric version): returns `false` (ordering unknown)
    ///
    /// # Examples
    ///
    /// ```
    /// use sbom_model::versions::Version;
    ///
    /// let old = Version::parse_lenient("2.0.0");
    /// let new = Version::parse_lenient("1.5.0");
    /// assert!(old.is_downgrade(&new));
    ///
    /// let old = Version::parse_lenient("1.0.0");
    /// let new = Version::parse_lenient("2.0.0");
    /// assert!(!old.is_downgrade(&new));
    /// ```
    pub fn is_downgrade(&self, new: &Self) -> bool {
        match (self, new) {
            (Version::Semver(old), Version::Semver(new)) => {
                new.cmp_precedence(old) == Ordering::Less
            }
            (Version::Numeric(old), Version::Numeric(new)) => numeric_downgrade(old, new),
            (Version::Semver(old), Version::Numeric(new_segs)) => {
                let old_segs = [old.major, old.minor, old.patch];
                numeric_downgrade(&old_segs, new_segs)
            }
            (Version::Numeric(old_segs), Version::Semver(new)) => {
                let new_segs = [new.major, new.minor, new.patch];
                numeric_downgrade(old_segs, &new_segs)
            }
            (
                Version::Deb {
                    epoch: oe,
                    upstream: ou,
                    revision: orev,
                },
                Version::Deb {
                    epoch: ne,
                    upstream: nu,
                    revision: nrev,
                },
            ) => deb_cmp((*ne, nu, nrev), (*oe, ou, orev)) == Ordering::Less,
            _ => false,
        }
    }
}

/// segment-by-segment numeric comparison with implicit zero padding.
fn numeric_downgrade(old: &[u64], new: &[u64]) -> bool {
    let max_len = old.len().max(new.len());
    for i in 0..max_len {
        let o = old.get(i).copied().unwrap_or(0);
        let n = new.get(i).copied().unwrap_or(0);
        if n < o {
            return true;
        }
        if n > o {
            return false;
        }
    }
    false
}

/// parses dot-separated numeric segments (e.g. four-part or leading-zero
/// versions). returns `None` when any segment is non-numeric or the string is
/// empty, so the caller can fall through to the next parsing strategy.
fn parse_numeric(stripped: &str) -> Option<Vec<u64>> {
    let mut segments = Vec::new();
    for part in stripped.split('.') {
        segments.push(part.parse::<u64>().ok()?);
    }
    if segments.is_empty() {
        None
    } else {
        Some(segments)
    }
}

/// parses a Debian/RPM-style `epoch:upstream-revision` version.
///
/// returns `None` for strings that don't look like a comparable package
/// version — the upstream part must start with a digit (the Debian convention)
/// and every character must be in the Debian/RPM version alphabet — so that
/// codenames, git hashes, and other genuinely opaque strings stay
/// [`Opaque`](Version::Opaque) rather than being force-ordered.
fn parse_deb(stripped: &str) -> Option<Version> {
    let (epoch, rest) = split_epoch(stripped);

    if !rest.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    if !rest.chars().all(is_deb_char) {
        return None;
    }

    // the revision is everything after the last hyphen (dpkg splits there);
    // an absent revision compares equal to "0".
    let (upstream, revision) = match rest.rfind('-') {
        Some(idx) => (rest[..idx].to_string(), rest[idx + 1..].to_string()),
        None => (rest.to_string(), String::new()),
    };

    Some(Version::Deb {
        epoch,
        upstream,
        revision,
    })
}

/// splits a leading `N:` (Debian) or `N!` (PEP440) epoch off a version string.
/// returns `(0, s)` when there is no numeric epoch prefix.
fn split_epoch(s: &str) -> (u64, &str) {
    if let Some(idx) = s.find([':', '!']) {
        let (head, tail) = s.split_at(idx);
        if !head.is_empty() && head.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(epoch) = head.parse::<u64>() {
                return (epoch, &tail[1..]);
            }
        }
    }
    (0, s)
}

/// characters permitted in a Debian/RPM upstream version or revision.
fn is_deb_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-' | '~' | ':')
}

/// orders two Debian/RPM-style versions given as `(epoch, upstream, revision)`:
/// a higher epoch always wins; ties fall through to the upstream version and
/// then the revision, both compared with [`verrevcmp`].
fn deb_cmp(a: (u64, &str, &str), b: (u64, &str, &str)) -> Ordering {
    a.0.cmp(&b.0)
        .then_with(|| verrevcmp(a.1, b.1))
        .then_with(|| verrevcmp(a.2, b.2))
}

/// the Debian `dpkg` version-component comparison (`verrevcmp`).
///
/// the two strings are scanned in lockstep, alternating between runs of
/// non-digits and runs of digits. non-digit runs are compared lexically with a
/// modified ordering (a tilde sorts before everything, even the end of a
/// string, and letters sort before other punctuation); digit runs are compared
/// numerically (leading zeros stripped, longer run wins). this is the standard
/// algorithm used for Debian upstream versions and revisions, and it also gives
/// correct results for the overwhelming majority of RPM versions.
fn verrevcmp(a: &str, b: &str) -> Ordering {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let mut i = 0;
    let mut j = 0;

    while i < a.len() || j < b.len() {
        while (i < a.len() && !a[i].is_ascii_digit()) || (j < b.len() && !b[j].is_ascii_digit()) {
            let ac = a.get(i).map_or(0, |&c| deb_order(c));
            let bc = b.get(j).map_or(0, |&c| deb_order(c));
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }

        while i < a.len() && a[i] == b'0' {
            i += 1;
        }
        while j < b.len() && b[j] == b'0' {
            j += 1;
        }

        let mut first_diff = 0i32;
        while i < a.len() && a[i].is_ascii_digit() && j < b.len() && b[j].is_ascii_digit() {
            if first_diff == 0 {
                first_diff = i32::from(a[i]) - i32::from(b[j]);
            }
            i += 1;
            j += 1;
        }
        // a longer remaining digit run means a larger number (no leading zeros
        // remain), which takes precedence over any earlier per-digit difference.
        if i < a.len() && a[i].is_ascii_digit() {
            return Ordering::Greater;
        }
        if j < b.len() && b[j].is_ascii_digit() {
            return Ordering::Less;
        }
        if first_diff != 0 {
            return first_diff.cmp(&0);
        }
    }

    Ordering::Equal
}

/// the per-character sort key used by [`verrevcmp`] for non-digit runs: a tilde
/// sorts before everything (even the end of a string), letters keep their ASCII
/// order, and all other characters sort after letters. digits and the end of a
/// string both sort as `0`, so a digit encountered mid-scan behaves like a
/// boundary (matching dpkg's `order()`).
fn deb_order(c: u8) -> i32 {
    if c.is_ascii_digit() {
        0
    } else if c.is_ascii_alphabetic() {
        i32::from(c)
    } else if c == b'~' {
        -1
    } else {
        i32::from(c) + 256
    }
}

/// convenience function: returns `true` if `new_ver` is a downgrade from `old_ver`.
///
/// parses both strings with [`Version::parse_lenient`] and delegates to
/// [`Version::is_downgrade`].
pub fn is_version_downgrade(old_ver: &str, new_ver: &str) -> bool {
    Version::parse_lenient(old_ver).is_downgrade(&Version::parse_lenient(new_ver))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_standard_semver() {
        let v = Version::parse_lenient("1.2.3");
        assert_eq!(v, Version::Semver(semver::Version::new(1, 2, 3)));
    }

    #[test]
    fn parse_v_prefix() {
        assert_eq!(
            Version::parse_lenient("v1.2.3"),
            Version::Semver(semver::Version::new(1, 2, 3))
        );
        assert_eq!(
            Version::parse_lenient("V1.2.3"),
            Version::Semver(semver::Version::new(1, 2, 3))
        );
    }

    #[test]
    fn parse_two_parts() {
        assert_eq!(
            Version::parse_lenient("1.2"),
            Version::Semver(semver::Version::new(1, 2, 0))
        );
    }

    #[test]
    fn parse_single_part() {
        assert_eq!(
            Version::parse_lenient("42"),
            Version::Semver(semver::Version::new(42, 0, 0))
        );
    }

    #[test]
    fn parse_prerelease() {
        let v = Version::parse_lenient("1.2.3-beta.1");
        match v {
            Version::Semver(sv) => {
                assert_eq!(sv.major, 1);
                assert_eq!(sv.minor, 2);
                assert_eq!(sv.patch, 3);
                assert!(!sv.pre.is_empty());
            }
            other => panic!("expected Semver, got {:?}", other),
        }
    }

    #[test]
    fn parse_build_metadata() {
        let v = Version::parse_lenient("1.2.3+build.456");
        match v {
            Version::Semver(sv) => {
                assert_eq!((sv.major, sv.minor, sv.patch), (1, 2, 3));
                assert!(!sv.build.is_empty());
            }
            other => panic!("expected Semver, got {:?}", other),
        }
    }

    #[test]
    fn parse_prerelease_and_build() {
        let v = Version::parse_lenient("1.0.0-alpha.1+build.789");
        match v {
            Version::Semver(sv) => {
                assert_eq!(sv.major, 1);
                assert!(!sv.pre.is_empty());
                assert!(!sv.build.is_empty());
            }
            other => panic!("expected Semver, got {:?}", other),
        }
    }

    #[test]
    fn parse_v_prefix_two_parts() {
        assert_eq!(
            Version::parse_lenient("v1.2"),
            Version::Semver(semver::Version::new(1, 2, 0))
        );
    }

    #[test]
    fn parse_v_prefix_single_part() {
        assert_eq!(
            Version::parse_lenient("v5"),
            Version::Semver(semver::Version::new(5, 0, 0))
        );
    }

    #[test]
    fn parse_v_prefix_prerelease() {
        let v = Version::parse_lenient("v2.0.0-rc.1");
        match v {
            Version::Semver(sv) => {
                assert_eq!(sv.major, 2);
                assert!(!sv.pre.is_empty());
            }
            other => panic!("expected Semver, got {:?}", other),
        }
    }

    #[test]
    fn parse_zero_version() {
        assert_eq!(
            Version::parse_lenient("0.0.0"),
            Version::Semver(semver::Version::new(0, 0, 0))
        );
    }

    #[test]
    fn parse_large_numbers() {
        assert_eq!(
            Version::parse_lenient("999.888.777"),
            Version::Semver(semver::Version::new(999, 888, 777))
        );
    }

    #[test]
    fn parse_single_zero() {
        assert_eq!(
            Version::parse_lenient("0"),
            Version::Semver(semver::Version::new(0, 0, 0))
        );
    }

    #[test]
    fn parse_four_part_is_numeric() {
        assert_eq!(
            Version::parse_lenient("1.2.3.4"),
            Version::Numeric(vec![1, 2, 3, 4])
        );
    }

    #[test]
    fn parse_date_based_is_numeric() {
        // leading zeros are rejected by semver but u64 parses them fine
        assert_eq!(
            Version::parse_lenient("2024.01.15"),
            Version::Numeric(vec![2024, 1, 15])
        );
    }

    #[test]
    fn parse_v_prefix_four_part_is_numeric() {
        // the v-prefix must be stripped before the numeric fallback splits
        assert_eq!(
            Version::parse_lenient("v1.2.3.4"),
            Version::Numeric(vec![1, 2, 3, 4])
        );
        assert_eq!(
            Version::parse_lenient("V1.2.3.4"),
            Version::Numeric(vec![1, 2, 3, 4])
        );
    }

    #[test]
    fn parse_v_prefix_date_based_is_numeric() {
        assert_eq!(
            Version::parse_lenient("v2024.01.15"),
            Version::Numeric(vec![2024, 1, 15])
        );
    }

    #[test]
    fn parse_leading_zeros_is_numeric() {
        assert_eq!(
            Version::parse_lenient("01.02.03"),
            Version::Numeric(vec![1, 2, 3])
        );
    }

    #[test]
    fn parse_non_numeric_is_opaque() {
        assert_eq!(Version::parse_lenient("abc"), Version::Opaque("abc".into()));
        assert_eq!(
            Version::parse_lenient("foo.bar.baz"),
            Version::Opaque("foo.bar.baz".into())
        );
    }

    #[test]
    fn parse_whitespace_is_opaque() {
        assert!(matches!(
            Version::parse_lenient(" 1.2.3"),
            Version::Opaque(_)
        ));
        assert!(matches!(
            Version::parse_lenient("1.2.3 "),
            Version::Opaque(_)
        ));
    }

    #[test]
    fn parse_empty_string_is_opaque() {
        assert!(matches!(Version::parse_lenient(""), Version::Opaque(_)));
    }

    #[test]
    fn downgrade_semver() {
        assert!(is_version_downgrade("2.0.0", "1.5.0"));
        assert!(is_version_downgrade("1.1.0", "1.0.0"));
        assert!(is_version_downgrade("1.0.1", "1.0.0"));
    }

    #[test]
    fn upgrade_semver_not_flagged() {
        assert!(!is_version_downgrade("1.0.0", "1.1.0"));
        assert!(!is_version_downgrade("1.0.0", "2.0.0"));
        assert!(!is_version_downgrade("1.0.0", "1.0.1"));
    }

    #[test]
    fn equal_semver_not_flagged() {
        assert!(!is_version_downgrade("1.0.0", "1.0.0"));
    }

    #[test]
    fn downgrade_v_prefix() {
        assert!(is_version_downgrade("v2.0.0", "v1.0.0"));
        assert!(!is_version_downgrade("v1.0.0", "v2.0.0"));
    }

    #[test]
    fn downgrade_prerelease() {
        assert!(is_version_downgrade("1.0.0", "1.0.0-rc1"));
        assert!(!is_version_downgrade("1.0.0-rc1", "1.0.0"));
    }

    #[test]
    fn downgrade_build_metadata() {
        // SemVer §10: build metadata MUST be ignored when determining
        // precedence, so a build-metadata-only change is never a downgrade in
        // either direction.
        assert!(!is_version_downgrade("1.0.0+build.1", "1.0.0+build.2"));
        assert!(!is_version_downgrade("1.0.0+build.2", "1.0.0+build.1"));
        assert!(!is_version_downgrade("1.0.0+build.1", "1.0.0+build.1"));
        // commit-hash build metadata (common in generated SBOMs) must not trip
        // the gate regardless of lexical ordering of the hashes.
        assert!(!is_version_downgrade("1.0.0+c144a98", "1.0.0+bc17664"));
        assert!(!is_version_downgrade("1.0.0+build.10", "1.0.0+build.9"));
    }

    #[test]
    fn downgrade_mixed_v_prefix() {
        assert!(is_version_downgrade("v2.0.0", "1.0.0"));
        assert!(is_version_downgrade("2.0.0", "v1.0.0"));
        assert!(!is_version_downgrade("v1.0.0", "2.0.0"));
        assert!(!is_version_downgrade("1.0.0", "v2.0.0"));
    }

    #[test]
    fn downgrade_prerelease_ordering() {
        assert!(is_version_downgrade("1.0.0-beta.1", "1.0.0-alpha.1"));
        assert!(is_version_downgrade("1.0.0-rc.1", "1.0.0-beta.1"));
        assert!(!is_version_downgrade("1.0.0-alpha.1", "1.0.0-beta.1"));
        assert!(!is_version_downgrade("1.0.0-beta.1", "1.0.0-rc.1"));
    }

    #[test]
    fn downgrade_prerelease_numeric_ordering() {
        assert!(is_version_downgrade("1.0.0-rc.2", "1.0.0-rc.1"));
        assert!(!is_version_downgrade("1.0.0-rc.1", "1.0.0-rc.2"));
    }

    #[test]
    fn downgrade_equal_with_v_prefix() {
        assert!(!is_version_downgrade("v1.0.0", "v1.0.0"));
    }

    #[test]
    fn downgrade_padded_two_part() {
        assert!(is_version_downgrade("1.2", "1.1"));
        assert!(!is_version_downgrade("1.1", "1.2"));
        assert!(!is_version_downgrade("1.2", "1.2"));
    }

    #[test]
    fn downgrade_padded_single_part() {
        assert!(is_version_downgrade("2", "1"));
        assert!(!is_version_downgrade("1", "2"));
        assert!(!is_version_downgrade("5", "5"));
    }

    #[test]
    fn downgrade_mixed_part_counts_semver() {
        assert!(is_version_downgrade("2.0", "1.9.9"));
        assert!(!is_version_downgrade("1.9.9", "2.0"));
    }

    #[test]
    fn downgrade_v_prefix_two_part() {
        assert!(is_version_downgrade("v2.0", "v1.0"));
        assert!(!is_version_downgrade("v1.0", "v2.0"));
    }

    #[test]
    fn downgrade_four_part() {
        assert!(is_version_downgrade("1.2.3.4", "1.2.3.3"));
        assert!(!is_version_downgrade("1.2.3.3", "1.2.3.4"));
        assert!(!is_version_downgrade("1.2.3.4", "1.2.3.4"));
    }

    #[test]
    fn downgrade_date_based() {
        assert!(is_version_downgrade("2024.01.15", "2023.12.01"));
        assert!(!is_version_downgrade("2023.12.01", "2024.01.15"));
    }

    #[test]
    fn downgrade_v_prefix_four_part() {
        // v-prefixed four-part versions parse to Numeric, so the downgrade
        // gate sees them instead of silently treating them as Opaque
        assert!(is_version_downgrade("v1.2.3.4", "v1.2.3.3"));
        assert!(!is_version_downgrade("v1.2.3.3", "v1.2.3.4"));
        assert!(!is_version_downgrade("v1.2.3.4", "v1.2.3.4"));
    }

    #[test]
    fn downgrade_v_prefix_date_based() {
        assert!(is_version_downgrade("v2024.01.15", "v2023.12.01"));
        assert!(!is_version_downgrade("v2023.12.01", "v2024.01.15"));
    }

    #[test]
    fn downgrade_non_numeric_not_flagged() {
        assert!(!is_version_downgrade("abc", "def"));
        assert!(!is_version_downgrade("foo.bar", "foo.baz"));
    }

    #[test]
    fn downgrade_numeric_unequal_length() {
        assert!(is_version_downgrade("1.2.3.4", "1.2.3"));
        assert!(!is_version_downgrade("1.2.3", "1.2.3.4"));
    }

    #[test]
    fn downgrade_large_major_numeric_equal() {
        // "2024.1.15" has no leading zeros, so it parses as valid semver
        assert!(!is_version_downgrade("2024.1.15", "2024.1.15"));
    }

    #[test]
    fn downgrade_semver_vs_four_part() {
        // "1.2.3" → Semver, "1.2.3.4" → Numeric; cross-comparison extracts
        // [major,minor,patch] from the semver side
        assert!(!is_version_downgrade("1.2.3", "1.2.3.4"));
        assert!(is_version_downgrade("1.2.3.4", "1.2.3"));
    }

    #[test]
    fn downgrade_v_prefix_vs_four_part() {
        // cross-variant comparison works after stripping the v-prefix during parse.
        assert!(!is_version_downgrade("v1.2.3", "1.2.3.4"));
        assert!(is_version_downgrade("1.2.3.4", "v1.2.3"));
    }

    #[test]
    fn downgrade_empty_strings() {
        assert!(!is_version_downgrade("", "1.0.0"));
        assert!(!is_version_downgrade("1.0.0", ""));
        assert!(!is_version_downgrade("", ""));
    }

    // --- Debian/RPM epoch/upstream/revision parsing ---

    #[test]
    fn parse_epoch_is_deb() {
        // versions with an epoch aren't semver and were previously Opaque
        assert!(matches!(
            Version::parse_lenient("2:1.0"),
            Version::Deb { .. }
        ));
        assert!(matches!(
            Version::parse_lenient("1:9.0"),
            Version::Deb { .. }
        ));
    }

    #[test]
    fn parse_revision_is_deb() {
        // "5.1-3" is not valid semver (two-part base) and was previously Opaque
        assert!(matches!(
            Version::parse_lenient("5.1-3"),
            Version::Deb { .. }
        ));
    }

    #[test]
    fn parse_deb_fields() {
        match Version::parse_lenient("2:1.2.3-4") {
            Version::Deb {
                epoch,
                upstream,
                revision,
            } => {
                assert_eq!(epoch, 2);
                assert_eq!(upstream, "1.2.3");
                assert_eq!(revision, "4");
            }
            other => panic!("expected Deb, got {:?}", other),
        }
    }

    #[test]
    fn parse_deb_revision_splits_at_last_hyphen() {
        // "1.2.3-2-1" is valid semver (pre-release "2-1"), so use a two-part
        // base that semver rejects to exercise the last-hyphen revision split
        match Version::parse_lenient("1.2-2-1") {
            Version::Deb {
                epoch,
                upstream,
                revision,
            } => {
                assert_eq!(epoch, 0);
                assert_eq!(upstream, "1.2-2");
                assert_eq!(revision, "1");
            }
            other => panic!("expected Deb, got {:?}", other),
        }
    }

    #[test]
    fn parse_pep440_epoch_is_deb() {
        match Version::parse_lenient("1!2.0") {
            Version::Deb {
                epoch,
                upstream,
                revision,
            } => {
                assert_eq!(epoch, 1);
                assert_eq!(upstream, "2.0");
                assert_eq!(revision, "");
            }
            other => panic!("expected Deb, got {:?}", other),
        }
    }

    #[test]
    fn parse_tilde_prerelease_is_deb() {
        // tilde pre-release strings aren't semver but are comparable Debian versions
        assert!(matches!(
            Version::parse_lenient("1.0.0~rc1"),
            Version::Deb { .. }
        ));
    }

    #[test]
    fn parse_codename_stays_opaque() {
        // a leading non-digit means it isn't a comparable package version
        assert!(matches!(
            Version::parse_lenient("focal-1"),
            Version::Opaque(_)
        ));
        assert!(matches!(
            Version::parse_lenient("stable"),
            Version::Opaque(_)
        ));
        // a bare numeric epoch with a non-version tail is not comparable either
        assert!(matches!(
            Version::parse_lenient("1:stable"),
            Version::Opaque(_)
        ));
    }

    // --- Debian/RPM downgrade detection ---

    #[test]
    fn downgrade_epoch() {
        // a higher epoch always wins, regardless of the upstream version
        assert!(is_version_downgrade("2:1.0", "1:9.0"));
        assert!(!is_version_downgrade("1:9.0", "2:1.0"));
        // epoch dominates: epoch up beats a lower upstream, epoch down beats a higher one
        assert!(!is_version_downgrade("1:1.0", "2:0.1"));
        assert!(is_version_downgrade("2:0.1", "1:1.0"));
    }

    #[test]
    fn downgrade_epoch_equal_upstream() {
        assert!(is_version_downgrade("1:2.0", "1:1.0"));
        assert!(!is_version_downgrade("1:1.0", "1:2.0"));
        assert!(!is_version_downgrade("1:1.0", "1:1.0"));
    }

    #[test]
    fn downgrade_implicit_epoch_zero() {
        // an absent epoch is 0, so adding an epoch is an upgrade, dropping to
        // an explicit 0 is neutral
        assert!(!is_version_downgrade("5.1-1", "1:0.1-1"));
        assert!(is_version_downgrade("1:0.1-1", "0:0.1-1"));
    }

    #[test]
    fn downgrade_revision() {
        assert!(is_version_downgrade("5.1-3", "5.1-2"));
        assert!(!is_version_downgrade("5.1-2", "5.1-3"));
        assert!(!is_version_downgrade("5.1-2", "5.1-2"));
    }

    #[test]
    fn downgrade_upstream_trumps_revision() {
        // equal revision, upstream down -> downgrade
        assert!(is_version_downgrade("1:5.2-1", "1:5.1-1"));
        // upstream up, revision down -> upgrade (upstream is compared first)
        assert!(!is_version_downgrade("1:5.1-9", "1:5.2-1"));
    }

    #[test]
    fn downgrade_absent_revision_equals_zero() {
        // an absent revision compares as "0"; "1.0" is semver so pin the epoch
        // to force Debian parsing on both sides
        assert!(is_version_downgrade("1:2.0-1", "1:2.0"));
        assert!(!is_version_downgrade("1:2.0", "1:2.0-1"));
    }

    #[test]
    fn downgrade_rpm_release_with_epoch() {
        // an epoch forces Debian parsing even though the tail resembles a
        // semver pre-release; RPM `.elN` release tails order numerically
        assert!(is_version_downgrade("1:1.2.3-2.el8", "1:1.2.3-1.el8"));
        assert!(!is_version_downgrade("1:1.2.3-1.el8", "1:1.2.3-2.el8"));
        // el8 is newer than el7
        assert!(is_version_downgrade("1:1.2.3-1.el8", "1:1.2.3-1.el7"));
        assert!(!is_version_downgrade("1:1.2.3-1.el7", "1:1.2.3-1.el8"));
    }

    #[test]
    fn downgrade_deb_numeric_not_lexical() {
        // 10 > 9 numerically even though "9" > "1" lexically
        assert!(is_version_downgrade("1.10-1", "1.9-1"));
        assert!(!is_version_downgrade("1.9-1", "1.10-1"));
    }

    #[test]
    fn downgrade_deb_tilde_prerelease() {
        // a tilde sorts before everything, so ~rc2 > ~rc1 and ~rc1 < the release
        assert!(is_version_downgrade("1.0.0~rc2", "1.0.0~rc1"));
        assert!(!is_version_downgrade("1.0.0~rc1", "1.0.0~rc2"));
        assert!(is_version_downgrade("1:1.0~rc1", "1:1.0~beta1"));
    }

    #[test]
    fn downgrade_real_world_deb() {
        // openssl with epoch and an Ubuntu security revision
        assert!(is_version_downgrade(
            "1:1.1.1f-1ubuntu2.16",
            "1:1.1.1f-1ubuntu2.15"
        ));
        assert!(!is_version_downgrade(
            "1:1.1.1f-1ubuntu2.15",
            "1:1.1.1f-1ubuntu2.16"
        ));
    }

    #[test]
    fn downgrade_deb_opaque_not_flagged() {
        // codenames and other non-version strings remain uncomparable
        assert!(!is_version_downgrade("focal", "bionic"));
        assert!(!is_version_downgrade("1:stable", "1:oldstable"));
    }

    #[test]
    fn downgrade_deb_vs_semver_not_flagged() {
        // cross-format comparison stays conservative (returns false)
        assert!(!is_version_downgrade("2:1.0", "1.0.0"));
        assert!(!is_version_downgrade("1.0.0", "2:1.0"));
    }
}
