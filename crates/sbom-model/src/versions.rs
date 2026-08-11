//! version parsing and comparison utilities.
//!
//! provides lenient version parsing for SBOM component versions, supporting
//! semver, dot-separated numeric strings, PEP 440 (Python) versions,
//! Debian/RPM-style epoch/revision versions, and opaque version strings.

use std::cmp::Ordering;

/// parsed version representation for lenient comparison.
///
/// covers the common version formats found in SBOMs:
/// - standard semver (possibly with `v` prefix or fewer than three parts)
/// - dot-separated numeric (e.g., date-based `2024.01.15` or four-part `1.2.3.4`)
/// - PEP 440 pre/post/dev releases and epochs (dominant in Python SBOMs)
/// - Debian/RPM-style `epoch:upstream-revision` (dominant in OS/container SBOMs)
/// - opaque strings that cannot be compared
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version {
    /// parseable as semver (with lenient parsing: `v`/`V` prefix stripped,
    /// one- or two-part versions padded to three parts).
    Semver(semver::Version),
    /// dot-separated numeric segments that don't qualify as semver
    /// (e.g., four-part versions or versions with leading zeros).
    Numeric(Vec<u64>),
    /// PEP 440 (Python) version carrying an epoch, pre-release, post-release or
    /// dev-release segment, ordered per the PEP.
    Pep440(Pep440),
    /// Debian/RPM-style version with an optional numeric epoch and a trailing
    /// revision, compared with the Debian `dpkg` algorithm. covers
    /// `epoch:upstream-revision` (Debian) and `epoch:version-release` (RPM); a
    /// `N!` epoch prefix is accepted too, for strings
    /// [`Pep440`](Version::Pep440) declines. an absent epoch is `0` and an
    /// absent revision is the empty string.
    Deb {
        epoch: u64,
        upstream: String,
        revision: String,
    },
    /// non-parseable version string where ordering cannot be determined.
    Opaque(String),
}

/// a normalized PEP 440 version: `[N!]N(.N)*[{a|b|rc}N][.postN][.devN][+local]`.
///
/// spelling aliases are folded to the canonical form during parsing
/// (`alpha` → `a`, `beta` → `b`, `c`/`pre`/`preview` → `rc`, `rev`/`r` →
/// `post`), and `-`/`_`/`.` separators are equivalent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pep440 {
    pub epoch: u64,
    pub release: Vec<u64>,
    pub pre: Option<(PreRelease, u64)>,
    pub post: Option<u64>,
    pub dev: Option<u64>,
    pub local: Vec<LocalSegment>,
}

/// a PEP 440 pre-release kind, in ascending order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PreRelease {
    Alpha,
    Beta,
    Rc,
}

/// one dot-separated part of a PEP 440 local version label. the variant order
/// is the PEP 440 rule: a lexical part sorts before any numeric one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum LocalSegment {
    Str(String),
    Num(u64),
}

impl Version {
    /// parses a version string leniently.
    ///
    /// tries semver first (stripping `v`/`V` prefix and padding one- or
    /// two-part versions), then dot-separated numeric, then PEP 440, then
    /// Debian/RPM-style epoch/revision versions, then falls back to
    /// [`Opaque`](Version::Opaque).
    ///
    /// # Examples
    ///
    /// ```
    /// use sbom_model::versions::Version;
    ///
    /// assert!(matches!(Version::parse_lenient("1.2.3"), Version::Semver(_)));
    /// assert!(matches!(Version::parse_lenient("v1.2"), Version::Semver(_)));
    /// assert!(matches!(Version::parse_lenient("2024.01.15"), Version::Numeric(_)));
    /// assert!(matches!(Version::parse_lenient("4.2.0rc1"), Version::Pep440(_)));
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

        if let Some(pep) = parse_pep440(stripped) {
            // a plain release has no PEP 440-specific segment; leave its classification alone
            if pep.epoch > 0 || pep.pre.is_some() || pep.post.is_some() || pep.dev.is_some() {
                return Version::Pep440(pep);
            }
        }

        if let Some(deb) = parse_deb(stripped) {
            return deb;
        }

        Version::Opaque(s.to_string())
    }

    /// orders two versions, returning `None` when the ordering is unknown.
    ///
    /// comparison strategy depends on the variant pair:
    /// - **Semver vs Semver**: semver *precedence* ordering (including
    ///   pre-release; build metadata is ignored per SemVer §10)
    /// - **Numeric vs Numeric**: segment-by-segment with implicit zero padding
    /// - **Semver vs Numeric** (either direction): extracts `[major, minor, patch]`
    ///   from the semver side and compares as numeric segments
    /// - **Deb vs Deb**: epoch (numeric), then upstream, then revision, via the
    ///   Debian `dpkg` version-comparison algorithm
    /// - **Pep440 against Pep440, Semver or Numeric** (either direction): the
    ///   other side is read as a PEP 440 version and both are ordered per PEP
    ///   440. a semver pre-release that isn't a PEP 440 suffix (say
    ///   `1.0.0-foo.bar`) has no PEP 440 reading, so that pair stays `None`
    /// - **Any other pair** (including any Opaque, or a Deb against a
    ///   semver/numeric/PEP 440 version): `None`
    ///
    /// deliberately weaker than [`PartialOrd`]: even two identical
    /// [`Opaque`](Version::Opaque) versions compare `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::cmp::Ordering;
    /// use sbom_model::versions::Version;
    ///
    /// let a = Version::parse_lenient("2.0.0");
    /// let b = Version::parse_lenient("1.5.0");
    /// assert_eq!(a.partial_cmp_lenient(&b), Some(Ordering::Greater));
    ///
    /// let opaque = Version::parse_lenient("deadbeef");
    /// assert_eq!(a.partial_cmp_lenient(&opaque), None);
    /// ```
    pub fn partial_cmp_lenient(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Version::Semver(a), Version::Semver(b)) => Some(a.cmp_precedence(b)),
            (Version::Numeric(a), Version::Numeric(b)) => Some(numeric_cmp(a, b)),
            (Version::Semver(a), Version::Numeric(b)) => {
                Some(numeric_cmp(&[a.major, a.minor, a.patch], b))
            }
            (Version::Numeric(a), Version::Semver(b)) => {
                Some(numeric_cmp(a, &[b.major, b.minor, b.patch]))
            }
            (
                Version::Deb {
                    epoch: ae,
                    upstream: au,
                    revision: arev,
                },
                Version::Deb {
                    epoch: be,
                    upstream: bu,
                    revision: brev,
                },
            ) => Some(deb_cmp((*ae, au, arev), (*be, bu, brev))),
            (Version::Pep440(_), _) | (_, Version::Pep440(_)) => {
                Some(pep440_cmp(&as_pep440(self)?, &as_pep440(other)?))
            }
            _ => None,
        }
    }

    /// returns `true` if `new` is a downgrade from `self`.
    ///
    /// a pair whose ordering is unknown is not a downgrade; see
    /// [`partial_cmp_lenient`](Self::partial_cmp_lenient) for the per-variant
    /// comparison rules.
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
        self.partial_cmp_lenient(new) == Some(Ordering::Greater)
    }
}

/// segment-by-segment numeric comparison with implicit zero padding.
fn numeric_cmp(a: &[u64], b: &[u64]) -> Ordering {
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x.cmp(&y);
        }
    }
    Ordering::Equal
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

/// pre-release spellings PEP 440 normalizes, longest first so `alpha` is not
/// read as `a` with a trailing `lpha`.
const PRE_ALIASES: [(&str, PreRelease); 8] = [
    ("alpha", PreRelease::Alpha),
    ("beta", PreRelease::Beta),
    ("preview", PreRelease::Rc),
    ("pre", PreRelease::Rc),
    ("rc", PreRelease::Rc),
    ("a", PreRelease::Alpha),
    ("b", PreRelease::Beta),
    ("c", PreRelease::Rc),
];

/// post-release spellings PEP 440 normalizes, longest first.
const POST_ALIASES: [(&str, ()); 3] = [("post", ()), ("rev", ()), ("r", ())];

const DEV_ALIASES: [(&str, ()); 1] = [("dev", ())];

/// parses a PEP 440 version, returning `None` for anything not confidently PEP
/// 440 so Debian and opaque strings fall through to the next strategy. the
/// implicit post-release form (`1.0-1`) is rejected: it is indistinguishable
/// from a Debian upstream-revision version.
fn parse_pep440(s: &str) -> Option<Pep440> {
    let lower = s.to_ascii_lowercase();

    let (head, local) = match lower.split_once('+') {
        Some((head, tail)) => (head, parse_local(tail)?),
        None => (lower.as_str(), Vec::new()),
    };
    let (epoch, mut rest) = match head.split_once('!') {
        Some((epoch, tail)) => (epoch.parse::<u64>().ok()?, tail),
        None => (0, head),
    };

    let mut release = Vec::new();
    loop {
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if end == 0 {
            return None;
        }
        release.push(rest[..end].parse::<u64>().ok()?);
        rest = &rest[end..];
        match rest.strip_prefix('.') {
            // a dot continues the release only when a digit follows it
            Some(next) if next.starts_with(|c: char| c.is_ascii_digit()) => rest = next,
            _ => break,
        }
    }

    let (pre, rest) = match take_segment(rest, &PRE_ALIASES) {
        Some((kind, n, rest)) => (Some((kind, n)), rest),
        None => (None, rest),
    };
    let (post, rest) = match take_segment(rest, &POST_ALIASES) {
        Some((_, n, rest)) => (Some(n), rest),
        None => (None, rest),
    };
    let (dev, rest) = match take_segment(rest, &DEV_ALIASES) {
        Some((_, n, rest)) => (Some(n), rest),
        None => (None, rest),
    };
    if !rest.is_empty() {
        return None;
    }

    Some(Pep440 {
        epoch,
        release,
        pre,
        post,
        dev,
        local,
    })
}

/// consumes a `[-_.]?<keyword>[-_.]?<number>?` suffix, returning the matched
/// keyword's tag, its number (an absent one is `0`, per PEP 440) and the rest.
fn take_segment<'a, T: Copy>(s: &'a str, aliases: &[(&str, T)]) -> Option<(T, u64, &'a str)> {
    let body = s.strip_prefix(['-', '_', '.']).unwrap_or(s);
    let (tag, rest) = aliases
        .iter()
        .find_map(|(name, tag)| Some((*tag, body.strip_prefix(*name)?)))?;
    let digits = rest.strip_prefix(['-', '_', '.']).unwrap_or(rest);
    let end = digits
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(digits.len());
    let n = if end == 0 {
        0
    } else {
        digits[..end].parse::<u64>().ok()?
    };
    Some((tag, n, &digits[end..]))
}

/// parses a PEP 440 local version label (the part after `+`).
fn parse_local(s: &str) -> Option<Vec<LocalSegment>> {
    let mut segments = Vec::new();
    for part in s.split(['-', '_', '.']) {
        if part.is_empty() || !part.chars().all(|c| c.is_ascii_alphanumeric()) {
            return None;
        }
        segments.push(match part.parse::<u64>() {
            Ok(n) => LocalSegment::Num(n),
            Err(_) => LocalSegment::Str(part.to_string()),
        });
    }
    Some(segments)
}

/// reads a version as a PEP 440 version, so a `Pep440` can be compared against
/// the semver and numeric spellings of the same release. returns `None` when
/// there is no PEP 440 reading.
fn as_pep440(v: &Version) -> Option<Pep440> {
    let plain = |release| Pep440 {
        epoch: 0,
        release,
        pre: None,
        post: None,
        dev: None,
        local: Vec::new(),
    };
    match v {
        Version::Pep440(p) => Some(p.clone()),
        Version::Numeric(segments) => Some(plain(segments.clone())),
        Version::Semver(s) if s.pre.is_empty() => Some(plain(vec![s.major, s.minor, s.patch])),
        Version::Semver(s) => {
            parse_pep440(&format!("{}.{}.{}-{}", s.major, s.minor, s.patch, s.pre))
        }
        Version::Deb { .. } | Version::Opaque(_) => None,
    }
}

/// orders two PEP 440 versions: epoch, release (zero-padded), then the
/// pre/post/dev segments, then the local label.
fn pep440_cmp(a: &Pep440, b: &Pep440) -> Ordering {
    a.epoch
        .cmp(&b.epoch)
        .then_with(|| numeric_cmp(&a.release, &b.release))
        .then_with(|| pre_key(a).cmp(&pre_key(b)))
        .then_with(|| a.post.cmp(&b.post))
        .then_with(|| dev_key(a).cmp(&dev_key(b)))
        .then_with(|| a.local.cmp(&b.local))
}

/// the pre-release sort key: a bare dev release precedes every pre-release of
/// the same version, and a release with no pre-release segment follows them.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum PreKey {
    BeforeAll,
    Pre(PreRelease, u64),
    AfterAll,
}

fn pre_key(v: &Pep440) -> PreKey {
    match v.pre {
        Some((kind, n)) => PreKey::Pre(kind, n),
        None if v.post.is_none() && v.dev.is_some() => PreKey::BeforeAll,
        None => PreKey::AfterAll,
    }
}

/// an absent dev segment sorts *after* any dev release, the reverse of `Option`.
fn dev_key(v: &Pep440) -> (bool, u64) {
    (v.dev.is_none(), v.dev.unwrap_or(0))
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
/// non-digits and runs of digits. non-digit runs are compared lexically in the
/// modified ordering of [`deb_order`]; digit runs are compared
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

/// convenience function: orders two version strings, returning `None` when the
/// ordering is unknown.
///
/// parses both strings with [`Version::parse_lenient`] and delegates to
/// [`Version::partial_cmp_lenient`].
pub fn compare_versions(a: &str, b: &str) -> Option<Ordering> {
    Version::parse_lenient(a).partial_cmp_lenient(&Version::parse_lenient(b))
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
        // versions with an epoch aren't semver
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
        // "5.1-3" is not valid semver (two-part base)
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
    fn parse_pep440_epoch_is_pep440() {
        match Version::parse_lenient("1!2.0") {
            Version::Pep440(p) => {
                assert_eq!(p.epoch, 1);
                assert_eq!(p.release, vec![2, 0]);
                assert_eq!(p.pre, None);
            }
            other => panic!("expected Pep440, got {:?}", other),
        }
    }

    #[test]
    fn parse_deb_keeps_epoch_bang_forms_it_declines() {
        // a Debian revision after a PEP 440 epoch is not a PEP 440 version
        match Version::parse_lenient("1!2.0-3") {
            Version::Deb {
                epoch,
                upstream,
                revision,
            } => {
                assert_eq!(epoch, 1);
                assert_eq!(upstream, "2.0");
                assert_eq!(revision, "3");
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

    #[test]
    fn deb_canonical_ordering_vectors() {
        use Ordering::{Equal, Greater, Less};

        // canonical dpkg (`verrevcmp`) orderings for the edge cases the other
        // tests don't fully pin, each `expected` derived by hand from the
        // `deb_order`/`verrevcmp` rules documented above. every string pins an
        // epoch so it forces `Deb` parsing — a bare `1.0`/`1.0~rc1` would parse
        // as Semver/Numeric and exercise the wrong comparator (see
        // `downgrade_absent_revision_equals_zero`). `expected` is how `a` orders
        // relative to `b`; the harness drives each vector through the public
        // `is_version_downgrade` in both directions.
        let cases = [
            // tilde chain: `~` < end-of-string < letters < other punctuation,
            // so 1.0~~ < 1.0~~a < 1.0~ < 1.0 < 1.0a
            ("1:1.0~~", "1:1.0~~a", Less),
            ("1:1.0~~a", "1:1.0~", Less),
            ("1:1.0~", "1:1.0", Less),
            ("1:1.0", "1:1.0a", Less),
            // tilde marks a pre-release: it sorts before the release, and
            // pre-releases order among themselves
            ("1:1.0~rc1", "1:1.0", Less),
            ("1:1.0~rc1", "1:1.0~rc2", Less),
            // digit runs compare numerically, not lexically: 10 > 9
            ("1:1.10", "1:1.9", Greater),
            // leading zeros don't change a digit run's value
            ("1:1.0", "1:1.00", Equal),
            ("1:1.01", "1:1.1", Equal),
            // a letter outranks a digit at a component boundary...
            ("1:1.a", "1:1.1", Greater),
            // ...but a continuing digit run still outranks a letter suffix
            ("1:1.0a", "1:1.01", Less),
            // epoch dominates the upstream comparison
            ("2:0.1", "1:9.9", Greater),
            // upstream is compared before the revision
            ("1:5.2-1", "1:5.1-9", Greater),
            // an absent revision compares equal to an explicit "0"
            ("1:2.0", "1:2.0-0", Equal),
            // revision digit runs are numeric too: 10 > 9
            ("1:2.0-10", "1:2.0-9", Greater),
        ];

        for (a, b, expected) in cases {
            // guard the vector: if either side stops parsing as Deb, it would
            // silently test a different comparator and prove nothing.
            assert!(
                matches!(Version::parse_lenient(a), Version::Deb { .. }),
                "{a} no longer parses as Deb"
            );
            assert!(
                matches!(Version::parse_lenient(b), Version::Deb { .. }),
                "{b} no longer parses as Deb"
            );
            match expected {
                // a < b: going b -> a is a downgrade, a -> b is not
                Less => {
                    assert!(is_version_downgrade(b, a), "expected {a} < {b}");
                    assert!(!is_version_downgrade(a, b), "expected {a} < {b}");
                }
                // a > b: going a -> b is a downgrade, b -> a is not
                Greater => {
                    assert!(is_version_downgrade(a, b), "expected {a} > {b}");
                    assert!(!is_version_downgrade(b, a), "expected {a} > {b}");
                }
                // a == b: neither direction is a downgrade
                Equal => {
                    assert!(!is_version_downgrade(a, b), "expected {a} == {b}");
                    assert!(!is_version_downgrade(b, a), "expected {a} == {b}");
                }
            }
        }
    }

    #[test]
    fn compare_orders_comparable_variant_pairs() {
        use Ordering::{Equal, Greater, Less};

        for (a, b, expected) in [
            ("2.0.0", "1.5.0", Greater),
            ("1.0.0", "1.0.0", Equal),
            ("1.2.3.4", "1.2.3.3", Greater),
            ("1.2.3", "1.2.3.4", Less),
            ("2:1.0-3", "1:9.0-1", Greater),
            ("5.1-3", "5.1-3", Equal),
        ] {
            assert_eq!(compare_versions(a, b), Some(expected), "{a} vs {b}");
            assert_eq!(
                compare_versions(b, a),
                Some(expected.reverse()),
                "{b} vs {a}"
            );
        }
    }

    #[test]
    fn compare_leaves_opaque_and_mixed_variants_unordered() {
        for (a, b) in [
            ("deadbeef", "1.0.0"),
            ("deadbeef", "cafebabe"),
            ("deadbeef", "deadbeef"),
            ("2:1.0-3", "1.0.0"),
            ("5.1-3", "5.1.0.0"),
        ] {
            assert_eq!(compare_versions(a, b), None, "{a} vs {b}");
            assert_eq!(compare_versions(b, a), None, "{b} vs {a}");
        }
    }

    // --- PEP 440 (Python) parsing and ordering ---

    #[test]
    fn parse_pep440_suffixes() {
        for s in [
            "1.0rc1",
            "1.0a1",
            "1.0b1",
            "1.0.dev1",
            "1.0.post1",
            "4.2.0rc1",
            "1!1.0",
            "1.0alpha1",
            "1.0-rc-1",
            "1.0_beta_2",
            "1.0.RC1",
            "2.0.post2.dev3",
            "1.0rc1+ubuntu.1",
        ] {
            assert!(
                matches!(Version::parse_lenient(s), Version::Pep440(_)),
                "{s} should parse as Pep440"
            );
        }
    }

    #[test]
    fn parse_pep440_fields() {
        match Version::parse_lenient("2!4.2.0.post3.dev7") {
            Version::Pep440(p) => {
                assert_eq!(p.epoch, 2);
                assert_eq!(p.release, vec![4, 2, 0]);
                assert_eq!(p.pre, None);
                assert_eq!(p.post, Some(3));
                assert_eq!(p.dev, Some(7));
                assert!(p.local.is_empty());
            }
            other => panic!("expected Pep440, got {:?}", other),
        }
    }

    #[test]
    fn parse_pep440_leaves_other_formats_alone() {
        for s in [
            "1.2.3",
            "v1.2",
            "42",
            "1.2.3-beta.1",
            "1.0.0-alpha.1+build.789",
            "0.0.0",
        ] {
            assert!(
                matches!(Version::parse_lenient(s), Version::Semver(_)),
                "{s} should still be Semver"
            );
        }
        for s in ["1.2.3.4", "2024.01.15", "01.02.03", "v1.2.3.4"] {
            assert!(
                matches!(Version::parse_lenient(s), Version::Numeric(_)),
                "{s} should still be Numeric"
            );
        }
        for s in [
            "2:1.0",
            "5.1-3",
            "2:1.2.3-4",
            "1.2-2-1",
            "1.0.0~rc1",
            "1:1.1.1f-1ubuntu2.16",
            "1.0+ubuntu.1",
        ] {
            assert!(
                matches!(Version::parse_lenient(s), Version::Deb { .. }),
                "{s} should still be Deb"
            );
        }
        for s in ["abc", "foo.bar.baz", "focal-1", "stable", "1:stable", ""] {
            assert!(
                matches!(Version::parse_lenient(s), Version::Opaque(_)),
                "{s} should still be Opaque"
            );
        }
    }

    /// asserts the strings are in strictly ascending order, every pair.
    fn assert_ascending(versions: &[&str]) {
        for (i, a) in versions.iter().enumerate() {
            for b in &versions[i + 1..] {
                assert_eq!(
                    compare_versions(a, b),
                    Some(Ordering::Less),
                    "expected {a} < {b}"
                );
                assert_eq!(
                    compare_versions(b, a),
                    Some(Ordering::Greater),
                    "expected {b} > {a}"
                );
                assert!(is_version_downgrade(b, a), "expected {b} -> {a} downgrade");
                assert!(!is_version_downgrade(a, b), "expected {a} -> {b} upgrade");
            }
        }
    }

    #[test]
    fn pep440_release_cycle_ordering() {
        assert_ascending(&[
            "1.0.dev1",
            "1.0a1",
            "1.0a2",
            "1.0b1",
            "1.0rc1",
            "1.0",
            "1.0.post1",
            "1.0.1",
        ]);
    }

    #[test]
    fn pep440_dev_ordering_within_segments() {
        assert_ascending(&["1.0.dev1", "1.0a1.dev1", "1.0a1", "1.0"]);
        assert_ascending(&["1.0", "1.0.post1.dev1", "1.0.post1"]);
    }

    #[test]
    fn pep440_epoch_ordering() {
        assert_ascending(&["2.0", "1!1.0", "1!2.0", "2!0.1"]);
    }

    #[test]
    fn pep440_spelling_aliases() {
        for (canonical, aliases) in [
            ("1.0a1", ["1.0alpha1", "1.0.ALPHA.1", "1.0-a-1"]),
            ("1.0b1", ["1.0beta1", "1.0.BETA.1", "1.0_b_1"]),
            ("1.0rc1", ["1.0c1", "1.0pre1", "1.0preview1"]),
            ("1.0.post1", ["1.0rev1", "1.0r1", "1.0-POST-1"]),
        ] {
            for alias in aliases {
                assert_eq!(
                    compare_versions(canonical, alias),
                    Some(Ordering::Equal),
                    "{alias} should normalize to {canonical}"
                );
            }
        }
        // an omitted number is an implicit 0, so 1.0rc < 1.0rc1
        assert_eq!(compare_versions("1.0rc", "1.0rc0"), Some(Ordering::Equal));
        assert_eq!(compare_versions("1.0rc", "1.0rc1"), Some(Ordering::Less));
    }

    #[test]
    fn pep440_compares_against_semver_and_numeric() {
        use Ordering::{Equal, Greater, Less};

        for (a, b, expected) in [
            // the silently-skipped transitions: one side parses Semver
            ("4.2.0rc1", "4.2.0", Less),
            ("1.0rc1", "1.0", Less),
            ("1.0.dev1", "1.0", Less),
            ("1.0", "1.0.post1", Less),
            ("1!1.0", "2.0", Greater),
            ("1.0.post1", "1.0.1", Less),
            // implicit zero padding across the two spellings of one release
            ("1.0.post0", "1.0.0.post0", Equal),
            // ...and against a four-part version, which parses Numeric
            ("1.2.3.4rc1", "1.2.3.4", Less),
            ("1.2.3.4.dev1", "1.2.3.3", Greater),
            // a semver pre-release that is also a PEP 440 pre-release
            ("1.0.0-rc1", "1.0rc2", Less),
            ("1.0.0-alpha.1", "1.0b1", Less),
        ] {
            assert_eq!(compare_versions(a, b), Some(expected), "{a} vs {b}");
            assert_eq!(
                compare_versions(b, a),
                Some(expected.reverse()),
                "{b} vs {a}"
            );
        }
    }

    #[test]
    fn pep440_local_version_ordering() {
        // a local label outranks the same version without one
        assert_ascending(&["1.0rc1", "1.0rc1+ubuntu", "1.0rc1+ubuntu.1"]);
        assert_ascending(&["1.0rc1+abc", "1.0rc1+1"]);
        assert_ascending(&["1.0rc1+build.9", "1.0rc1+build.10"]);
        assert_eq!(
            compare_versions("1.0rc1+UBUNTU-1", "1.0rc1+ubuntu.1"),
            Some(Ordering::Equal)
        );
    }

    #[test]
    fn pep440_stays_uncomparable_against_deb_and_opaque() {
        for (a, b) in [
            ("1.0rc1", "2:1.0"),
            ("1.0rc1", "1.0.0~rc1"),
            ("1.0rc1", "deadbeef"),
            // a semver pre-release with no PEP 440 reading
            ("1.0.0-foo.bar", "1.0rc1"),
        ] {
            assert_eq!(compare_versions(a, b), None, "{a} vs {b}");
            assert_eq!(compare_versions(b, a), None, "{b} vs {a}");
        }
    }

    #[test]
    fn downgrade_pep440_gate() {
        // the false positive: a normal Python pre-release progression
        assert!(!is_version_downgrade("1.0.dev1", "1.0a1"));
        assert!(is_version_downgrade("1.0a1", "1.0.dev1"));
        // the silent skips
        assert!(!is_version_downgrade("4.2.0rc1", "4.2.0"));
        assert!(is_version_downgrade("4.2.0", "4.2.0rc1"));
        assert!(!is_version_downgrade("1.0", "1.0.post1"));
        assert!(is_version_downgrade("1.0.post1", "1.0"));
        assert!(!is_version_downgrade("1.0rc1", "1.0rc1"));
    }

    #[test]
    fn downgrade_agrees_with_compare() {
        use Ordering::Greater;

        for (a, b) in [
            ("2.0.0", "1.5.0"),
            ("1.0.0", "2.0.0"),
            ("1.0.0", "1.0.0"),
            ("2024.01.15", "2024.01.14"),
            ("2:1.0-3", "1:9.0-1"),
            ("1.0.0+build.10", "1.0.0+build.9"),
            ("deadbeef", "1.0.0"),
        ] {
            assert_eq!(
                is_version_downgrade(a, b),
                compare_versions(a, b) == Some(Greater),
                "{a} -> {b}"
            );
        }
    }
}
