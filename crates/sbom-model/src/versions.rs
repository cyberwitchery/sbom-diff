//! version parsing and comparison utilities.
//!
//! provides lenient version parsing for SBOM component versions, supporting
//! semver, dot-separated numeric strings, PEP440-style qualified versions,
//! Debian/RPM-style epoch/revision versions, and opaque version strings.
//!
//! versions of different kinds are ordered through a shared
//! `(epoch, release, qualifier)` key; see [`Version::partial_cmp_lenient`] for
//! which pairs that leaves unordered.

use std::cmp::Ordering;

/// parsed version representation for lenient comparison.
///
/// covers the common version formats found in SBOMs:
/// - standard semver (possibly with `v` prefix or fewer than three parts)
/// - dot-separated numeric (e.g., date-based `2024.01.15` or four-part `1.2.3.4`)
/// - PEP440-style qualified versions (dominant on pypi, plus maven `-SNAPSHOT`)
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
    /// numeric release with a PEP440 epoch or pre/post/dev qualifier, compared
    /// with the PEP440 ordering. covers pypi versions (`1.0rc1`, `1.0.dev1`,
    /// `1!2.0`, `1.0.post1`) and the maven `-SNAPSHOT` marker.
    Pep440(Pep440),
    /// Debian/RPM-style version with an optional numeric epoch and a trailing
    /// revision, compared with the Debian `dpkg` algorithm. covers
    /// `epoch:upstream-revision` (Debian) and `epoch:version-release` (RPM). an
    /// absent epoch is `0` and an absent revision is the empty string.
    Deb {
        epoch: u64,
        upstream: String,
        revision: String,
    },
    /// non-parseable version string where ordering cannot be determined.
    Opaque(String),
}

/// a PEP440-style version: numeric release core plus optional epoch,
/// pre-release, post-release, and development-release qualifiers.
///
/// build a value with [`Version::parse_lenient`]; ordering follows PEP440's
/// `dev < alpha < beta < rc < release < post`, with maven's `-SNAPSHOT`
/// slotted between `rc` and the release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pep440 {
    epoch: u64,
    release: Vec<u64>,
    pre: Option<(PreKind, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
}

/// pre-release markers, in ascending order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PreKind {
    Alpha,
    Beta,
    Rc,
    Snapshot,
}

impl Version {
    /// parses a version string leniently.
    ///
    /// tries semver first (stripping `v`/`V` prefix and padding one- or
    /// two-part versions), then dot-separated numeric, then PEP440-style
    /// qualified versions, then Debian/RPM-style epoch/revision versions, then
    /// falls back to [`Opaque`](Version::Opaque).
    ///
    /// # Examples
    ///
    /// ```
    /// use sbom_model::versions::Version;
    ///
    /// assert!(matches!(Version::parse_lenient("1.2.3"), Version::Semver(_)));
    /// assert!(matches!(Version::parse_lenient("v1.2"), Version::Semver(_)));
    /// assert!(matches!(Version::parse_lenient("2024.01.15"), Version::Numeric(_)));
    /// assert!(matches!(Version::parse_lenient("1.0rc1"), Version::Pep440(_)));
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
            return pep;
        }

        if let Some(deb) = parse_deb(stripped) {
            return deb;
        }

        Version::Opaque(s.to_string())
    }

    /// orders two versions, returning `None` when the ordering is unknown.
    ///
    /// two versions of the same kind use that kind's native ordering:
    /// - **Semver**: semver *precedence* (including pre-release; build metadata
    ///   is ignored per SemVer §10)
    /// - **Numeric**: segment-by-segment with implicit zero padding
    /// - **Pep440**: epoch, release, then `dev < alpha < beta < rc < SNAPSHOT <
    ///   release < post` per PEP440
    /// - **Deb**: epoch, then upstream, then revision, via the Debian `dpkg`
    ///   version-comparison algorithm
    ///
    /// versions of different kinds are reduced to a common
    /// `(epoch, release, qualifier)` key: a differing epoch decides, then
    /// differing release components decide. with both equal, the qualifiers
    /// decide only when both rank on the shared `dev < pre-release < release <
    /// post-release` scale — a plain release outranks any pre-release, so
    /// `1.0.0` is [`Greater`](Ordering::Greater) than `1.0.0rc1`. an
    /// unrecognized pre-release (a semver `-next.0`, a Debian `~foo`) still
    /// ranks below a release but not against another pre-release, and a Debian
    /// upstream suffix or revision (`1.0.2k`, `5.1-3`) does not rank at all.
    ///
    /// anything unranked, and anything involving an [`Opaque`](Version::Opaque)
    /// version, is `None`.
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
    /// let release = Version::parse_lenient("1.0.0");
    /// let candidate = Version::parse_lenient("1.0.0rc1");
    /// assert_eq!(release.partial_cmp_lenient(&candidate), Some(Ordering::Greater));
    ///
    /// let opaque = Version::parse_lenient("deadbeef");
    /// assert_eq!(a.partial_cmp_lenient(&opaque), None);
    /// ```
    pub fn partial_cmp_lenient(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Version::Semver(a), Version::Semver(b)) => Some(a.cmp_precedence(b)),
            (Version::Numeric(a), Version::Numeric(b)) => Some(numeric_cmp(a, b)),
            (Version::Pep440(a), Version::Pep440(b)) => Some(a.cmp_pep440(b)),
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
            _ => cross_kind_cmp(self, other),
        }
    }

    /// reduces a version to the `(epoch, release, qualifier)` key shared by all
    /// kinds. `None` for [`Opaque`](Version::Opaque), which has no release.
    fn cross_key(&self) -> Option<(u64, Vec<u64>, Qual)> {
        match self {
            Version::Semver(v) => Some((
                0,
                vec![v.major, v.minor, v.patch],
                if v.pre.is_empty() {
                    Qual::Release
                } else {
                    Qual::UnrankedPre
                },
            )),
            Version::Numeric(segments) => Some((0, segments.clone(), Qual::Release)),
            Version::Pep440(p) => Some((p.epoch, p.release.clone(), p.qual())),
            Version::Deb {
                epoch,
                upstream,
                revision,
            } => {
                let (release, suffix) = split_release(upstream)?;
                let qual = if suffix.starts_with('~') {
                    Qual::UnrankedPre
                } else if !suffix.is_empty() || !revision.is_empty() {
                    Qual::Unranked
                } else {
                    Qual::Release
                };
                Some((*epoch, release, qual))
            }
            Version::Opaque(_) => None,
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

/// where a version sits on the release scale shared by every scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Qual {
    Dev(u64),
    Pre(PreKind, u64),
    /// a pre-release marker no scheme-independent rank applies to.
    UnrankedPre,
    Release,
    Post(u64),
    /// a suffix whose meaning is scheme-specific (a Debian upstream suffix or
    /// revision), so it orders against nothing outside its own scheme.
    Unranked,
}

impl Qual {
    fn rank(self) -> u8 {
        match self {
            Qual::Dev(_) => 0,
            Qual::Pre(..) => 1,
            Qual::UnrankedPre => 2,
            Qual::Release => 3,
            Qual::Post(_) => 4,
            Qual::Unranked => 5,
        }
    }
}

/// orders two versions of different kinds through [`Version::cross_key`].
fn cross_kind_cmp(a: &Version, b: &Version) -> Option<Ordering> {
    let (a_epoch, a_release, a_qual) = a.cross_key()?;
    let (b_epoch, b_release, b_qual) = b.cross_key()?;
    match a_epoch
        .cmp(&b_epoch)
        .then_with(|| numeric_cmp(&a_release, &b_release))
    {
        Ordering::Equal => qual_cmp(a_qual, b_qual),
        decided => Some(decided),
    }
}

/// orders two qualifiers of versions that share an epoch and release.
fn qual_cmp(a: Qual, b: Qual) -> Option<Ordering> {
    match (a, b) {
        (Qual::Unranked, _) | (_, Qual::Unranked) => None,
        // an unranked pre-release precedes its release but not another pre-release
        (Qual::UnrankedPre, Qual::UnrankedPre | Qual::Dev(_) | Qual::Pre(..))
        | (Qual::Dev(_) | Qual::Pre(..), Qual::UnrankedPre) => None,
        (Qual::Dev(x), Qual::Dev(y)) | (Qual::Post(x), Qual::Post(y)) => Some(x.cmp(&y)),
        (Qual::Pre(xk, x), Qual::Pre(yk, y)) => Some(xk.cmp(&yk).then(x.cmp(&y))),
        _ => Some(a.rank().cmp(&b.rank())),
    }
}

impl Pep440 {
    /// PEP440 ordering: epoch, release, then the pre/post/dev sort keys.
    fn cmp_pep440(&self, other: &Self) -> Ordering {
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| numeric_cmp(&self.release, &other.release))
            .then_with(|| self.pre_key().cmp(&other.pre_key()))
            .then_with(|| self.post_key().cmp(&other.post_key()))
            .then_with(|| self.dev_key().cmp(&other.dev_key()))
    }

    /// a development release with no pre- or post-release marker sorts before
    /// every pre-release; an absent marker on any other version sorts after.
    fn pre_key(&self) -> (i8, PreKind, u64) {
        match self.pre {
            Some((kind, n)) => (0, kind, n),
            None if self.post.is_none() && self.dev.is_some() => (-1, PreKind::Alpha, 0),
            None => (1, PreKind::Alpha, 0),
        }
    }

    fn post_key(&self) -> (u8, u64) {
        self.post.map_or((0, 0), |n| (1, n))
    }

    fn dev_key(&self) -> (u8, u64) {
        self.dev.map_or((1, 0), |n| (0, n))
    }

    fn qual(&self) -> Qual {
        match (self.pre, self.post, self.dev) {
            (Some((kind, n)), _, _) => Qual::Pre(kind, n),
            (None, Some(n), _) => Qual::Post(n),
            (None, None, Some(n)) => Qual::Dev(n),
            (None, None, None) => Qual::Release,
        }
    }
}

/// parses a PEP440-style version: an optional `N!` epoch, a numeric release,
/// and any number of pre/post/dev markers.
///
/// returns `None` for anything the markers don't fully explain, leaving Debian
/// shapes (`1.0.2k`, `5.1-3`, `1.0~rc1`) to [`parse_deb`], and `None` for a
/// plain numeric release, leaving it to the semver and numeric parsers.
fn parse_pep440(stripped: &str) -> Option<Version> {
    let (epoch, rest) = split_pep440_epoch(stripped);
    let (release, mut rest) = split_release(rest)?;
    let (mut pre, mut post, mut dev) = (None, None, None);

    while !rest.is_empty() {
        let body = rest.strip_prefix(['.', '-', '_']).unwrap_or(rest);
        let (marker, n, tail) = take_marker(body)?;
        match marker {
            Marker::Pre(kind) if pre.is_none() && post.is_none() && dev.is_none() => {
                pre = Some((kind, n));
            }
            Marker::Post if post.is_none() && dev.is_none() => post = Some(n),
            Marker::Dev if dev.is_none() => dev = Some(n),
            _ => return None,
        }
        rest = tail;
    }

    if epoch == 0 && pre.is_none() && post.is_none() && dev.is_none() {
        return None;
    }
    Some(Version::Pep440(Pep440 {
        epoch,
        release,
        pre,
        post,
        dev,
    }))
}

/// splits a leading `N!` PEP440 epoch off a version string.
fn split_pep440_epoch(s: &str) -> (u64, &str) {
    if let Some((head, tail)) = s.split_once('!') {
        if let Ok(epoch) = head.parse::<u64>() {
            return (epoch, tail);
        }
    }
    (0, s)
}

/// splits a leading dot-separated numeric release off a version string,
/// returning it with the remaining suffix. `None` when there is no leading
/// digit or a segment overflows.
fn split_release(s: &str) -> Option<(Vec<u64>, &str)> {
    let mut release = Vec::new();
    let mut rest = s;
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
            Some(next) if next.starts_with(|c: char| c.is_ascii_digit()) => rest = next,
            _ => return Some((release, rest)),
        }
    }
}

#[derive(Clone, Copy)]
enum Marker {
    Pre(PreKind),
    Post,
    Dev,
}

/// markers, longest first so `preview` wins over `pre` and `beta` over `b`. the
/// single-letter aliases require a following digit: `0.9.8b` is an upstream
/// patch letter, which dpkg sorts *above* `0.9.8`.
const MARKERS: &[(&str, Marker, bool)] = &[
    ("snapshot", Marker::Pre(PreKind::Snapshot), false),
    ("preview", Marker::Pre(PreKind::Rc), false),
    ("alpha", Marker::Pre(PreKind::Alpha), false),
    ("beta", Marker::Pre(PreKind::Beta), false),
    ("post", Marker::Post, false),
    ("dev", Marker::Dev, false),
    ("pre", Marker::Pre(PreKind::Rc), false),
    ("rc", Marker::Pre(PreKind::Rc), false),
    ("a", Marker::Pre(PreKind::Alpha), true),
    ("b", Marker::Pre(PreKind::Beta), true),
    ("c", Marker::Pre(PreKind::Rc), true),
];

/// consumes one marker and its optional ordinal, returning the rest.
fn take_marker(body: &str) -> Option<(Marker, u64, &str)> {
    let lower = body.to_ascii_lowercase();
    for (word, marker, needs_ordinal) in MARKERS {
        let Some(tail) = lower.strip_prefix(word) else {
            continue;
        };
        let tail = &body[body.len() - tail.len()..];
        let end = tail
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(tail.len());
        if *needs_ordinal && end == 0 {
            continue;
        }
        let ordinal = if end == 0 {
            0
        } else {
            tail[..end].parse::<u64>().ok()?
        };
        return Some((*marker, ordinal, &tail[end..]));
    }
    None
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
        assert!(matches!(
            Version::parse_lenient("1!2.0"),
            Version::Pep440(_)
        ));
        assert_eq!(compare_versions("1!2.0", "1!3.0"), Some(Ordering::Less));
        assert_eq!(compare_versions("1!2.0", "9.9.9"), Some(Ordering::Greater));
        assert_eq!(compare_versions("1!2.0", "1:2.0"), Some(Ordering::Equal));
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
    fn downgrade_deb_vs_semver_epoch_dominates() {
        assert!(is_version_downgrade("2:1.0", "1.0.0"));
        assert!(!is_version_downgrade("1.0.0", "2:1.0"));
        assert!(is_version_downgrade("2:1.0", "0:1.0.0"));
    }

    #[test]
    fn downgrade_deb_vs_semver_release_decides() {
        assert!(is_version_downgrade("1.1.1f-1", "1.0.0"));
        assert!(!is_version_downgrade("1.0.0", "1.1.1f-1"));
    }

    #[test]
    fn downgrade_deb_suffix_vs_semver_not_flagged() {
        assert_eq!(compare_versions("1.0.2k", "1.0.2"), None);
        assert_eq!(compare_versions("5.1-3", "5.1.0"), None);
        assert!(!is_version_downgrade("1.0.2k", "1.0.2"));
        assert!(!is_version_downgrade("5.1-3", "5.1.0"));
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

    // --- PEP440 parsing and ordering ---

    #[test]
    fn parse_pep440_shapes() {
        for s in [
            "1.0rc1",
            "1.0.0rc1",
            "1.0a1",
            "1.0b2",
            "1.0c1",
            "1.0.dev1",
            "1.0a1.dev1",
            "1.0.post1",
            "1.0-alpha",
            "1.0_beta2",
            "1.0-SNAPSHOT",
            "1.0preview1",
            "1!2.0",
        ] {
            assert!(
                matches!(Version::parse_lenient(s), Version::Pep440(_)),
                "{s} did not parse as Pep440"
            );
        }
    }

    #[test]
    fn parse_pep440_leaves_debian_shapes_alone() {
        for s in ["1.0~rc1", "5.1-3", "1.0.2k", "0.9.8b", "1:1.0", "1.2-2-1"] {
            assert!(
                matches!(Version::parse_lenient(s), Version::Deb { .. }),
                "{s} was taken from the Debian parser"
            );
        }
    }

    #[test]
    fn pep440_stage_ordering() {
        use Ordering::Less;

        // PEP440 §"summary of permitted suffixes": dev < a < b < rc < release < post
        for (a, b) in [
            ("1.0.dev1", "1.0a1"),
            ("1.0a1.dev1", "1.0a1"),
            ("1.0a1", "1.0b1"),
            ("1.0b1", "1.0rc1"),
            ("1.0rc1", "1.0.post1"),
            ("1.0.post1.dev1", "1.0.post1"),
            ("1.0rc1", "1.0rc2"),
            ("1.0.dev1", "1.0.dev2"),
            ("1.0.post1", "1.0.post2"),
            // maven puts SNAPSHOT after every qualifier but before the release
            ("1.0rc1", "1.0-SNAPSHOT"),
        ] {
            assert_eq!(compare_versions(a, b), Some(Less), "{a} vs {b}");
            assert!(is_version_downgrade(b, a), "{b} -> {a}");
            assert!(!is_version_downgrade(a, b), "{a} -> {b}");
        }
    }

    #[test]
    fn pep440_aliases_and_case_are_equivalent() {
        for (a, b) in [
            ("1.0a1", "1.0alpha1"),
            ("1.0b1", "1.0beta1"),
            ("1.0c1", "1.0rc1"),
            ("1.0rc1", "1.0preview1"),
            ("1.0rc1", "1.0-RC1"),
            ("1.0-SNAPSHOT", "1.0-snapshot"),
            ("1.0rc1", "1.0.rc1"),
            ("1.0rc1", "1.0_rc1"),
            ("1.0rc", "1.0rc0"),
        ] {
            assert_eq!(compare_versions(a, b), Some(Ordering::Equal), "{a} vs {b}");
        }
    }

    #[test]
    fn pep440_epoch_dominates_release() {
        assert_eq!(compare_versions("1!1.0", "9.9.9"), Some(Ordering::Greater));
        assert!(is_version_downgrade("1!1.0", "2.0.0"));
        assert!(!is_version_downgrade("2.0.0", "1!1.0"));
    }

    // --- cross-kind ordering ---

    #[test]
    fn downgrade_release_to_prerelease_across_kinds() {
        for (release, candidate) in [
            ("1.0.0", "1.0.0rc1"),
            ("2.0.0", "2.0.0rc1"),
            ("1.0", "1.0.dev1"),
            ("1.0", "1.0-SNAPSHOT"),
            ("1.0.0", "1.0-alpha"),
            ("1.0.0.0", "1.0.0-beta.1"),
            ("1.0.0", "1.0.0~rc1"),
            ("1.2.3", "1.2.3-next.0"),
        ] {
            assert!(
                is_version_downgrade(release, candidate),
                "{release} -> {candidate} not flagged"
            );
            assert!(
                !is_version_downgrade(candidate, release),
                "{candidate} -> {release} wrongly flagged"
            );
        }
    }

    #[test]
    fn cross_kind_post_release_outranks_release() {
        assert_eq!(
            compare_versions("1.0.post1", "1.0.0"),
            Some(Ordering::Greater)
        );
        assert!(is_version_downgrade("1.0.post1", "1.0.0"));
        assert!(!is_version_downgrade("1.0.0", "1.0.post1"));
    }

    #[test]
    fn cross_kind_release_components_decide_first() {
        for (a, b) in [
            ("2.0.0", "1.0.0rc1"),
            ("2.0.0rc1", "1.0.0"),
            ("1.0.2k", "1.0.1"),
            ("1.0.2k", "1.0.post1"),
            ("2024.01.15", "2023.1.0rc1"),
            ("1.2.3.4", "1.2.3rc1"),
        ] {
            assert_eq!(
                compare_versions(a, b),
                Some(Ordering::Greater),
                "{a} vs {b}"
            );
        }
    }

    #[test]
    fn cross_kind_unrecognized_prereleases_stay_unordered() {
        for (a, b) in [
            ("1.0.0-next.0", "1.0.0rc1"),
            ("1.0~rc1", "1.0rc1"),
            ("1.0~rc1", "1.0.dev1"),
            ("1.0.0-beta.1", "1.0-SNAPSHOT"),
        ] {
            assert_eq!(compare_versions(a, b), None, "{a} vs {b}");
            assert!(!is_version_downgrade(a, b));
            assert!(!is_version_downgrade(b, a));
        }
    }

    #[test]
    fn cross_kind_semver_prerelease_beats_numeric() {
        assert_eq!(
            compare_versions("1.0.0.0", "1.0.0-beta.1"),
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare_versions("1.0.0-beta.1", "1.0.0.0"),
            Some(Ordering::Less)
        );
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
            ("1.2.3.RELEASE", "1.2.3"),
            ("5.1-3", "5.1.0.0"),
            ("1.0.0-next.0", "1.0rc1"),
            ("1.0~rc1", "1.0rc1"),
        ] {
            assert_eq!(compare_versions(a, b), None, "{a} vs {b}");
            assert_eq!(compare_versions(b, a), None, "{b} vs {a}");
        }
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
