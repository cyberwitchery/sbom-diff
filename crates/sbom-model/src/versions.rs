//! version parsing and comparison utilities.
//!
//! provides lenient version parsing for SBOM component versions, supporting
//! semver, dot-separated numeric strings, PEP 440 (Python) versions,
//! Debian and RPM epoch/revision versions, Maven (Java) versions, NuGet
//! (.NET) versions, and opaque version strings.
//!
//! two entry points parse a version string: [`Version::parse_lenient`] infers
//! the format from the string alone, and [`Version::parse_for_ecosystem`]
//! applies the rules of the component's ecosystem. inference cannot separate a
//! Debian revision from a semver pre-release — `1.2.3-1ubuntu2` and
//! `1.0.0-alpha.1` are the same shape, ordered in opposite directions — so
//! callers that know the ecosystem should pass it. the same holds for PEP 440:
//! `1.0.2a` is a Python pre-release and a Debian upstream version, ordered on
//! opposite sides of `1.0.2`.

use std::cmp::Ordering;

/// parsed version representation for lenient comparison.
///
/// covers the common version formats found in SBOMs:
/// - standard semver (possibly with `v` prefix or fewer than three parts)
/// - dot-separated numeric (e.g., date-based `2024.01.15` or four-part `1.2.3.4`)
/// - PEP 440 pre/post/dev releases and epochs (dominant in Python SBOMs)
/// - Debian `epoch:upstream-revision` and RPM `epoch:version-release` (dominant
///   in OS/container SBOMs)
/// - Maven versions, whose qualifiers (`1.0-SNAPSHOT`, `2.0-rc1`) look like
///   semver pre-releases but are ranked by a named order
/// - NuGet versions, which carry a fourth numeric field and compare their
///   release labels case-insensitively
/// - opaque strings that cannot be compared
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version {
    /// parseable as semver (with lenient parsing: `v`/`V` prefix stripped,
    /// one- or two-part versions padded to three parts).
    Semver(semver::Version),
    /// dot-separated numeric segments that don't qualify as semver
    /// (e.g., four-part versions or versions with leading zeros).
    Numeric(Vec<u64>),
    /// PEP 440 (Python) version, ordered per the PEP. inference produces this
    /// variant only for a version carrying an epoch, pre-release, post-release
    /// or dev-release segment;
    /// [`parse_for_ecosystem`](Version::parse_for_ecosystem) produces it for
    /// every `pypi` version, including a plain release and the spellings a
    /// Debian version shares (`1.0.2a`, `1.0-1`).
    Pep440(Pep440),
    /// Debian-style `epoch:upstream-revision` version, compared with the Debian
    /// `dpkg` algorithm. a `N!` epoch prefix is accepted too, for strings
    /// [`Pep440`](Version::Pep440) declines. an absent epoch is `0` and an
    /// absent revision is the empty string.
    Deb {
        epoch: u64,
        upstream: String,
        revision: String,
    },
    /// RPM `epoch:version-release`, compared with rpm's own `rpmvercmp`
    /// algorithm, which disagrees with the Debian one on ordinary inputs. an
    /// absent epoch is `0`; an absent release is the empty string and sorts
    /// below every release, including `0`. only
    /// [`parse_for_ecosystem`](Version::parse_for_ecosystem) produces this
    /// variant — the shape alone does not distinguish an RPM version from a
    /// Debian one.
    Rpm {
        epoch: u64,
        version: String,
        release: String,
    },
    /// Maven (Java) version, compared with Maven's own version-order algorithm,
    /// under which `1.0-SNAPSHOT` sorts below `1.0` but `1.0-sp` above it. only
    /// [`parse_for_ecosystem`](Version::parse_for_ecosystem) produces this
    /// variant — the shape alone does not distinguish a Maven qualifier from a
    /// semver pre-release or a Debian revision.
    Maven(String),
    /// NuGet (.NET) version `major.minor.patch[.revision][-release][+metadata]`,
    /// compared with NuGet.Versioning's rules: four numeric fields, an absent
    /// one being `0`, then dot-separated release labels compared
    /// case-insensitively. build metadata is not kept: NuGet ignores it for
    /// both ordering and equality. only
    /// [`parse_for_ecosystem`](Version::parse_for_ecosystem) produces this
    /// variant — the shape alone does not distinguish a NuGet release label
    /// from a semver pre-release.
    Nuget {
        version: [u64; 4],
        release: Vec<String>,
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
    /// Debian-style epoch/revision versions, then falls back to
    /// [`Opaque`](Version::Opaque).
    ///
    /// the shape alone does not always identify the format; when the
    /// component's ecosystem is known, prefer
    /// [`parse_for_ecosystem`](Self::parse_for_ecosystem).
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
        let stripped = strip_v_prefix(s);

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

        if let Some(pep) = parse_pep440(stripped, Pep440Grammar::Unambiguous) {
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

    /// parses a version string with the rules of the ecosystem it came from.
    ///
    /// `ecosystem` is a purl package type (the value of
    /// [`Component::ecosystem`](crate::Component::ecosystem)). `None`, or a type
    /// with no dedicated ruleset, is exactly [`parse_lenient`](Self::parse_lenient).
    ///
    /// `deb` versions are read as [`Deb`](Version::Deb) and ordered by the
    /// `dpkg` algorithm, `rpm` versions as [`Rpm`](Version::Rpm) and ordered by
    /// rpm's `rpmvercmp`, `maven` versions as [`Maven`](Version::Maven) and
    /// ordered by Maven's version-order algorithm, `nuget` versions as
    /// [`Nuget`](Version::Nuget) and ordered by NuGet.Versioning's rules, and
    /// `pypi` versions as [`Pep440`](Version::Pep440) and ordered by PEP 440. a
    /// leading `v`/`V` is stripped, as [`parse_lenient`](Self::parse_lenient)
    /// does; a string that is still not a valid version for that ecosystem is
    /// [`Opaque`](Version::Opaque) rather than being retried as semver.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::cmp::Ordering;
    /// use sbom_model::versions::Version;
    ///
    /// // `1ubuntu2` is a Debian revision, not a semver pre-release
    /// let old = Version::parse_for_ecosystem(Some("deb"), "1.2.3-1ubuntu2");
    /// let new = Version::parse_for_ecosystem(Some("deb"), "1.2.3-2");
    /// assert_eq!(old.partial_cmp_lenient(&new), Some(Ordering::Less));
    ///
    /// // rpm ranks a numeric segment above an alpha one, dpkg the other way
    /// let old = Version::parse_for_ecosystem(Some("rpm"), "1.a");
    /// let new = Version::parse_for_ecosystem(Some("rpm"), "1.1");
    /// assert_eq!(old.partial_cmp_lenient(&new), Some(Ordering::Less));
    ///
    /// // a Maven snapshot precedes its release, and `sp` follows it
    /// let snapshot = Version::parse_for_ecosystem(Some("maven"), "1.0-SNAPSHOT");
    /// let release = Version::parse_for_ecosystem(Some("maven"), "1.0");
    /// let patched = Version::parse_for_ecosystem(Some("maven"), "1.0-sp1");
    /// assert_eq!(snapshot.partial_cmp_lenient(&release), Some(Ordering::Less));
    /// assert_eq!(patched.partial_cmp_lenient(&release), Some(Ordering::Greater));
    ///
    /// // NuGet compares release labels case-insensitively, and the fourth
    /// // field outranks the release
    /// let preview = Version::parse_for_ecosystem(Some("nuget"), "5.0.0-preview.1");
    /// let rc = Version::parse_for_ecosystem(Some("nuget"), "5.0.0-RC.1");
    /// let revision = Version::parse_for_ecosystem(Some("nuget"), "5.0.0.1");
    /// assert_eq!(preview.partial_cmp_lenient(&rc), Some(Ordering::Less));
    /// assert_eq!(rc.partial_cmp_lenient(&revision), Some(Ordering::Less));
    ///
    /// // `1.0.2a` is PEP 440's `1.0.2a0`, a pre-release below its release
    /// let pre = Version::parse_for_ecosystem(Some("pypi"), "1.0.2a");
    /// let release = Version::parse_for_ecosystem(Some("pypi"), "1.0.2");
    /// assert_eq!(pre.partial_cmp_lenient(&release), Some(Ordering::Less));
    ///
    /// let guessed = Version::parse_for_ecosystem(None, "1.2.3-1ubuntu2");
    /// assert_eq!(guessed, Version::parse_lenient("1.2.3-1ubuntu2"));
    /// ```
    pub fn parse_for_ecosystem(ecosystem: Option<&str>, s: &str) -> Self {
        match Scheme::for_ecosystem(ecosystem) {
            Scheme::Infer => Version::parse_lenient(s),
            Scheme::Deb => parse_deb(s)
                .or_else(|| parse_deb(strip_v_prefix(s)))
                .unwrap_or_else(|| Version::Opaque(s.to_string())),
            Scheme::Rpm => parse_rpm(s)
                .or_else(|| parse_rpm(strip_v_prefix(s)))
                .unwrap_or_else(|| Version::Opaque(s.to_string())),
            Scheme::Maven => parse_maven(s)
                .or_else(|| parse_maven(strip_v_prefix(s)))
                .unwrap_or_else(|| Version::Opaque(s.to_string())),
            Scheme::Nuget => parse_nuget(s)
                .or_else(|| parse_nuget(strip_v_prefix(s)))
                .unwrap_or_else(|| Version::Opaque(s.to_string())),
            Scheme::Pypi => parse_pep440(s, Pep440Grammar::Full)
                .or_else(|| parse_pep440(strip_v_prefix(s), Pep440Grammar::Full))
                .map(Version::Pep440)
                .unwrap_or_else(|| Version::Opaque(s.to_string())),
        }
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
    /// - **Rpm vs Rpm**: epoch (numeric), then version, then release, via rpm's
    ///   `rpmvercmp` algorithm
    /// - **Maven vs Maven**: item by item, via Maven's version-order algorithm.
    ///   a version nesting past the parser's depth cap is declined
    /// - **Nuget vs Nuget**: the four numeric fields, then a version carrying
    ///   release labels below one that carries none, then the labels
    /// - **Pep440 against Pep440, Semver or Numeric** (either direction): the
    ///   other side is read as a PEP 440 version and both are ordered per PEP
    ///   440. a semver pre-release that isn't a PEP 440 suffix (say
    ///   `1.0.0-foo.bar`) has no PEP 440 reading, so that pair stays `None`
    /// - **Any other pair** (including any Opaque, any two of Deb, Rpm, Maven
    ///   and Nuget, or any of them against a semver/numeric/PEP 440 version):
    ///   `None`
    ///
    /// deliberately weaker than [`PartialOrd`]: even two identical
    /// [`Opaque`](Version::Opaque) versions compare `None`.
    ///
    /// which arm applies depends on how each side was parsed:
    /// [`parse_for_ecosystem`](Self::parse_for_ecosystem) puts both sides of a
    /// known ecosystem in the same variant, where
    /// [`parse_lenient`](Self::parse_lenient) can infer different ones.
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
            (
                Version::Rpm {
                    epoch: ae,
                    version: av,
                    release: arel,
                },
                Version::Rpm {
                    epoch: be,
                    version: bv,
                    release: brel,
                },
            ) => Some(rpm_cmp((*ae, av, arel), (*be, bv, brel))),
            (Version::Maven(a), Version::Maven(b)) => maven_cmp(a, b),
            (
                Version::Nuget {
                    version: av,
                    release: arel,
                },
                Version::Nuget {
                    version: bv,
                    release: brel,
                },
            ) => Some(nuget_cmp((av, arel), (bv, brel))),
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

/// the ruleset [`Version::parse_for_ecosystem`] reads a string with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Infer,
    Deb,
    Rpm,
    Maven,
    Nuget,
    Pypi,
}

impl Scheme {
    fn for_ecosystem(ecosystem: Option<&str>) -> Self {
        match ecosystem {
            Some(e) if e.eq_ignore_ascii_case("deb") => Scheme::Deb,
            Some(e) if e.eq_ignore_ascii_case("rpm") => Scheme::Rpm,
            Some(e) if e.eq_ignore_ascii_case("maven") => Scheme::Maven,
            Some(e) if e.eq_ignore_ascii_case("nuget") => Scheme::Nuget,
            Some(e) if e.eq_ignore_ascii_case("pypi") => Scheme::Pypi,
            _ => Scheme::Infer,
        }
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

/// how much of PEP 440's grammar to accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pep440Grammar {
    /// the whole PEP, for a version already known to be Python.
    Full,
    /// only the spellings no other ecosystem writes the same way. the implicit
    /// post-release form (`1.0-1`) and the bare single-letter suffix
    /// (`1.0.2a`, `2024h`, `1.1.1a-r0`) are declined: both are
    /// indistinguishable from a Debian upstream version.
    Unambiguous,
}

/// parses a PEP 440 version, returning `None` for anything the `grammar` does
/// not accept, so Debian and opaque strings fall through to the next strategy.
fn parse_pep440(s: &str, grammar: Pep440Grammar) -> Option<Pep440> {
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

    let (pre, rest) = match take_segment(rest, &PRE_ALIASES, grammar) {
        Some((kind, n, rest)) => (Some((kind, n)), rest),
        None => (None, rest),
    };
    let (post, rest) = match take_segment(rest, &POST_ALIASES, grammar) {
        Some((_, n, rest)) => (Some(n), rest),
        None => take_implicit_post(rest, grammar),
    };
    let (dev, rest) = match take_segment(rest, &DEV_ALIASES, grammar) {
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
fn take_segment<'a, T: Copy>(
    s: &'a str,
    aliases: &[(&str, T)],
    grammar: Pep440Grammar,
) -> Option<(T, u64, &'a str)> {
    let body = s.strip_prefix(['-', '_', '.']).unwrap_or(s);
    let (name, tag, rest) = aliases
        .iter()
        .find_map(|(name, tag)| Some((*name, *tag, body.strip_prefix(*name)?)))?;
    let digits = rest.strip_prefix(['-', '_', '.']).unwrap_or(rest);
    let end = digits
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(digits.len());
    let n = match end {
        0 if name.len() == 1 && grammar == Pep440Grammar::Unambiguous => return None,
        0 => 0,
        _ => digits[..end].parse::<u64>().ok()?,
    };
    Some((tag, n, &digits[end..]))
}

/// consumes PEP 440's implicit post-release suffix, a bare `-<number>`.
fn take_implicit_post(s: &str, grammar: Pep440Grammar) -> (Option<u64>, &str) {
    if grammar == Pep440Grammar::Unambiguous {
        return (None, s);
    }
    let Some(digits) = s.strip_prefix('-') else {
        return (None, s);
    };
    let end = digits
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(digits.len());
    match digits[..end].parse::<u64>() {
        Ok(n) => (Some(n), &digits[end..]),
        Err(_) => (None, s),
    }
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
        Version::Semver(s) => parse_pep440(
            &format!("{}.{}.{}-{}", s.major, s.minor, s.patch, s.pre),
            Pep440Grammar::Unambiguous,
        ),
        Version::Deb { .. }
        | Version::Rpm { .. }
        | Version::Maven(_)
        | Version::Nuget { .. }
        | Version::Opaque(_) => None,
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

/// strips a leading `v`/`V` version prefix.
fn strip_v_prefix(s: &str) -> &str {
    s.strip_prefix('v')
        .or_else(|| s.strip_prefix('V'))
        .unwrap_or(s)
}

/// parses a Debian-style `epoch:upstream-revision` version.
///
/// returns `None` for strings that don't look like a comparable package
/// version — the upstream part must start with a digit (the Debian convention)
/// and every character must be in the Debian version alphabet — so that
/// codenames, git hashes, and other genuinely opaque strings stay
/// [`Opaque`](Version::Opaque) rather than being force-ordered.
fn parse_deb(s: &str) -> Option<Version> {
    let (epoch, rest) = split_epoch(s, &[':', '!']);

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

/// splits a leading numeric epoch, delimited by any of `seps` (`:` for Debian
/// and RPM, `!` for PEP 440), off a version string. returns `(0, s)` when there
/// is no numeric epoch prefix.
fn split_epoch<'a>(s: &'a str, seps: &[char]) -> (u64, &'a str) {
    if let Some(idx) = s.find(seps) {
        let (head, tail) = s.split_at(idx);
        if !head.is_empty() && head.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(epoch) = head.parse::<u64>() {
                return (epoch, &tail[1..]);
            }
        }
    }
    (0, s)
}

/// characters permitted in a Debian upstream version or revision.
fn is_deb_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-' | '~' | ':')
}

/// orders two Debian-style versions given as `(epoch, upstream, revision)`:
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
/// algorithm used for Debian upstream versions and revisions; RPM versions are
/// ordered by [`rpmvercmp`] instead, which disagrees with it.
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

/// parses an RPM `epoch:version-release` version.
///
/// returns `None` on the same grounds as [`parse_deb`]: the version must start
/// with a digit and every character must be in the RPM version alphabet, so
/// codenames, git hashes and other genuinely opaque strings stay
/// [`Opaque`](Version::Opaque) rather than being force-ordered.
fn parse_rpm(s: &str) -> Option<Version> {
    let (epoch, rest) = split_epoch(s, &[':']);

    if !rest.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    if !rest.chars().all(is_rpm_char) {
        return None;
    }

    // rpm's `parseEVR` splits the release at the last hyphen, as dpkg does
    let (version, release) = match rest.rfind('-') {
        Some(idx) => (rest[..idx].to_string(), rest[idx + 1..].to_string()),
        None => (rest.to_string(), String::new()),
    };

    Some(Version::Rpm {
        epoch,
        version,
        release,
    })
}

/// characters permitted in an RPM version or release. wider than
/// [`is_deb_char`]: `_` is an ordinary separator in RPM versions and `^` marks a
/// post-release snapshot.
fn is_rpm_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-' | '~' | ':' | '_' | '^')
}

/// orders two RPM versions given as `(epoch, version, release)`: a higher epoch
/// always wins; ties fall through to the version and then the release, both
/// compared with [`rpmvercmp`].
fn rpm_cmp(a: (u64, &str, &str), b: (u64, &str, &str)) -> Ordering {
    a.0.cmp(&b.0)
        .then_with(|| rpmvercmp(a.1, b.1))
        .then_with(|| rpmvercmp(a.2, b.2))
}

/// rpm's own version-component comparison (`rpmvercmp`).
///
/// the two strings are scanned in lockstep, skipping separators on each side
/// independently, so `1.0` and `1_0` are equal. `~` sorts before everything,
/// including the end of a string; `^` sorts after the end of a string but
/// before any longer continuation, so `1.0 < 1.0^ < 1.0.1`. otherwise each side
/// yields its leading run of digits or of letters: a digit run outranks a letter
/// run, two digit runs compare with leading zeros stripped and the longer run
/// winning, and two letter runs compare bytewise. running out of string first
/// loses.
fn rpmvercmp(a: &str, b: &str) -> Ordering {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let mut i = 0;
    let mut j = 0;

    while i < a.len() || j < b.len() {
        while i < a.len() && is_rpm_separator(a[i]) {
            i += 1;
        }
        while j < b.len() && is_rpm_separator(b[j]) {
            j += 1;
        }

        if a.get(i) == Some(&b'~') || b.get(j) == Some(&b'~') {
            if a.get(i) != Some(&b'~') {
                return Ordering::Greater;
            }
            if b.get(j) != Some(&b'~') {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }

        if a.get(i) == Some(&b'^') || b.get(j) == Some(&b'^') {
            if i == a.len() {
                return Ordering::Less;
            }
            if j == b.len() {
                return Ordering::Greater;
            }
            if a.get(i) != Some(&b'^') {
                return Ordering::Greater;
            }
            if b.get(j) != Some(&b'^') {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }

        if i == a.len() || j == b.len() {
            break;
        }

        let numeric = a[i].is_ascii_digit();
        let a_end = run_end(a, i, numeric);
        let b_end = run_end(b, j, numeric);
        // an empty run on the other side means different kinds; the digit wins
        if b_end == j {
            return if numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }

        let mut x = &a[i..a_end];
        let mut y = &b[j..b_end];
        if numeric {
            x = strip_leading_zeros(x);
            y = strip_leading_zeros(y);
            if x.len() != y.len() {
                return x.len().cmp(&y.len());
            }
        }
        match x.cmp(y) {
            Ordering::Equal => {}
            ord => return ord,
        }

        i = a_end;
        j = b_end;
    }

    match (i == a.len(), j == b.len()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        _ => Ordering::Greater,
    }
}

/// bytes [`rpmvercmp`] skips: anything that is not alphanumeric, `~` or `^`.
fn is_rpm_separator(c: u8) -> bool {
    !(c.is_ascii_alphanumeric() || matches!(c, b'~' | b'^'))
}

/// the end of the run of digits (or, when `numeric` is false, of letters)
/// starting at `from`.
fn run_end(s: &[u8], from: usize, numeric: bool) -> usize {
    let in_run = |c: &&u8| {
        if numeric {
            c.is_ascii_digit()
        } else {
            c.is_ascii_alphabetic()
        }
    };
    from + s[from..].iter().take_while(in_run).count()
}

/// drops a digit run's leading zeros, leaving an all-zero run empty.
fn strip_leading_zeros(s: &[u8]) -> &[u8] {
    let zeros = s.iter().take_while(|&&c| c == b'0').count();
    &s[zeros..]
}

/// parses a Maven version.
///
/// returns `None` on the same grounds as [`parse_deb`]: the version must start
/// with a digit and every character must be in the Maven version alphabet, so
/// codenames like `RELEASE`, git hashes and other genuinely opaque strings stay
/// [`Opaque`](Version::Opaque) rather than being force-ordered. a version whose
/// item tree nests past [`MAVEN_MAX_DEPTH`] is declined the same way.
fn parse_maven(s: &str) -> Option<Version> {
    if !s.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    if !s.chars().all(is_maven_char) {
        return None;
    }
    maven_parse(s)?;

    Some(Version::Maven(s.to_string()))
}

/// characters permitted in a Maven version. wider than [`is_deb_char`]: `_` is
/// a Maven separator, and non-ASCII letters and digits are ordinary qualifier
/// characters.
fn is_maven_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | '+')
}

/// one node of a parsed Maven version: a run of ASCII digits with its leading
/// zeros stripped, a qualifier folded to the spelling the ranking is defined
/// on, or the sub-list a separator opens. each is null when empty.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MavenItem {
    Num(String),
    Qual(String),
    List(Vec<MavenItem>),
}

impl MavenItem {
    fn is_null(&self) -> bool {
        match self {
            MavenItem::Num(digits) => digits.is_empty(),
            MavenItem::Qual(value) => value.is_empty(),
            MavenItem::List(items) => items.is_empty(),
        }
    }
}

/// the deepest item tree [`maven_parse`] will build. every level costs a frame
/// in [`maven_list_cmp`], and real Maven versions nest a handful.
const MAVEN_MAX_DEPTH: usize = 64;

/// orders two Maven versions with Maven's version-order algorithm, or `None`
/// when either nests past [`MAVEN_MAX_DEPTH`].
fn maven_cmp(a: &str, b: &str) -> Option<Ordering> {
    Some(maven_list_cmp(&maven_parse(a)?, &maven_parse(b)?))
}

/// parses a Maven version into its normalized item tree, or `None` when it
/// nests past [`MAVEN_MAX_DEPTH`].
///
/// items are separated by `.`, `-`, `_` and by any transition between ASCII
/// digits and other characters; every separator but `.` opens a sub-list, as
/// does a qualifier reached from a digit or introduced by a `.` after an
/// item. an empty item is Maven's `0`, so `1-.1` is `1-0.1`.
fn maven_parse(s: &str) -> Option<Vec<MavenItem>> {
    let s = s.to_lowercase();
    let mut stack: Vec<Vec<MavenItem>> = vec![Vec::new()];
    let mut digits = false;
    let mut start = 0;

    for (i, c) in s.char_indices() {
        if matches!(c, '.' | '-' | '_') {
            let item = if i == start {
                MavenItem::Num(String::new())
            } else {
                maven_item(digits, &s[start..i])
            };
            stack.last_mut().expect("stack is never emptied").push(item);
            start = i + c.len_utf8();
            if c != '.' {
                maven_open(&mut stack)?;
            }
            continue;
        }

        let is_digit = c.is_ascii_digit();
        if i > start && is_digit && !digits {
            if !stack.last().expect("stack is never emptied").is_empty() {
                maven_open(&mut stack)?;
            }
            let qualifier = MavenItem::Qual(maven_qualifier(&s[start..i], true));
            stack
                .last_mut()
                .expect("stack is never emptied")
                .push(qualifier);
            start = i;
            maven_open(&mut stack)?;
        } else if i > start && !is_digit && digits {
            let number = maven_item(true, &s[start..i]);
            stack
                .last_mut()
                .expect("stack is never emptied")
                .push(number);
            start = i;
            maven_open(&mut stack)?;
        }
        digits = is_digit;
    }

    if s.len() > start {
        if !digits && !stack.last().expect("stack is never emptied").is_empty() {
            maven_open(&mut stack)?;
        }
        let item = maven_item(digits, &s[start..]);
        stack.last_mut().expect("stack is never emptied").push(item);
    }

    while stack.len() > 1 {
        let mut child = stack.pop().expect("length is above one");
        maven_normalize(&mut child);
        stack
            .last_mut()
            .expect("stack is never emptied")
            .push(MavenItem::List(child));
    }

    let mut items = stack.pop().expect("stack is never emptied");
    maven_normalize(&mut items);
    Some(items)
}

/// opens a sub-list, or `None` at [`MAVEN_MAX_DEPTH`].
fn maven_open(stack: &mut Vec<Vec<MavenItem>>) -> Option<()> {
    if stack.len() >= MAVEN_MAX_DEPTH {
        return None;
    }
    stack.push(Vec::new());
    Some(())
}

/// classifies one item's text. `followed_by_digit` only matters for the
/// `a`/`b`/`m` shorthands.
fn maven_item(digits: bool, text: &str) -> MavenItem {
    if digits {
        MavenItem::Num(text.trim_start_matches('0').to_string())
    } else {
        MavenItem::Qual(maven_qualifier(text, false))
    }
}

/// folds a qualifier to the spelling the ranking is defined on: lower case,
/// `ga`/`final`/`release` to the empty release qualifier, `cr` to `rc`, and a
/// lone `a`/`b`/`m` directly followed by a digit to its long form.
fn maven_qualifier(text: &str, followed_by_digit: bool) -> String {
    let lower = text.to_lowercase();

    if followed_by_digit {
        match lower.as_str() {
            "a" => return "alpha".to_string(),
            "b" => return "beta".to_string(),
            "m" => return "milestone".to_string(),
            _ => {}
        }
    }

    match lower.as_str() {
        "ga" | "final" | "release" => String::new(),
        "cr" => "rc".to_string(),
        _ => lower,
    }
}

/// drops a list's trailing null items, so that `1.0.0`, `1.ga` and `1-0` all
/// reduce to `1`. a sub-list is stepped over rather than ending the scan.
fn maven_normalize(items: &mut Vec<MavenItem>) {
    let mut i = items.len();
    while i > 0 {
        i -= 1;
        if items[i].is_null() {
            items.remove(i);
        } else if !matches!(items[i], MavenItem::List(_)) {
            break;
        }
    }
}

/// orders two item lists, padding the shorter with the null each unmatched item
/// is measured against.
fn maven_list_cmp(a: &[MavenItem], b: &[MavenItem]) -> Ordering {
    for i in 0..a.len().max(b.len()) {
        let ord = match (a.get(i), b.get(i)) {
            (Some(x), Some(y)) => maven_item_cmp(x, y),
            (Some(x), None) => maven_null_cmp(x),
            (None, Some(y)) => maven_null_cmp(y).reverse(),
            (None, None) => Ordering::Equal,
        };

        if ord != Ordering::Equal {
            return ord;
        }
    }

    Ordering::Equal
}

/// orders two items on the ranking `qualifier < sub-list < number`.
fn maven_item_cmp(a: &MavenItem, b: &MavenItem) -> Ordering {
    match (a, b) {
        (MavenItem::Num(x), MavenItem::Num(y)) => x.len().cmp(&y.len()).then_with(|| x.cmp(y)),
        (MavenItem::Qual(x), MavenItem::Qual(y)) => {
            maven_qualifier_rank(x).cmp(&maven_qualifier_rank(y))
        }
        (MavenItem::List(x), MavenItem::List(y)) => maven_list_cmp(x, y),
        (MavenItem::Num(_), _) => Ordering::Greater,
        (_, MavenItem::Num(_)) => Ordering::Less,
        (MavenItem::List(_), MavenItem::Qual(_)) => Ordering::Greater,
        (MavenItem::Qual(_), MavenItem::List(_)) => Ordering::Less,
    }
}

/// orders an item against the absent one facing it: a number against `0`, a
/// qualifier against the release qualifier, a list against its own contents.
fn maven_null_cmp(item: &MavenItem) -> Ordering {
    match item {
        MavenItem::Num(digits) => {
            if digits.is_empty() {
                Ordering::Equal
            } else {
                Ordering::Greater
            }
        }
        MavenItem::Qual(value) => maven_qualifier_rank(value).cmp(&maven_qualifier_rank("")),
        MavenItem::List(items) => items
            .iter()
            .map(maven_null_cmp)
            .find(|ord| *ord != Ordering::Equal)
            .unwrap_or(Ordering::Equal),
    }
}

/// the qualifier ranking: the named qualifiers in their documented order, then
/// every other one, lexically, above them all.
fn maven_qualifier_rank(q: &str) -> (usize, &str) {
    const KNOWN: [&str; 7] = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"];

    match KNOWN.iter().position(|known| *known == q) {
        Some(i) => (i, ""),
        None => (KNOWN.len(), q),
    }
}

/// parses a NuGet version.
///
/// returns `None` on the same grounds as [`parse_deb`]: the string must be one
/// to four dot-separated numeric fields, optionally followed by a `-` release
/// label list and a `+` build metadata suffix, so codenames, git hashes and
/// other genuinely opaque strings stay [`Opaque`](Version::Opaque).
fn parse_nuget(s: &str) -> Option<Version> {
    let (core, rest) = match s.find(['-', '+']) {
        Some(idx) => (&s[..idx], &s[idx..]),
        None => (s, ""),
    };

    let mut version = [0u64; 4];
    for (i, field) in core.split('.').enumerate() {
        if i == version.len() || field.is_empty() || !field.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        version[i] = field.parse().ok()?;
    }

    // a `+` ahead of any `-` opens the metadata, so the rest is never a label
    let (labels, metadata) = match rest.strip_prefix('-') {
        Some(tail) => match tail.split_once('+') {
            Some((labels, metadata)) => (labels, Some(metadata)),
            None => (tail, None),
        },
        None => ("", rest.strip_prefix('+')),
    };

    if let Some(metadata) = metadata {
        if metadata.is_empty()
            || !metadata
                .bytes()
                .all(|b| is_nuget_label_byte(b) || b == b'.')
        {
            return None;
        }
    }

    let release: Vec<String> = if labels.is_empty() {
        Vec::new()
    } else {
        labels.split('.').map(str::to_string).collect()
    };
    if release
        .iter()
        .any(|label| label.is_empty() || !label.bytes().all(is_nuget_label_byte))
    {
        return None;
    }

    Some(Version::Nuget { version, release })
}

/// characters permitted in a NuGet release label or metadata part.
fn is_nuget_label_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}

/// orders two NuGet versions given as `(numeric fields, release labels)`: the
/// four fields in order, then a version carrying release labels below one that
/// carries none, then the labels themselves.
fn nuget_cmp(a: (&[u64; 4], &[String]), b: (&[u64; 4], &[String])) -> Ordering {
    a.0.cmp(b.0)
        .then_with(|| a.1.is_empty().cmp(&b.1.is_empty()))
        .then_with(|| nuget_release_cmp(a.1, b.1))
}

/// orders two release-label lists label by label, a list that runs out first
/// sorting below the one that continues.
fn nuget_release_cmp(a: &[String], b: &[String]) -> Ordering {
    for i in 0..a.len().max(b.len()) {
        let ord = match (a.get(i), b.get(i)) {
            (Some(x), Some(y)) => nuget_label_cmp(x, y),
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (None, None) => Ordering::Equal,
        };

        if ord != Ordering::Equal {
            return ord;
        }
    }

    Ordering::Equal
}

/// orders two release labels: two labels NuGet reads as numbers compare
/// numerically, a number sorts below a label that is not one, and any other
/// pair compares case-insensitively. the `i32` is NuGet's `int.TryParse`: a
/// digit run too long for one is an ordinary string.
fn nuget_label_cmp(a: &str, b: &str) -> Ordering {
    match (a.parse::<i32>().ok(), b.parse::<i32>().ok()) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => a
            .bytes()
            .map(|b| b.to_ascii_uppercase())
            .cmp(b.bytes().map(|b| b.to_ascii_uppercase())),
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

/// convenience function: returns `true` if `new_ver` is a downgrade from
/// `old_ver` under `ecosystem`'s version rules.
///
/// parses both strings with [`Version::parse_for_ecosystem`] and delegates to
/// [`Version::is_downgrade`]. a `None` ecosystem is exactly
/// [`is_version_downgrade`].
///
/// # Examples
///
/// ```
/// use sbom_model::versions::is_version_downgrade_for_ecosystem;
///
/// // a routine Ubuntu security update, not a downgrade
/// assert!(!is_version_downgrade_for_ecosystem(
///     Some("deb"),
///     "1.2.3-1ubuntu2",
///     "1.2.3-2"
/// ));
/// assert!(is_version_downgrade_for_ecosystem(Some("deb"), "1.2.3-2", "1.2.3-1ubuntu2"));
/// ```
pub fn is_version_downgrade_for_ecosystem(
    ecosystem: Option<&str>,
    old_ver: &str,
    new_ver: &str,
) -> bool {
    Version::parse_for_ecosystem(ecosystem, old_ver)
        .is_downgrade(&Version::parse_for_ecosystem(ecosystem, new_ver))
}

/// convenience function: orders two version strings under `ecosystem`'s version
/// rules, returning `None` when the ordering is unknown.
///
/// parses both strings with [`Version::parse_for_ecosystem`] and delegates to
/// [`Version::partial_cmp_lenient`]. a `None` ecosystem is exactly
/// [`compare_versions`].
///
/// # Examples
///
/// ```
/// use std::cmp::Ordering;
/// use sbom_model::versions::compare_versions_for_ecosystem;
///
/// assert_eq!(
///     compare_versions_for_ecosystem(Some("deb"), "1.0~rc1", "1.0"),
///     Some(Ordering::Less)
/// );
///
/// // a `^` post-release snapshot, which the Debian alphabet has no reading for
/// assert_eq!(
///     compare_versions_for_ecosystem(Some("rpm"), "1.0^20200101git", "1.0"),
///     Some(Ordering::Greater)
/// );
/// ```
pub fn compare_versions_for_ecosystem(
    ecosystem: Option<&str>,
    a: &str,
    b: &str,
) -> Option<Ordering> {
    Version::parse_for_ecosystem(ecosystem, a)
        .partial_cmp_lenient(&Version::parse_for_ecosystem(ecosystem, b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn maven_cmp(a: &str, b: &str) -> Ordering {
        super::maven_cmp(a, b).unwrap_or_else(|| panic!("{a} vs {b} exceeds the depth cap"))
    }

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

    // --- letter-suffixed OS package versions (OpenSSL, tzdata, Alpine) ---

    /// `pattern` with its `@` replaced by each letter of `a`..`z` in turn.
    fn letter_suffixed(pattern: &str) -> Vec<String> {
        ('a'..='z')
            .map(|c| pattern.replace('@', &c.to_string()))
            .collect()
    }

    #[test]
    fn bare_single_letter_suffix_parses_as_deb() {
        for pattern in ["1.0.2@", "2024@", "1.1.1@-r0", "1.0@"] {
            for s in letter_suffixed(pattern) {
                assert!(
                    matches!(Version::parse_lenient(&s), Version::Deb { .. }),
                    "{s} should parse as Deb"
                );
            }
        }
    }

    #[test]
    fn letter_suffixed_versions_order_across_the_alphabet() {
        for pattern in ["1.0.2@", "2024@", "1.1.1@-r0"] {
            let versions = letter_suffixed(pattern);
            let refs: Vec<&str> = versions.iter().map(String::as_str).collect();
            assert_ascending(&refs);
        }
        assert_ascending(&["2024a", "2024h", "2025a", "2025b"]);
        assert_ascending(&["1.1.1a-r0", "1.1.1d-r0", "1.1.1d-r1", "1.1.1w-r0"]);
    }

    #[test]
    fn bare_keyword_longer_than_one_letter_stays_pep440() {
        for s in [
            "1.0rc",
            "1.0.dev",
            "1.0.post",
            "1.0alpha",
            "1.0beta",
            "1.0pre",
            "1.0preview",
            "1.0rev",
            "2.0.post2.dev3",
        ] {
            assert!(
                matches!(Version::parse_lenient(s), Version::Pep440(_)),
                "{s} should still parse as Pep440"
            );
        }
    }

    #[test]
    fn single_letter_alias_with_a_number_stays_pep440() {
        for s in [
            "1.0a1",
            "1.0b1",
            "1.0c1",
            "1.0r1",
            "1.0a0",
            "1.0-a-1",
            "1.0_b_2",
            "1.0.c.3",
            "1!2.0a1",
            "1.0a1+ubuntu.1",
        ] {
            assert!(
                matches!(Version::parse_lenient(s), Version::Pep440(_)),
                "{s} should still parse as Pep440"
            );
        }
    }

    #[test]
    fn downgrade_letter_suffix_gate() {
        assert!(is_version_downgrade("1.0.2d", "1.0.2c"));
        assert!(!is_version_downgrade("1.0.2c", "1.0.2d"));
        assert!(is_version_downgrade("2025a", "2024h"));
        assert!(!is_version_downgrade("2024h", "2025a"));
        assert!(is_version_downgrade("1.1.1d-r0", "1.1.1a-r0"));
        assert!(!is_version_downgrade("1.1.1a-r0", "1.1.1d-r0"));
        assert!(!is_version_downgrade("1.0.2a", "1.0.2a"));
        // a base release and its letter releases are Semver against Deb
        assert_eq!(compare_versions("1.0.2", "1.0.2a"), None);
        assert!(!is_version_downgrade("1.0.2", "1.0.2a"));
        assert!(!is_version_downgrade("1.0.2a", "1.0.2"));
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

    /// version strings spanning every shape the two entry points disagree about.
    const ECOSYSTEM_CORPUS: &[&str] = &[
        "1",
        "1.0",
        "1.0.0",
        "1.2.3",
        "v1.2.3",
        "2024.01.15",
        "1.2.3.4",
        "1.0.0-alpha.1",
        "1.0.0-alpha.2",
        "1.0.0-rc.1",
        "1.0.0+build.9",
        "1.0.0-foo.bar",
        "4.2.0rc1",
        "1.0.dev1",
        "1.0a1",
        "1!1.0",
        "1.0.post1",
        "1.0.2a",
        "1.2.3-1",
        "1.2.3-2",
        "1.2.3-1ubuntu2",
        "1.2.3-1build1",
        "1.2.3-1+deb11u1",
        "1.0~rc1",
        "2:1.0-3",
        "4.4.2-2.el7_9",
        "deadbeef",
        "",
    ];

    #[test]
    fn unknown_ecosystem_parses_exactly_like_parse_lenient() {
        for eco in [
            None,
            Some("npm"),
            Some("cargo"),
            Some("golang"),
            Some("python"),
        ] {
            for s in ECOSYSTEM_CORPUS {
                assert_eq!(
                    Version::parse_for_ecosystem(eco, s),
                    Version::parse_lenient(s),
                    "{eco:?} / {s}"
                );
            }
        }
    }

    #[test]
    fn unknown_ecosystem_orders_exactly_like_the_string_only_path() {
        for eco in [
            None,
            Some("npm"),
            Some("cargo"),
            Some("golang"),
            Some("python"),
        ] {
            for a in ECOSYSTEM_CORPUS {
                for b in ECOSYSTEM_CORPUS {
                    assert_eq!(
                        compare_versions_for_ecosystem(eco, a, b),
                        compare_versions(a, b),
                        "{eco:?} / {a} vs {b}"
                    );
                    assert_eq!(
                        is_version_downgrade_for_ecosystem(eco, a, b),
                        is_version_downgrade(a, b),
                        "{eco:?} / {a} -> {b}"
                    );
                }
            }
        }
    }

    #[test]
    fn semver_prereleases_keep_their_semver_reading() {
        for eco in [None, Some("npm"), Some("cargo")] {
            assert_eq!(
                compare_versions_for_ecosystem(eco, "1.0.0-alpha.1", "1.0.0"),
                Some(Ordering::Less),
                "{eco:?}"
            );
            assert!(!is_version_downgrade_for_ecosystem(
                eco,
                "1.0.0-alpha.1",
                "1.0.0"
            ));
            assert!(is_version_downgrade_for_ecosystem(
                eco,
                "1.0.0",
                "1.0.0-alpha.1"
            ));
        }
    }

    #[test]
    fn deb_ecosystem_parses_as_deb() {
        assert_eq!(
            Version::parse_for_ecosystem(Some("deb"), "1.2.3-1ubuntu2"),
            Version::Deb {
                epoch: 0,
                upstream: "1.2.3".into(),
                revision: "1ubuntu2".into(),
            }
        );
        assert!(matches!(
            Version::parse_for_ecosystem(Some("deb"), "1.2.3"),
            Version::Deb { .. }
        ));
        assert!(matches!(
            Version::parse_for_ecosystem(Some("deb"), "1.0.0-alpha.1"),
            Version::Deb { .. }
        ));
    }

    #[test]
    fn deb_ecosystem_match_ignores_case() {
        assert_eq!(
            Version::parse_for_ecosystem(Some("DEB"), "1.2.3-1ubuntu2"),
            Version::parse_for_ecosystem(Some("deb"), "1.2.3-1ubuntu2")
        );
    }

    #[test]
    fn deb_ecosystem_does_not_retry_a_non_deb_string_as_semver() {
        assert_eq!(
            Version::parse_for_ecosystem(Some("deb"), "4.4.2-2.el7_9"),
            Version::Opaque("4.4.2-2.el7_9".into())
        );
        assert!(matches!(
            Version::parse_for_ecosystem(Some("deb"), "v1.2.3-1ubuntu2"),
            Version::Deb { .. }
        ));
    }

    /// every expectation checked against `dpkg --compare-versions` on Debian.
    #[test]
    fn deb_ecosystem_strips_a_v_prefix_instead_of_skipping_the_pair() {
        use Ordering::{Greater, Less};

        for (a, b, expected) in [
            ("v1.2.3", "v1.2.4", Less),
            ("v1.2.10", "v1.2.9", Greater),
            ("V1.2.3", "V1.2.4", Less),
            ("v1.2.3-1ubuntu2", "v1.2.3-2", Less),
        ] {
            assert_eq!(
                compare_versions_for_ecosystem(Some("deb"), a, b),
                Some(expected),
                "{a} vs {b}"
            );
            assert_eq!(
                compare_versions_for_ecosystem(Some("deb"), b, a),
                Some(expected.reverse()),
                "{b} vs {a}"
            );
        }

        assert!(is_version_downgrade_for_ecosystem(
            Some("deb"),
            "v1.2.4",
            "v1.2.3"
        ));
    }

    /// every expectation checked against `dpkg --compare-versions` on Debian.
    #[test]
    fn deb_ecosystem_orders_revisions_the_way_dpkg_does() {
        use Ordering::{Greater, Less};

        for (a, b, expected) in [
            ("1.2.3-1ubuntu2", "1.2.3-2", Less),
            ("1.2.3-1build1", "1.2.3-2", Less),
            ("1.2.3-2ubuntu0.1", "1.2.3-3", Less),
            ("1.2.3-1+deb11u1", "1.2.3-2", Less),
            ("1.2.3-1+deb11u1", "1.2.3-1+deb11u2", Less),
            ("1.2.3-1ubuntu2", "1.2.3-1ubuntu1", Greater),
            ("1.2.3-1", "1.2.3-10", Less),
            ("1.2.3", "1.2.3-1", Less),
            ("1.0-1", "1.0", Greater),
            ("1.0~rc1", "1.0", Less),
            ("1.0~rc1-1", "1.0-1", Less),
            ("1.2.3-1~bpo11+1", "1.2.3-1", Less),
            ("2:1.0-1", "10.0-1", Greater),
            ("1.1.1n-0+deb11u5", "1.1.1o-1", Less),
        ] {
            assert_eq!(
                compare_versions_for_ecosystem(Some("deb"), a, b),
                Some(expected),
                "{a} vs {b}"
            );
            assert_eq!(
                compare_versions_for_ecosystem(Some("deb"), b, a),
                Some(expected.reverse()),
                "{b} vs {a}"
            );
        }
    }

    #[test]
    fn deb_ecosystem_clears_the_false_downgrade_the_string_only_path_reports() {
        assert!(!is_version_downgrade_for_ecosystem(
            Some("deb"),
            "1.2.3-1ubuntu2",
            "1.2.3-2"
        ));
        assert!(is_version_downgrade("1.2.3-1ubuntu2", "1.2.3-2"));
        assert!(is_version_downgrade_for_ecosystem(
            Some("deb"),
            "1.2.3-2",
            "1.2.3-1ubuntu2"
        ));
    }

    #[test]
    fn deb_ecosystem_catches_the_downgrades_the_string_only_path_passed() {
        for (old, new) in [
            ("1.2.3-2", "1.2.3-1ubuntu2"),
            ("1.2.3-3", "1.2.3-2ubuntu0.1"),
            ("1.2.3-1+deb11u2", "1.2.3-1+deb11u1"),
        ] {
            assert!(!is_version_downgrade(old, new), "{old} -> {new}");
            assert!(
                is_version_downgrade_for_ecosystem(Some("deb"), old, new),
                "{old} -> {new}"
            );
        }
    }

    #[test]
    fn deb_ecosystem_orders_plus_revisions_the_string_only_path_read_as_equal() {
        assert_eq!(
            compare_versions("1.2.3-1+deb11u1", "1.2.3-1+deb11u2"),
            Some(Ordering::Equal)
        );
        assert_eq!(
            compare_versions_for_ecosystem(Some("deb"), "1.2.3-1+deb11u1", "1.2.3-1+deb11u2"),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn deb_ecosystem_makes_previously_uncomparable_pairs_comparable() {
        for (a, b) in [("1.0-1", "1.0"), ("1.0~rc1", "1.0"), ("1.0.2a", "1.0.2")] {
            assert_eq!(compare_versions(a, b), None, "{a} vs {b}");
            assert!(
                compare_versions_for_ecosystem(Some("deb"), a, b).is_some(),
                "{a} vs {b}"
            );
        }
    }

    /// rpm's own `tests/rpmvercmp.at` assertion list, one case per row.
    /// `expected` is how `a` orders relative to `b`.
    #[test]
    fn rpmvercmp_upstream_vectors() {
        use Ordering::{Equal, Greater, Less};

        for (a, b, expected) in [
            ("1.0", "1.0", Equal),
            ("1.0", "2.0", Less),
            ("2.0", "1.0", Greater),
            ("2.0.1", "2.0.1", Equal),
            ("2.0", "2.0.1", Less),
            ("2.0.1", "2.0", Greater),
            ("2.0.1a", "2.0.1a", Equal),
            ("2.0.1a", "2.0.1", Greater),
            ("2.0.1", "2.0.1a", Less),
            ("5.5p1", "5.5p1", Equal),
            ("5.5p1", "5.5p2", Less),
            ("5.5p2", "5.5p1", Greater),
            ("5.5p10", "5.5p10", Equal),
            ("5.5p1", "5.5p10", Less),
            ("5.5p10", "5.5p1", Greater),
            ("10xyz", "10.1xyz", Less),
            ("10.1xyz", "10xyz", Greater),
            ("xyz10", "xyz10", Equal),
            ("xyz10", "xyz10.1", Less),
            ("xyz10.1", "xyz10", Greater),
            ("xyz.4", "xyz.4", Equal),
            ("xyz.4", "8", Less),
            ("8", "xyz.4", Greater),
            ("xyz.4", "2", Less),
            ("2", "xyz.4", Greater),
            ("5.5p2", "5.6p1", Less),
            ("5.6p1", "5.5p2", Greater),
            ("5.6p1", "6.5p1", Less),
            ("6.5p1", "5.6p1", Greater),
            ("6.0.rc1", "6.0", Greater),
            ("6.0", "6.0.rc1", Less),
            ("10b2", "10a1", Greater),
            ("10a2", "10b2", Less),
            ("1.0aa", "1.0aa", Equal),
            ("1.0a", "1.0aa", Less),
            ("1.0aa", "1.0a", Greater),
            ("10.0001", "10.0001", Equal),
            ("10.0001", "10.1", Equal),
            ("10.1", "10.0001", Equal),
            ("10.0001", "10.0039", Less),
            ("10.0039", "10.0001", Greater),
            ("4.999.9", "5.0", Less),
            ("5.0", "4.999.9", Greater),
            ("20101121", "20101121", Equal),
            ("20101121", "20101122", Less),
            ("20101122", "20101121", Greater),
            ("2_0", "2_0", Equal),
            ("2.0", "2_0", Equal),
            ("2_0", "2.0", Equal),
            ("a", "a", Equal),
            ("a+", "a+", Equal),
            ("a+", "a_", Equal),
            ("a_", "a+", Equal),
            ("+a", "+a", Equal),
            ("+a", "_a", Equal),
            ("_a", "+a", Equal),
            ("+_", "+_", Equal),
            ("_+", "+_", Equal),
            ("_+", "_+", Equal),
            ("+", "_", Equal),
            ("_", "+", Equal),
            ("1.0~rc1", "1.0~rc1", Equal),
            ("1.0~rc1", "1.0", Less),
            ("1.0", "1.0~rc1", Greater),
            ("1.0~rc1", "1.0~rc2", Less),
            ("1.0~rc2", "1.0~rc1", Greater),
            ("1.0~rc1~git123", "1.0~rc1~git123", Equal),
            ("1.0~rc1~git123", "1.0~rc1", Less),
            ("1.0~rc1", "1.0~rc1~git123", Greater),
            ("1.0^", "1.0^", Equal),
            ("1.0^", "1.0", Greater),
            ("1.0", "1.0^", Less),
            ("1.0^git1", "1.0^git1", Equal),
            ("1.0^git1", "1.0", Greater),
            ("1.0", "1.0^git1", Less),
            ("1.0^git1", "1.0^git2", Less),
            ("1.0^git2", "1.0^git1", Greater),
            ("1.0^git1", "1.01", Less),
            ("1.01", "1.0^git1", Greater),
            ("1.0^20160101", "1.0^20160101", Equal),
            ("1.0^20160101", "1.0.1", Less),
            ("1.0.1", "1.0^20160101", Greater),
            ("1.0^20160101^git1", "1.0^20160101^git1", Equal),
            ("1.0^20160102", "1.0^20160101^git1", Greater),
            ("1.0^20160101^git1", "1.0^20160102", Less),
            ("1.0~rc1^git1", "1.0~rc1^git1", Equal),
            ("1.0~rc1^git1", "1.0~rc1", Greater),
            ("1.0~rc1", "1.0~rc1^git1", Less),
            ("1.0^git1~pre", "1.0^git1~pre", Equal),
            ("1.0^git1", "1.0^git1~pre", Greater),
            ("1.0^git1~pre", "1.0^git1", Less),
            // upstream keeps these as documented quirks: the alpha run is
            // compared against "fc", so 'b' loses and 'g' wins
            ("1b.fc17", "1b.fc17", Equal),
            ("1b.fc17", "1.fc17", Less),
            ("1.fc17", "1b.fc17", Greater),
            ("1g.fc17", "1g.fc17", Equal),
            ("1g.fc17", "1.fc17", Greater),
            ("1.fc17", "1g.fc17", Less),
            // non-ASCII bytes are separators, so these are all equal
            ("1.1.α", "1.1.α", Equal),
            ("1.1.α", "1.1.β", Equal),
            ("1.1.β", "1.1.α", Equal),
            ("1.1.αα", "1.1.α", Equal),
            ("1.1.α", "1.1.ββ", Equal),
            ("1.1.ββ", "1.1.αα", Equal),
        ] {
            assert_eq!(rpmvercmp(a, b), expected, "{a} vs {b}");
        }
    }

    /// derived from the algorithm: upstream's vectors exercise `rpmvercmp`
    /// alone, never the epoch and release `parseEVR` splits off ahead of it.
    #[test]
    fn rpm_ecosystem_orders_epoch_then_version_then_release() {
        use Ordering::{Equal, Greater, Less};

        for (a, b, expected) in [
            ("2:1.0-1", "1:9.9-9", Greater),
            ("1.0-1", "0:1.0-1", Equal),
            ("1.1-1", "1.0-9", Greater),
            ("1.0-2", "1.0-10", Less),
            ("1.0-1.el8", "1.0-1.el9", Less),
            ("1.0-0", "1.0-1", Less),
            // an absent release sorts below every release, including `0`
            ("1.0", "1.0-0", Less),
        ] {
            assert_eq!(
                compare_versions_for_ecosystem(Some("rpm"), a, b),
                Some(expected),
                "{a} vs {b}"
            );
            assert_eq!(
                compare_versions_for_ecosystem(Some("rpm"), b, a),
                Some(expected.reverse()),
                "{b} vs {a}"
            );
        }
    }

    /// the pairs rpm and dpkg return different verdicts for. every `deb`
    /// expectation was checked against `dpkg --compare-versions`.
    #[test]
    fn rpm_and_deb_disagree_on_ordinary_versions() {
        use Ordering::{Equal, Greater, Less};

        for (a, b, deb, rpm) in [
            // an alpha run against a digit run: dpkg ranks the letter above the
            // digit, rpm below it
            ("1.a", "1.1", Some(Greater), Some(Less)),
            ("1.fc35", "1.1", Some(Greater), Some(Less)),
            // `_` is a plain separator in rpm and outside the Debian alphabet
            ("1.0", "1_0", None, Some(Equal)),
            // `^` marks a post-release snapshot, which sorts above the base
            ("1.0^20200101gitabc", "1.0", None, Some(Greater)),
            // a stock RHEL release string, unreadable under the Debian alphabet
            ("4.4.2-2.el7_9", "4.4.2-3.el7_9", None, Some(Less)),
        ] {
            assert_eq!(
                compare_versions_for_ecosystem(Some("deb"), a, b),
                deb,
                "deb: {a} vs {b}"
            );
            assert_eq!(
                compare_versions_for_ecosystem(Some("rpm"), a, b),
                rpm,
                "rpm: {a} vs {b}"
            );
        }
    }

    #[test]
    fn rpm_ecosystem_reverses_a_gate_the_deb_rules_fire_backwards() {
        assert!(is_version_downgrade_for_ecosystem(
            Some("deb"),
            "1.a",
            "1.1"
        ));
        assert!(!is_version_downgrade_for_ecosystem(
            Some("rpm"),
            "1.a",
            "1.1"
        ));
        assert!(is_version_downgrade_for_ecosystem(
            Some("rpm"),
            "1.1",
            "1.a"
        ));
    }

    #[test]
    fn rpm_ecosystem_parses_as_rpm() {
        assert_eq!(
            Version::parse_for_ecosystem(Some("rpm"), "5.1.8-2.fc35"),
            Version::Rpm {
                epoch: 0,
                version: "5.1.8".into(),
                release: "2.fc35".into(),
            }
        );
        assert_eq!(
            Version::parse_for_ecosystem(Some("rpm"), "1:2.36.1-2.fc35"),
            Version::Rpm {
                epoch: 1,
                version: "2.36.1".into(),
                release: "2.fc35".into(),
            }
        );
        assert_eq!(
            Version::parse_for_ecosystem(Some("rpm"), "4.4.2-2.el7_9"),
            Version::Rpm {
                epoch: 0,
                version: "4.4.2".into(),
                release: "2.el7_9".into(),
            }
        );
        assert!(matches!(
            Version::parse_for_ecosystem(Some("rpm"), "1.2.3"),
            Version::Rpm { .. }
        ));
        assert!(matches!(
            Version::parse_for_ecosystem(Some("rpm"), "1.0.0-alpha.1"),
            Version::Rpm { .. }
        ));
    }

    #[test]
    fn rpm_ecosystem_match_ignores_case() {
        assert_eq!(
            Version::parse_for_ecosystem(Some("RPM"), "5.1.8-2.fc35"),
            Version::parse_for_ecosystem(Some("rpm"), "5.1.8-2.fc35")
        );
    }

    #[test]
    fn rpm_ecosystem_keeps_codenames_and_hashes_opaque() {
        for s in ["deadbeef", "focal", "", "stable", "1.0 "] {
            assert_eq!(
                Version::parse_for_ecosystem(Some("rpm"), s),
                Version::Opaque(s.to_string()),
                "{s}"
            );
        }
    }

    #[test]
    fn rpm_ecosystem_strips_a_v_prefix_instead_of_skipping_the_pair() {
        assert!(matches!(
            Version::parse_for_ecosystem(Some("rpm"), "v1.2.3-1"),
            Version::Rpm { .. }
        ));
        assert_eq!(
            compare_versions_for_ecosystem(Some("rpm"), "v1.2.3", "v1.2.4"),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn rpm_stays_uncomparable_against_every_other_parse_result() {
        let rpm = Version::parse_for_ecosystem(Some("rpm"), "1.2.3-1");
        for other in [
            Version::parse_for_ecosystem(Some("deb"), "1.2.3-1"),
            Version::parse_lenient("1.2.3"),
            Version::parse_lenient("2024.01.15"),
            Version::parse_lenient("4.2.0rc1"),
            Version::parse_lenient("deadbeef"),
        ] {
            assert_eq!(rpm.partial_cmp_lenient(&other), None, "{other:?}");
            assert_eq!(other.partial_cmp_lenient(&rpm), None, "{other:?}");
        }
    }

    #[test]
    fn parse_lenient_never_produces_the_rpm_variant() {
        for s in
            ECOSYSTEM_CORPUS
                .iter()
                .copied()
                .chain(["1.0^20200101", "1_0", "1.a", "5.1.8-2.fc35"])
        {
            assert!(
                !matches!(Version::parse_lenient(s), Version::Rpm { .. }),
                "{s}"
            );
        }
    }

    /// Maven's documented "End Result Examples", one case per row.
    /// `expected` is how `a` orders relative to `b`.
    #[test]
    fn maven_documented_ordering_examples() {
        use Ordering::{Equal, Greater, Less};

        for (a, b, expected) in [
            ("1", "1.1", Less),
            ("1-snapshot", "1", Less),
            ("1", "1-sp", Less),
            ("1-foo2", "1-foo10", Less),
            ("1.foo", "1-foo", Equal),
            ("1-foo", "1-1", Less),
            ("1-1", "1.1", Less),
            ("1.ga", "1-ga", Equal),
            ("1-ga", "1-0", Equal),
            ("1-0", "1_0", Equal),
            ("1_0", "1.0", Equal),
            ("1.0", "1", Equal),
            ("1-sp", "1-ga", Greater),
            ("1-sp.1", "1-ga.1", Greater),
            ("1-sp-1", "1-ga-1", Less),
            ("1-a1", "1-alpha-1", Equal),
            ("1.0-alpha1", "1.0-ALPHA1", Equal),
            ("1.7", "1.K", Greater),
            ("5.zebra", "5.aardvark", Greater),
            ("1.α", "1.b", Greater),
        ] {
            assert_eq!(maven_cmp(a, b), expected, "{a} vs {b}");
            assert_eq!(maven_cmp(b, a), expected.reverse(), "{b} vs {a}");
        }
    }

    /// Maven's documented splitting and trimming examples: each row is a
    /// version and the spelling it reduces to.
    #[test]
    fn maven_documented_splitting_and_trimming_examples() {
        for (version, reduced) in [
            ("1-1.foo-bar1baz-.1", "1-1.foo-bar-1-baz-0.1"),
            ("1.0.0", "1"),
            ("1.ga", "1"),
            ("1.final", "1"),
            ("1.0", "1"),
            ("1.", "1"),
            ("1-", "1"),
            ("1_", "1"),
            ("1.0.0-foo.0.0", "1-foo"),
            ("1.0.0-0.0.0", "1"),
        ] {
            assert_eq!(maven_parse(version), maven_parse(reduced), "{version}");
        }
    }

    #[test]
    fn maven_ranks_qualifiers_in_the_documented_order() {
        let ascending = [
            "1-alpha",
            "1-beta",
            "1-milestone",
            "1-rc",
            "1-snapshot",
            "1",
            "1-sp",
        ];

        for (i, a) in ascending.iter().enumerate() {
            for b in &ascending[i + 1..] {
                assert_eq!(maven_cmp(a, b), Ordering::Less, "{a} vs {b}");
                assert_eq!(maven_cmp(b, a), Ordering::Greater, "{b} vs {a}");
            }
            // an unrecognized qualifier outranks every named one
            assert_eq!(maven_cmp(a, "1-zzz"), Ordering::Less, "{a} vs 1-zzz");
        }
        assert_eq!(maven_cmp("1-zzz", "1-aaa"), Ordering::Greater);
    }

    #[test]
    fn maven_folds_qualifier_aliases() {
        for (a, b) in [
            ("1-cr", "1-rc"),
            ("1-cr1", "1-rc1"),
            ("1-ga", "1"),
            ("1-final", "1"),
            ("1-release", "1"),
            ("1-a1", "1-alpha1"),
            ("1-b2", "1-beta2"),
            ("1-m3", "1-milestone3"),
            ("1-RC1", "1-rc1"),
        ] {
            assert_eq!(maven_cmp(a, b), Ordering::Equal, "{a} vs {b}");
        }

        // the one-letter shorthands expand only directly before a digit
        assert_eq!(maven_cmp("1-a", "1-alpha"), Ordering::Greater);
        assert_eq!(maven_cmp("1-a.1", "1-alpha.1"), Ordering::Greater);
    }

    #[test]
    fn maven_folds_a_dotted_qualifier_to_the_hyphenated_form() {
        for (a, b) in [
            ("1.0.0.CR1", "1.0.0-RC1"),
            ("1.0.0.Final", "1.0.0"),
            ("1.0.0.GA", "1.0.0-ga"),
            ("2.0.0.Final", "2.0.0-Final"),
            ("1.0.0.Alpha1", "1.0.0-a1"),
            ("3.1.0.RELEASE", "3.1.0"),
        ] {
            assert_eq!(maven_cmp(a, b), Ordering::Equal, "{a} vs {b}");
        }

        for (a, b) in [
            ("1.0.0.CR1", "1.0.0-CR2"),
            ("1.0.0.Alpha1", "1.0.0-RC1"),
            ("1.0.0.CR1", "1.0.0"),
            ("2.0.a", "2-1"),
            ("3.1.0.M1", "3.1.0-RC1"),
            ("1.0.0.Beta1", "1.0.0.CR1"),
        ] {
            assert_eq!(maven_cmp(a, b), Ordering::Less, "{a} vs {b}");
            assert_eq!(maven_cmp(b, a), Ordering::Greater, "{b} vs {a}");
        }
    }

    /// JBoss, Spring, Hibernate and Netty, each rung also placed against the
    /// hyphenated spelling of its neighbours.
    #[test]
    fn maven_orders_the_published_dotted_ladders() {
        for ladder in [
            &[
                "1.0.0.Alpha1",
                "1.0.0-Beta1",
                "1.0.0.CR1",
                "1.0.0-CR2",
                "1.0.0.Final",
            ][..],
            &[
                "3.1.0.M1",
                "3.1.0-M2",
                "3.1.0.RC1",
                "3.1.0-RELEASE",
                "3.1.1.RELEASE",
            ][..],
            &["5.4.2.Final", "5.4.10.Final", "5.5.0.Alpha1", "5.5.0.Final"][..],
            &["4.1.9.Final", "4.1.65.Final", "4.1.65.1.Final"][..],
        ] {
            for (i, a) in ladder.iter().enumerate() {
                for b in &ladder[i + 1..] {
                    assert_eq!(maven_cmp(a, b), Ordering::Less, "{a} vs {b}");
                    assert_eq!(maven_cmp(b, a), Ordering::Greater, "{b} vs {a}");
                }
            }
        }
    }

    #[test]
    fn maven_nests_a_qualifier_reached_past_an_item() {
        assert_eq!(maven_cmp("1-0.alpha", "1-alpha"), Ordering::Greater);
        assert_eq!(maven_cmp("1-0.beta", "1-0.alpha"), Ordering::Greater);
        assert_eq!(maven_cmp("1-0.alpha", "1-1"), Ordering::Less);
        assert_eq!(maven_cmp("1-0.alpha", "1"), Ordering::Less);
    }

    #[test]
    fn maven_declines_a_version_nested_past_the_depth_cap() {
        let ok = format!("1{}", "-1".repeat(MAVEN_MAX_DEPTH - 2));
        let deep = format!("1{}", "-1".repeat(MAVEN_MAX_DEPTH));

        assert!(super::maven_parse(&ok).is_some());
        assert!(super::maven_parse(&deep).is_none());
        assert_eq!(
            Version::parse_for_ecosystem(Some("maven"), &ok),
            Version::Maven(ok)
        );
        assert_eq!(
            Version::parse_for_ecosystem(Some("maven"), &deep),
            Version::Opaque(deep)
        );
    }

    #[test]
    fn maven_declines_a_version_that_would_overflow_the_stack() {
        for deep in [format!("1{}", "-1".repeat(200_000)), "1a".repeat(200_000)] {
            assert_eq!(
                Version::parse_for_ecosystem(Some("maven"), &deep),
                Version::Opaque(deep.clone())
            );
            assert_eq!(
                Version::Maven(deep.clone()).partial_cmp_lenient(&Version::Maven(deep)),
                None
            );
        }
    }

    #[test]
    fn maven_ordering_is_antisymmetric_and_transitive_on_the_documented_vectors() {
        const CORPUS: &[&str] = &[
            "1",
            "1.0",
            "1.1",
            "1-1",
            "1.foo",
            "1-foo",
            "1.bar",
            "1-bar",
            "1-alpha",
            "1-a1",
            "1-beta",
            "1-milestone",
            "1-rc",
            "1-cr",
            "1-snapshot",
            "1-ga",
            "1-sp",
            "1-sp.1",
            "1-sp-1",
            "1-ga-1",
            "1.0.0-foo.0.0",
            "1_0",
            "2",
            "1.0.1",
            "1.0-alpha1",
        ];

        for a in CORPUS {
            for b in CORPUS {
                assert_eq!(
                    maven_cmp(a, b),
                    maven_cmp(b, a).reverse(),
                    "asymmetric: {a} vs {b}"
                );
                for c in CORPUS {
                    let (ab, bc) = (maven_cmp(a, b), maven_cmp(b, c));
                    if ab == bc || bc == Ordering::Equal {
                        assert_eq!(maven_cmp(a, c), ab, "intransitive: {a}, {b}, {c}");
                    }
                }
            }
        }
    }

    #[test]
    fn maven_compares_numeric_tokens_beyond_u64() {
        assert_eq!(
            maven_cmp("1.99999999999999999999999", "1.99999999999999999999998"),
            Ordering::Greater
        );
        assert_eq!(maven_cmp("1.0000000000000000000001", "1.2"), Ordering::Less);
    }

    /// the case the string-only path cannot order at all: `1.0-SNAPSHOT` reads
    /// as Debian and `1.0` as semver, and a mixed pair is `None`.
    #[test]
    fn maven_ecosystem_orders_a_snapshot_against_its_release() {
        assert_eq!(compare_versions("1.0-SNAPSHOT", "1.0"), None);

        assert_eq!(
            compare_versions_for_ecosystem(Some("maven"), "1.0-SNAPSHOT", "1.0"),
            Some(Ordering::Less)
        );
        assert!(!is_version_downgrade_for_ecosystem(
            Some("maven"),
            "1.0-SNAPSHOT",
            "1.0"
        ));
        assert!(is_version_downgrade_for_ecosystem(
            Some("maven"),
            "1.0",
            "1.0-SNAPSHOT"
        ));
    }

    #[test]
    fn maven_ecosystem_makes_previously_uncomparable_pairs_comparable() {
        use Ordering::{Equal, Greater, Less};

        for (a, b, expected) in [
            ("1.0-SNAPSHOT", "1.0", Less),
            ("1.0-M1", "1.0", Less),
            ("1.0-sp1", "1.0", Greater),
            // a JBoss-style `.Final` release is the release itself
            ("2.0.0.Final", "2.0.0", Equal),
            ("1.0-cr1", "1.0-rc1", Equal),
            // `_` is outside the Debian alphabet, so a JDK version is opaque
            ("1.7.0_80", "1.7.0_79", Greater),
        ] {
            assert_eq!(compare_versions(a, b), None, "{a} vs {b}");
            assert_eq!(
                compare_versions_for_ecosystem(Some("maven"), a, b),
                Some(expected),
                "{a} vs {b}"
            );
            assert_eq!(
                compare_versions_for_ecosystem(Some("maven"), b, a),
                Some(expected.reverse()),
                "{b} vs {a}"
            );
        }
    }

    #[test]
    fn maven_ecosystem_reverses_a_gate_the_string_only_path_fires_backwards() {
        // read as Debian revisions, `Final` sorts below `SNAPSHOT`; Maven ranks
        // the release above every snapshot
        assert_eq!(
            compare_versions("1.0-Final", "1.0-SNAPSHOT"),
            Some(Ordering::Less)
        );
        assert!(is_version_downgrade("1.0-SNAPSHOT", "1.0-Final"));
        assert!(!is_version_downgrade("1.0-Final", "1.0-SNAPSHOT"));

        assert_eq!(
            compare_versions_for_ecosystem(Some("maven"), "1.0-Final", "1.0-SNAPSHOT"),
            Some(Ordering::Greater)
        );
        assert!(!is_version_downgrade_for_ecosystem(
            Some("maven"),
            "1.0-SNAPSHOT",
            "1.0-Final"
        ));
        assert!(is_version_downgrade_for_ecosystem(
            Some("maven"),
            "1.0-Final",
            "1.0-SNAPSHOT"
        ));
    }

    #[test]
    fn maven_ecosystem_parses_as_maven() {
        assert_eq!(
            Version::parse_for_ecosystem(Some("maven"), "1.0-SNAPSHOT"),
            Version::Maven("1.0-SNAPSHOT".into())
        );
        for s in [
            "1.2.3",
            "1.0.0-alpha.1",
            "2.0.0.Final",
            "1.7.0_80",
            "1.0+b1",
        ] {
            assert!(
                matches!(
                    Version::parse_for_ecosystem(Some("maven"), s),
                    Version::Maven(_)
                ),
                "{s}"
            );
        }
    }

    #[test]
    fn maven_ecosystem_match_ignores_case() {
        assert_eq!(
            Version::parse_for_ecosystem(Some("MAVEN"), "1.0-SNAPSHOT"),
            Version::parse_for_ecosystem(Some("maven"), "1.0-SNAPSHOT")
        );
    }

    #[test]
    fn maven_ecosystem_keeps_codenames_and_hashes_opaque() {
        for s in [
            "deadbeef",
            "RELEASE",
            "LATEST",
            "",
            "master-SNAPSHOT",
            "1.0 ",
        ] {
            assert_eq!(
                Version::parse_for_ecosystem(Some("maven"), s),
                Version::Opaque(s.to_string()),
                "{s}"
            );
        }
    }

    #[test]
    fn maven_ecosystem_strips_a_v_prefix_instead_of_skipping_the_pair() {
        assert!(matches!(
            Version::parse_for_ecosystem(Some("maven"), "v1.2.3"),
            Version::Maven(_)
        ));
        assert_eq!(
            compare_versions_for_ecosystem(Some("maven"), "v1.2.3", "v1.2.4"),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn maven_stays_uncomparable_against_every_other_parse_result() {
        let maven = Version::parse_for_ecosystem(Some("maven"), "1.2.3-1");
        for other in [
            Version::parse_for_ecosystem(Some("deb"), "1.2.3-1"),
            Version::parse_for_ecosystem(Some("rpm"), "1.2.3-1"),
            Version::parse_lenient("1.2.3"),
            Version::parse_lenient("2024.01.15"),
            Version::parse_lenient("4.2.0rc1"),
            Version::parse_lenient("deadbeef"),
        ] {
            assert_eq!(maven.partial_cmp_lenient(&other), None, "{other:?}");
            assert_eq!(other.partial_cmp_lenient(&maven), None, "{other:?}");
        }
    }

    fn nuget_cmp(a: &str, b: &str) -> Ordering {
        compare_versions_for_ecosystem(Some("nuget"), a, b)
            .unwrap_or_else(|| panic!("{a} vs {b} is not a NuGet version"))
    }

    /// asserts the strings are in strictly ascending NuGet order, every pair.
    fn assert_nuget_ascending(versions: &[&str]) {
        for (i, a) in versions.iter().enumerate() {
            for b in &versions[i + 1..] {
                assert_eq!(nuget_cmp(a, b), Ordering::Less, "{a} vs {b}");
                assert_eq!(nuget_cmp(b, a), Ordering::Greater, "{b} vs {a}");
                assert!(
                    is_version_downgrade_for_ecosystem(Some("nuget"), b, a),
                    "expected {b} -> {a} downgrade"
                );
                assert!(
                    !is_version_downgrade_for_ecosystem(Some("nuget"), a, b),
                    "expected {a} -> {b} upgrade"
                );
            }
        }
    }

    /// every pair derived from NuGet.Versioning's documented rules.
    #[test]
    fn nuget_documented_ordering_examples() {
        use Ordering::{Equal, Greater, Less};

        for (a, b, expected) in [
            ("1", "1.0.0.0", Equal),
            ("1.0", "1.0.0.0", Equal),
            ("1.0.0", "1.0.0.0", Equal),
            ("1.01", "1.1", Equal),
            ("1.0.0.010", "1.0.0.10", Equal),
            ("1.0.0.1", "1.0.0", Greater),
            ("1.0.0.9", "1.0.1", Less),
            ("1.0.0-alpha", "1.0.0", Less),
            ("1.0.0.1-alpha", "1.0.0.1", Less),
            ("2.0.0.0", "2.0.0-rc", Greater),
            ("1.0.0-alpha", "1.0.0-BETA", Less),
            ("1.0.0-Alpha", "1.0.0-alpha", Equal),
            ("1.0.0-1", "1.0.0-alpha", Less),
            ("1.0.0-01", "1.0.0-1", Equal),
            ("1.0.0-2", "1.0.0-10", Less),
            ("1.0.0-alpha", "1.0.0-alpha.1", Less),
            ("1.0.0-alpha", "1.0.0-Alpha.1", Less),
            ("1.0.0-rc.1+build", "1.0.0-rc.2", Less),
            // an empty label list is not a pre-release
            ("1.0.0-", "1.0.0", Equal),
            // a digit run past NuGet's `int.TryParse` is an ordinary string
            ("1.0.0-99999999999", "1.0.0-alpha", Less),
        ] {
            assert_eq!(nuget_cmp(a, b), expected, "{a} vs {b}");
            assert_eq!(nuget_cmp(b, a), expected.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn nuget_ignores_build_metadata_for_ordering_and_equality() {
        for (a, b) in [
            ("1.0.0+sha1", "1.0.0+sha2"),
            ("1.0.0+a", "1.0.0"),
            ("1.0.0-rc+a", "1.0.0-rc+b"),
            ("1.0.0+meta-with-dashes", "1.0.0+0.1"),
        ] {
            assert_eq!(nuget_cmp(a, b), Ordering::Equal, "{a} vs {b}");
            assert_eq!(
                Version::parse_for_ecosystem(Some("nuget"), a),
                Version::parse_for_ecosystem(Some("nuget"), b),
                "{a} vs {b}"
            );
        }
    }

    #[test]
    fn nuget_orders_the_dotnet_release_ladder() {
        assert_nuget_ascending(&[
            "6.0.0-alpha.1",
            "6.0.0-Beta.1",
            "6.0.0-preview.7.21377.19",
            "6.0.0-RC.1.21451.13",
            "6.0.0-rc.2.21480.5",
            "6.0.0",
            "6.0.0.1",
            "6.0.1-preview.1",
            "6.0.1",
            "6.1.0",
        ]);
        assert_nuget_ascending(&["1.0.0-1", "1.0.0-2", "1.0.0-10", "1.0.0-a", "1.0.0-a.1"]);
        assert_nuget_ascending(&["13.0.1", "13.0.3", "13.0.10", "13.1.0"]);
    }

    #[test]
    fn nuget_ordering_is_antisymmetric_and_transitive() {
        const CORPUS: &[&str] = &[
            "1",
            "1.0",
            "1.0.0",
            "1.0.0.0",
            "1.0.0.1",
            "1.0.1",
            "1.1",
            "2",
            "1.0.0-alpha",
            "1.0.0-ALPHA",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-rc",
            "1.0.0-1",
            "1.0.0-01",
            "1.0.0-2",
            "1.0.0-10",
            "1.0.0+meta",
            "1.0.0-rc+meta",
            "1.0.0.1-rc",
        ];

        for a in CORPUS {
            for b in CORPUS {
                assert_eq!(
                    nuget_cmp(a, b),
                    nuget_cmp(b, a).reverse(),
                    "asymmetric: {a} vs {b}"
                );
                for c in CORPUS {
                    let (ab, bc) = (nuget_cmp(a, b), nuget_cmp(b, c));
                    if ab == bc || bc == Ordering::Equal {
                        assert_eq!(nuget_cmp(a, c), ab, "intransitive: {a}, {b}, {c}");
                    }
                }
            }
        }
    }

    /// a leading zero in a release label is not a semver identifier, so the
    /// string-only path reads the version as Debian and every pair is mixed.
    #[test]
    fn nuget_ecosystem_makes_previously_uncomparable_pairs_comparable() {
        use Ordering::{Equal, Less};

        for (a, b, expected) in [
            ("1.0.0-01", "1.0.0-1", Equal),
            ("1.0.0-01", "1.0.0-alpha", Less),
            ("1.0.0-01", "1.0.0", Less),
            ("1.0.0-01", "1.0.0.1", Less),
            ("1.0.0-01", "1.0.0-rc.1", Less),
        ] {
            assert_eq!(compare_versions(a, b), None, "{a} vs {b}");
            assert_eq!(nuget_cmp(a, b), expected, "{a} vs {b}");
            assert_eq!(nuget_cmp(b, a), expected.reverse(), "{b} vs {a}");
        }
    }

    /// semver orders release labels case-sensitively, so an upper-case label
    /// sorts below every lower-case one.
    #[test]
    fn nuget_ecosystem_reverses_gates_the_string_only_path_fires_backwards() {
        use Ordering::{Equal, Greater, Less};

        for (a, b, inferred, nuget) in [
            ("1.0.0-alpha", "1.0.0-BETA", Greater, Less),
            ("3.0.0-beta", "3.0.0-RC", Greater, Less),
            ("5.0.0-preview.1", "5.0.0-RC.1", Greater, Less),
            ("1.0.0-Alpha", "1.0.0-alpha", Less, Equal),
            ("1.0.0-alpha", "1.0.0-Alpha.1", Greater, Less),
            // the inferred numeric reading drops the pre-release entirely
            ("2.0.0.0", "2.0.0-rc", Equal, Greater),
        ] {
            assert_eq!(compare_versions(a, b), Some(inferred), "{a} vs {b}");
            assert_eq!(nuget_cmp(a, b), nuget, "{a} vs {b}");
        }

        assert!(is_version_downgrade("3.0.0-beta", "3.0.0-RC"));
        assert!(!is_version_downgrade_for_ecosystem(
            Some("nuget"),
            "3.0.0-beta",
            "3.0.0-RC"
        ));
        assert!(is_version_downgrade_for_ecosystem(
            Some("nuget"),
            "3.0.0-RC",
            "3.0.0-beta"
        ));
    }

    #[test]
    fn nuget_ecosystem_parses_as_nuget() {
        assert_eq!(
            Version::parse_for_ecosystem(Some("nuget"), "1.2.3.4-rc.1+sha"),
            Version::Nuget {
                version: [1, 2, 3, 4],
                release: vec!["rc".into(), "1".into()],
            }
        );
        for s in ["1", "1.2", "1.2.3", "1.2.3.4", "1.0.0-alpha.1", "1.0.0+b1"] {
            assert!(
                matches!(
                    Version::parse_for_ecosystem(Some("nuget"), s),
                    Version::Nuget { .. }
                ),
                "{s}"
            );
        }
    }

    #[test]
    fn nuget_ecosystem_match_ignores_case() {
        assert_eq!(
            Version::parse_for_ecosystem(Some("NuGet"), "1.0.0-rc"),
            Version::parse_for_ecosystem(Some("nuget"), "1.0.0-rc")
        );
    }

    #[test]
    fn nuget_ecosystem_keeps_codenames_and_hashes_opaque() {
        for s in [
            "deadbeef",
            "",
            "latest",
            "1.0.0.0.0",
            "1.0.0.99999999999999999999",
            "1.0.0+",
            "1.0.0+α",
            "1.0.0-α",
            "1.0.0-a..b",
            "1.0.0 ",
            "1.0.0~rc1",
            "2:1.0-3",
        ] {
            assert_eq!(
                Version::parse_for_ecosystem(Some("nuget"), s),
                Version::Opaque(s.to_string()),
                "{s}"
            );
        }
    }

    #[test]
    fn nuget_ecosystem_strips_a_v_prefix_instead_of_skipping_the_pair() {
        assert!(matches!(
            Version::parse_for_ecosystem(Some("nuget"), "v1.2.3"),
            Version::Nuget { .. }
        ));
        assert_eq!(
            compare_versions_for_ecosystem(Some("nuget"), "v1.2.3", "v1.2.4"),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn nuget_stays_uncomparable_against_every_other_parse_result() {
        let nuget = Version::parse_for_ecosystem(Some("nuget"), "1.2.3-1");
        for other in [
            Version::parse_for_ecosystem(Some("deb"), "1.2.3-1"),
            Version::parse_for_ecosystem(Some("rpm"), "1.2.3-1"),
            Version::parse_for_ecosystem(Some("maven"), "1.2.3-1"),
            Version::parse_lenient("1.2.3"),
            Version::parse_lenient("2024.01.15"),
            Version::parse_lenient("4.2.0rc1"),
            Version::parse_lenient("deadbeef"),
        ] {
            assert_eq!(nuget.partial_cmp_lenient(&other), None, "{other:?}");
            assert_eq!(other.partial_cmp_lenient(&nuget), None, "{other:?}");
        }
    }

    #[test]
    fn parse_lenient_never_produces_the_nuget_variant() {
        for s in ECOSYSTEM_CORPUS.iter().copied().chain([
            "1.0.0-alpha",
            "1.2.3.4",
            "1.0.0+sha",
            "1.0.0.1-rc.1",
        ]) {
            assert!(
                !matches!(Version::parse_lenient(s), Version::Nuget { .. }),
                "{s}"
            );
        }
    }

    #[test]
    fn parse_lenient_never_produces_the_maven_variant() {
        for s in ECOSYSTEM_CORPUS.iter().copied().chain([
            "1.0-SNAPSHOT",
            "2.0.0.Final",
            "1.7.0_80",
            "1-sp",
        ]) {
            assert!(
                !matches!(Version::parse_lenient(s), Version::Maven(_)),
                "{s}"
            );
        }
    }

    #[test]
    fn pypi_ecosystem_orders_a_bare_letter_pre_release_below_its_release() {
        assert_eq!(compare_versions("1.0.2a", "1.0.2"), None);

        assert_eq!(
            compare_versions_for_ecosystem(Some("pypi"), "1.0.2a", "1.0.2"),
            Some(Ordering::Less)
        );
        assert!(!is_version_downgrade_for_ecosystem(
            Some("pypi"),
            "1.0.2a",
            "1.0.2"
        ));
        assert!(is_version_downgrade_for_ecosystem(
            Some("pypi"),
            "1.0.2",
            "1.0.2a"
        ));
    }

    #[test]
    fn pypi_ecosystem_makes_previously_uncomparable_pairs_comparable() {
        use Ordering::{Equal, Greater, Less};

        for (a, b, expected) in [
            ("1.0.2a", "1.0.2", Less),
            ("1.0.2c", "1.0.2rc0", Equal),
            ("1.0.2r", "1.0.2", Greater),
            ("1.0-1", "1.0", Greater),
            ("1.0-1", "1.0.post1", Equal),
            ("1.0+abc", "1.0", Greater),
            ("1.0+abc", "1.0.1", Less),
            ("2024a", "2024", Less),
            ("1.0.2a", "1!0.1", Less),
        ] {
            assert_eq!(compare_versions(a, b), None, "{a} vs {b}");
            assert_eq!(
                compare_versions_for_ecosystem(Some("pypi"), a, b),
                Some(expected),
                "{a} vs {b}"
            );
            assert_eq!(
                compare_versions_for_ecosystem(Some("pypi"), b, a),
                Some(expected.reverse()),
                "{b} vs {a}"
            );
        }
    }

    #[test]
    fn pypi_ecosystem_reverses_a_gate_the_string_only_path_fires_backwards() {
        // read as Debian upstream versions, a letter sorts below `+`; PEP 440
        // ranks a local label below the post release
        assert_eq!(compare_versions("1.0+0", "1.0r"), Some(Ordering::Greater));
        assert!(is_version_downgrade("1.0+0", "1.0r"));
        assert!(!is_version_downgrade("1.0r", "1.0+0"));

        assert_eq!(
            compare_versions_for_ecosystem(Some("pypi"), "1.0+0", "1.0r"),
            Some(Ordering::Less)
        );
        assert!(!is_version_downgrade_for_ecosystem(
            Some("pypi"),
            "1.0+0",
            "1.0r"
        ));
        assert!(is_version_downgrade_for_ecosystem(
            Some("pypi"),
            "1.0r",
            "1.0+0"
        ));
    }

    /// PEP 440 §"Summary of permitted suffixes and relative ordering", one
    /// strictly ascending ladder.
    #[test]
    fn pypi_ecosystem_orders_the_documented_ladder() {
        let ladder = [
            "1.0.dev456",
            "1.0a1",
            "1.0a2.dev456",
            "1.0a12.dev456",
            "1.0a12",
            "1.0b1.dev456",
            "1.0b2",
            "1.0b2.post345.dev456",
            "1.0b2.post345",
            "1.0rc1.dev456",
            "1.0rc1",
            "1.0",
            "1.0+abc.5",
            "1.0+abc.7",
            "1.0+5",
            "1.0.post456.dev34",
            "1.0.post456",
            "1.0.15",
            "1.1.dev1",
            "1.1",
            "2!0.5",
        ];
        for (i, a) in ladder.iter().enumerate() {
            for (j, b) in ladder.iter().enumerate() {
                assert_eq!(
                    compare_versions_for_ecosystem(Some("pypi"), a, b),
                    Some(i.cmp(&j)),
                    "{a} vs {b}"
                );
            }
        }
    }

    #[test]
    fn pypi_ecosystem_folds_spelling_aliases_and_separators() {
        for (a, b) in [
            ("1.0alpha1", "1.0a1"),
            ("1.0-alpha-1", "1.0a1"),
            ("1.0_ALPHA_1", "1.0a1"),
            ("1.0.beta.2", "1.0b2"),
            ("1.0pre1", "1.0rc1"),
            ("1.0PREVIEW1", "1.0rc1"),
            ("1.0c1", "1.0rc1"),
            ("1.0a", "1.0a0"),
            ("1.0.rev2", "1.0.post2"),
            ("1.0-r2", "1.0.post2"),
            ("1.0-2", "1.0.post2"),
            ("1.0.dev", "1.0.dev0"),
            ("V1.0", "1.0"),
        ] {
            assert_eq!(
                Version::parse_for_ecosystem(Some("pypi"), a),
                Version::parse_for_ecosystem(Some("pypi"), b),
                "{a} vs {b}"
            );
        }
    }

    #[test]
    fn pypi_ecosystem_parses_as_pep440() {
        for s in [
            "1",
            "1.0",
            "1.2.3",
            "1.2.3.4",
            "v1.2.3",
            "1.0.2a",
            "1!1.0",
            "1.0.post1",
            "1.0.dev1",
            "1.0+ubuntu1",
            "1.0-1",
        ] {
            assert!(
                matches!(
                    Version::parse_for_ecosystem(Some("pypi"), s),
                    Version::Pep440(_)
                ),
                "{s}"
            );
        }
    }

    #[test]
    fn pypi_ecosystem_match_ignores_case() {
        assert_eq!(
            Version::parse_for_ecosystem(Some("PyPI"), "1.0.2a"),
            Version::parse_for_ecosystem(Some("pypi"), "1.0.2a")
        );
    }

    #[test]
    fn pypi_ecosystem_keeps_non_pep440_strings_opaque() {
        for s in [
            "deadbeef",
            "",
            "1.0 ",
            "1.0.1x",
            "1.0_1",
            "1.0~rc1",
            "2:1.0-3",
            "1.2.3-1ubuntu2",
            "4.4.2-2.el7_9",
            "1.0.0-foo.bar",
            "2024h",
            "1.0-1-1",
            "1.0.post1-1",
            "1.0+",
        ] {
            assert_eq!(
                Version::parse_for_ecosystem(Some("pypi"), s),
                Version::Opaque(s.to_string()),
                "{s}"
            );
        }
    }

    #[test]
    fn pypi_ecosystem_strips_a_v_prefix_instead_of_skipping_the_pair() {
        assert!(matches!(
            Version::parse_for_ecosystem(Some("pypi"), "v1.2.3"),
            Version::Pep440(_)
        ));
        assert_eq!(
            compare_versions_for_ecosystem(Some("pypi"), "v1.2.3", "v1.2.4"),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn pypi_stays_uncomparable_against_the_other_ecosystem_variants() {
        let pypi = Version::parse_for_ecosystem(Some("pypi"), "1.2.3");
        for other in [
            Version::parse_for_ecosystem(Some("deb"), "1.2.3-1"),
            Version::parse_for_ecosystem(Some("rpm"), "1.2.3-1"),
            Version::parse_for_ecosystem(Some("maven"), "1.2.3-1"),
            Version::parse_lenient("deadbeef"),
        ] {
            assert_eq!(pypi.partial_cmp_lenient(&other), None, "{other:?}");
            assert_eq!(other.partial_cmp_lenient(&pypi), None, "{other:?}");
        }
    }

    #[test]
    fn pypi_leaves_the_inferred_path_alone() {
        for s in ECOSYSTEM_CORPUS.iter().copied().chain([
            "1.0.2a",
            "2024h",
            "1.1.1a-r0",
            "1.0-1",
            "1.0+abc",
            "1.0r",
        ]) {
            assert_eq!(
                Version::parse_for_ecosystem(None, s),
                Version::parse_lenient(s),
                "{s}"
            );
        }
        assert!(matches!(
            Version::parse_lenient("1.0.2a"),
            Version::Deb { .. }
        ));
        assert!(matches!(
            Version::parse_lenient("1.0-1"),
            Version::Deb { .. }
        ));
    }
}
