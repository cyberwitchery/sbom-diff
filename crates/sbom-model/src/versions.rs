//! version parsing and comparison utilities.
//!
//! provides lenient version parsing for SBOM component versions, supporting
//! semver, dot-separated numeric strings, and opaque version strings.

/// parsed version representation for lenient comparison.
///
/// covers the three common version formats found in SBOMs:
/// - Standard semver (possibly with `v` prefix or fewer than three parts)
/// - Dot-separated numeric (e.g., date-based `2024.01.15` or four-part `1.2.3.4`)
/// - Opaque strings that cannot be compared
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version {
    /// parseable as semver (with lenient parsing: `v`/`V` prefix stripped,
    /// one- or two-part versions padded to three parts).
    Semver(semver::Version),
    /// dot-separated numeric segments that don't qualify as semver
    /// (e.g., four-part versions or versions with leading zeros).
    Numeric(Vec<u64>),
    /// non-parseable version string where ordering cannot be determined.
    Opaque(String),
}

impl Version {
    /// parses a version string leniently.
    ///
    /// tries semver first (stripping `v`/`V` prefix and padding one- or
    /// two-part versions), then dot-separated numeric, then falls back
    /// to [`Opaque`](Version::Opaque).
    ///
    /// # Examples
    ///
    /// ```
    /// use sbom_model::versions::Version;
    ///
    /// assert!(matches!(Version::parse_lenient("1.2.3"), Version::Semver(_)));
    /// assert!(matches!(Version::parse_lenient("v1.2"), Version::Semver(_)));
    /// assert!(matches!(Version::parse_lenient("2024.01.15"), Version::Numeric(_)));
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

        // try dot-separated numeric
        let raw_parts: Vec<&str> = s.split('.').collect();
        let mut segments = Vec::new();
        for part in &raw_parts {
            match part.parse::<u64>() {
                Ok(n) => segments.push(n),
                Err(_) => return Version::Opaque(s.to_string()),
            }
        }
        if segments.is_empty() {
            return Version::Opaque(s.to_string());
        }
        Version::Numeric(segments)
    }

    /// returns `true` if `new` is a downgrade from `self`.
    ///
    /// comparison strategy depends on the variant pair:
    /// - **Semver vs Semver**: standard semver ordering (including pre-release)
    /// - **Numeric vs Numeric**: segment-by-segment with implicit zero padding
    /// - **Semver vs Numeric** (either direction): extracts `[major, minor, patch]`
    ///   from the semver side and compares as numeric segments
    /// - **Any Opaque**: returns `false` (ordering unknown)
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
            (Version::Semver(old), Version::Semver(new)) => new < old,
            (Version::Numeric(old), Version::Numeric(new)) => numeric_downgrade(old, new),
            (Version::Semver(old), Version::Numeric(new_segs)) => {
                let old_segs = [old.major, old.minor, old.patch];
                numeric_downgrade(&old_segs, new_segs)
            }
            (Version::Numeric(old_segs), Version::Semver(new)) => {
                let new_segs = [new.major, new.minor, new.patch];
                numeric_downgrade(old_segs, &new_segs)
            }
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

    // -------------------------------------------------------------------
    // Version::parse_lenient
    // -------------------------------------------------------------------

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

    // -------------------------------------------------------------------
    // Version::is_downgrade — semver path
    // -------------------------------------------------------------------

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
        assert!(!is_version_downgrade("1.0.0+build.1", "1.0.0+build.2"));
        assert!(is_version_downgrade("1.0.0+build.2", "1.0.0+build.1"));
        assert!(!is_version_downgrade("1.0.0+build.1", "1.0.0+build.1"));
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

    // -------------------------------------------------------------------
    // Version::is_downgrade — numeric fallback path
    // -------------------------------------------------------------------

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

    // -------------------------------------------------------------------
    // Version::is_downgrade — cross-variant (Semver vs Numeric)
    // -------------------------------------------------------------------

    #[test]
    fn downgrade_semver_vs_four_part() {
        // "1.2.3" → Semver, "1.2.3.4" → Numeric; cross-comparison extracts
        // [major,minor,patch] from the semver side
        assert!(!is_version_downgrade("1.2.3", "1.2.3.4"));
        assert!(is_version_downgrade("1.2.3.4", "1.2.3"));
    }

    #[test]
    fn downgrade_v_prefix_vs_four_part() {
        // unlike the old implementation (which bailed because the numeric
        // fallback couldn't parse "v1"), the Version enum correctly handles
        // cross-variant comparison after stripping the v-prefix during parse.
        assert!(!is_version_downgrade("v1.2.3", "1.2.3.4"));
        assert!(is_version_downgrade("1.2.3.4", "v1.2.3"));
    }

    // -------------------------------------------------------------------
    // edge cases
    // -------------------------------------------------------------------

    #[test]
    fn downgrade_empty_strings() {
        assert!(!is_version_downgrade("", "1.0.0"));
        assert!(!is_version_downgrade("1.0.0", ""));
        assert!(!is_version_downgrade("", ""));
    }
}
