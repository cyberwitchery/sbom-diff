//! cross-ecosystem sweep of [`compare_versions`] over a corpus built by class.
//!
//! run with `cargo test -p sbom-model --test version_sweep -- --nocapture` to
//! print the per-class comparability matrix and the full ordering table.

use sbom_model::versions::{compare_versions, Version};
use std::cmp::Ordering;

/// version shapes each ecosystem actually emits, grouped by the ecosystem that
/// emits them. every entry is distinct so the cross-product has no duplicates.
const CORPUS: &[(&str, &[&str])] = &[
    (
        "pypi",
        &[
            "1.0",
            "1.0.0",
            "1.0.dev1",
            "1.0a1",
            "1.0a1.dev1",
            "1.0b2",
            "1.0rc1",
            "1.0.0rc1",
            "1.0.post1",
            "1!1.0",
            "2.0.0rc1",
        ],
    ),
    (
        "maven",
        &[
            "1.0-SNAPSHOT",
            "1.0.0-SNAPSHOT",
            "1.0-alpha",
            "2.0-M1",
            "1.2.3.RELEASE",
        ],
    ),
    (
        "go",
        &[
            "v1.2.3",
            "v2.0.0+incompatible",
            "v0.0.0-20240101120000-abcdef123456",
        ],
    ),
    (
        "npm",
        &["1.0.0-beta.1", "1.0.0-next.0", "0.0.0-canary", "2.0.0"],
    ),
    (
        "deb",
        &[
            "1:1.1.1f-1ubuntu2.16",
            "2.30.2-1",
            "1.0~rc1",
            "1.0.2k",
            "0.9.8b",
        ],
    ),
    (
        "rpm",
        &["1:1.2.3-2.el8", "4.14.3-19.el8_6", "2.4.6-97.el8", "1:2.0"],
    ),
    ("numeric", &["2024.01.15", "1.2.3.4", "1.0.0.0"]),
    ("opaque", &["deadbeef", "stable", ""]),
];

fn all() -> Vec<(&'static str, &'static str)> {
    CORPUS
        .iter()
        .flat_map(|(class, versions)| versions.iter().map(move |v| (*class, *v)))
        .collect()
}

fn kind(v: &str) -> &'static str {
    match Version::parse_lenient(v) {
        Version::Semver(_) => "semver",
        Version::Numeric(_) => "numeric",
        Version::Pep440(_) => "pep440",
        Version::Deb { .. } => "deb",
        Version::Opaque(_) => "opaque",
    }
}

fn show(o: Option<Ordering>) -> &'static str {
    match o {
        Some(Ordering::Less) => "<",
        Some(Ordering::Equal) => "=",
        Some(Ordering::Greater) => ">",
        None => "?",
    }
}

#[test]
fn sweep_reports_comparability_and_orderings() {
    let corpus = all();

    println!("== parse kinds ==");
    for (class, v) in &corpus {
        println!("{class:8} {:40} {}", format!("{v:?}"), kind(v));
    }

    let mut uncomparable = 0usize;
    let mut total = 0usize;
    println!("\n== ordering table ==");
    for (aclass, a) in &corpus {
        for (bclass, b) in &corpus {
            if a == b {
                continue;
            }
            total += 1;
            let o = compare_versions(a, b);
            if o.is_none() {
                uncomparable += 1;
            }
            println!("{aclass}/{a} {} {bclass}/{b}", show(o));
        }
    }

    let same_kind: Vec<_> = corpus
        .iter()
        .flat_map(|(_, a)| corpus.iter().map(move |(_, b)| (*a, *b)))
        .filter(|(a, b)| a != b && kind(a) == kind(b))
        .collect();
    let same_kind_none = same_kind
        .iter()
        .filter(|(a, b)| compare_versions(a, b).is_none())
        .count();
    let cross_kind_total = total - same_kind.len();
    let cross_kind_none = uncomparable - same_kind_none;

    println!("\n== summary ==");
    println!("ordered pairs:        {total}");
    println!("uncomparable:         {uncomparable}");
    println!(
        "same-kind pairs:      {} (none: {same_kind_none})",
        same_kind.len()
    );
    println!("cross-kind pairs:     {cross_kind_total} (none: {cross_kind_none})");
}

#[test]
fn ordering_is_reflexive_for_parsed_versions() {
    for (_, v) in all() {
        let parsed = Version::parse_lenient(v);
        if matches!(parsed, Version::Opaque(_)) {
            continue;
        }
        assert_eq!(
            parsed.partial_cmp_lenient(&parsed),
            Some(Ordering::Equal),
            "{v} does not compare equal to itself"
        );
    }
}

#[test]
fn ordering_is_antisymmetric() {
    let corpus = all();
    for (_, a) in &corpus {
        for (_, b) in &corpus {
            assert_eq!(
                compare_versions(a, b),
                compare_versions(b, a).map(Ordering::reverse),
                "{a} vs {b} is not antisymmetric"
            );
        }
    }
}

#[test]
fn ordering_is_transitive() {
    let corpus: Vec<Version> = all()
        .iter()
        .map(|(_, v)| Version::parse_lenient(v))
        .collect();
    let labels: Vec<&str> = all().iter().map(|(_, v)| *v).collect();

    let mut violations = Vec::new();
    for (i, a) in corpus.iter().enumerate() {
        for (j, b) in corpus.iter().enumerate() {
            let Some(ab) = a.partial_cmp_lenient(b) else {
                continue;
            };
            for (k, c) in corpus.iter().enumerate() {
                let (Some(bc), Some(ac)) = (b.partial_cmp_lenient(c), a.partial_cmp_lenient(c))
                else {
                    continue;
                };
                let expected = match (ab, bc) {
                    (Ordering::Equal, o) | (o, Ordering::Equal) => o,
                    (Ordering::Less, Ordering::Less) => Ordering::Less,
                    (Ordering::Greater, Ordering::Greater) => Ordering::Greater,
                    _ => continue,
                };
                if ac != expected {
                    violations.push(format!(
                        "{} {} {} {} {} but {} {} {}",
                        labels[i],
                        show(Some(ab)),
                        labels[j],
                        show(Some(bc)),
                        labels[k],
                        labels[i],
                        show(Some(ac)),
                        labels[k]
                    ));
                }
            }
        }
    }
    for v in &violations {
        println!("transitivity violation: {v}");
    }
    assert!(violations.is_empty(), "{} violations", violations.len());
}
