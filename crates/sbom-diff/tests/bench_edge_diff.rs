//! micro-benchmark for edge diff reverse lookup performance.
//! run with: cargo test -p sbom-diff --test bench_edge_diff -- --nocapture --ignored

use sbom_diff::Differ;
use sbom_model::{Component, ComponentId, DependencyKind, Sbom};
use std::collections::BTreeMap;
use std::time::Instant;

/// build two SBOMs where every component has a *different* ID in old vs new
/// (triggering reconciliation via identity matching) and each component has
/// dependency edges.  This maximises the reverse-lookup work in
/// `compute_edge_diffs`.
fn make_sboms(n: usize) -> (Sbom, Sbom) {
    let mut old = Sbom::default();
    let mut new = Sbom::default();

    for i in 0..n {
        let name = format!("pkg-{i}");
        let version = "1.0.0".to_string();
        let ecosystem = "cargo".to_string();

        // old component: hash-based ID (no purl)
        let mut old_comp = Component::new(name.clone(), Some(version.clone()));
        old_comp.ecosystem = Some(ecosystem.clone());
        let old_id = old_comp.id.clone();
        old.components.insert(old_id.clone(), old_comp);

        // new component: purl-based ID (different from old)
        let purl = format!("pkg:cargo/{name}@{version}");
        let new_id = ComponentId::new(Some(&purl), &[]);
        let mut new_comp = Component::new(name.clone(), Some(version.clone()));
        new_comp.ecosystem = Some(ecosystem);
        new_comp.purl = Some(purl);
        new_comp.id = new_id.clone();
        new.components.insert(new_id.clone(), new_comp);

        // add a dependency edge: component i depends on component (i+1) % n
        // (creates a cycle, but the differ doesn't care about cycles)
        let dep_name = format!("pkg-{}", (i + 1) % n);
        let dep_version = "1.0.0".to_string();

        let old_dep_id = Component::new(dep_name.clone(), Some(dep_version.clone())).id;
        let new_dep_purl = format!("pkg:cargo/{dep_name}@{dep_version}");
        let new_dep_id = ComponentId::new(Some(&new_dep_purl), &[]);

        old.dependencies
            .entry(old_id)
            .or_insert_with(BTreeMap::new)
            .insert(old_dep_id, DependencyKind::Runtime);
        new.dependencies
            .entry(new_id)
            .or_insert_with(BTreeMap::new)
            .insert(new_dep_id, DependencyKind::Runtime);
    }

    (old, new)
}

fn bench_diff(label: &str, n: usize, warmup: usize, iters: usize) {
    let (old, new) = make_sboms(n);

    // warmup
    for _ in 0..warmup {
        let _ = Differ::diff(&old, &new, None);
    }

    // timed runs
    let mut times = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = Differ::diff(&old, &new, None);
        times.push(start.elapsed());
    }

    times.sort();
    let median = times[times.len() / 2];
    let min = times[0];
    let max = times[times.len() - 1];
    let mean: f64 = times.iter().map(|t| t.as_secs_f64()).sum::<f64>() / iters as f64;

    println!(
        "{label} (n={n}): median={:.3}ms  mean={:.3}ms  min={:.3}ms  max={:.3}ms  ({iters} iters)",
        median.as_secs_f64() * 1000.0,
        mean * 1000.0,
        min.as_secs_f64() * 1000.0,
        max.as_secs_f64() * 1000.0,
    );
}

#[test]
#[ignore]
fn benchmark_edge_diff_scaling() {
    println!();
    for &n in &[500, 1000, 2000, 5000, 10000] {
        bench_diff("edge_diff", n, 1, 5);
    }
}
