use crate::recipe::{Curve, Hash, Pattern, Recipe, SeedEncoding, SeedPattern};
use anyhow::{Context, Result, ensure};
use clap::ValueEnum;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, ValueEnum)]
pub enum Suite {
    All,
    Hashes,
    Patterns,
}

pub struct Selection {
    pub suite: Suite,
    pub curves: Vec<Curve>,
    pub hashes: Vec<Hash>,
    pub encodings: Vec<SeedEncoding>,
    pub seed_patterns: Vec<SeedPattern>,
    pub patterns: Vec<Pattern>,
    pub count: u64,
    pub class_counts: Vec<String>,
    pub tag_bits: u8,
}

#[derive(Serialize)]
pub struct Plan {
    pub recipes: Vec<Recipe>,
    pub candidate_seeds: u64,
    /// Excludes pack headers, database index and integrity trailers. Zero scalars are skipped.
    pub record_payload_bytes_upper_bound: u64,
}

fn name(value: impl ValueEnum) -> String {
    value
        .to_possible_value()
        .expect("enum value")
        .get_name()
        .to_owned()
}

pub fn build(selection: Selection) -> Result<Plan> {
    let Selection {
        suite,
        curves,
        hashes,
        encodings,
        seed_patterns,
        patterns,
        count,
        class_counts,
        tag_bits,
    } = selection;
    ensure!(
        [24, 32, 48, 64].contains(&tag_bits),
        "--tag-bits must be 24, 32, 48 or 64"
    );
    ensure!(
        (1..=1u64 << 32).contains(&count),
        "count must be within 1..=2^32"
    );
    ensure!(!curves.is_empty(), "select at least one curve");
    ensure!(
        !matches!(suite, Suite::Patterns) || (hashes.is_empty() && seed_patterns.is_empty()),
        "--hash and --seed-pattern require the hashes or all suite"
    );
    ensure!(
        !matches!(suite, Suite::Hashes) || patterns.is_empty(),
        "--pattern requires the patterns or all suite"
    );
    let mut overrides = BTreeMap::new();
    for item in class_counts {
        let (class, amount) = item
            .split_once('=')
            .context("--class-count requires CLASS=N")?;
        let amount: u64 = amount
            .parse()
            .context("class count must be a positive integer")?;
        ensure!(
            (1..=1u64 << 32).contains(&amount),
            "class count must be within 1..=2^32"
        );
        ensure!(
            overrides.insert(class.to_owned(), amount).is_none(),
            "duplicate class count: {class}"
        );
    }
    let hashes = if hashes.is_empty() {
        Hash::value_variants().to_vec()
    } else {
        hashes
    };
    let seed_patterns = if seed_patterns.is_empty() {
        SeedPattern::ALL.to_vec()
    } else {
        seed_patterns
    };
    let patterns = if patterns.is_empty() {
        Pattern::ALL.to_vec()
    } else {
        patterns
    };
    let mut used = BTreeSet::new();
    let mut budget = |class: String, limit: u64| -> Result<u64> {
        used.insert(class.clone());
        if let Some(&amount) = overrides.get(&class) {
            ensure!(
                amount <= limit,
                "{class} count {amount} exceeds this recipe's finite limit {limit}"
            );
            Ok(amount)
        } else {
            Ok(count.min(limit))
        }
    };
    let mut recipes = Vec::new();
    for curve in curves {
        if !matches!(suite, Suite::Patterns) {
            ensure!(!encodings.is_empty(), "select at least one seed encoding");
            for &hash in &hashes {
                for &encoding in &encodings {
                    for &pattern in &seed_patterns {
                        recipes.push(Recipe {
                            curve,
                            hash: Some(hash),
                            encoding: Some(encoding),
                            seed_pattern: (pattern != SeedPattern::Counter).then_some(pattern),
                            mapping: "digest-be-mod-order-v1".into(),
                            start: 0,
                            count: budget(
                                format!("seed:{}", name(pattern)),
                                pattern.limit(encoding),
                            )?,
                        });
                    }
                }
            }
        }
        if !matches!(suite, Suite::Hashes) {
            for &pattern in &patterns {
                recipes.push(Recipe::patterned(
                    curve,
                    pattern,
                    0,
                    budget(format!("scalar:{}", name(pattern)), pattern.limit(curve))?,
                ));
            }
        }
    }
    for class in overrides.keys() {
        ensure!(used.contains(class), "unknown or unselected class: {class}");
    }
    let mut seen = BTreeSet::new();
    let mut candidate_seeds = 0u64;
    let mut record_payload_bytes_upper_bound = 0u64;
    let mut unique = Vec::new();
    for recipe in recipes {
        recipe.validate()?;
        if !seen.insert(serde_json::to_string(&recipe)?) {
            continue;
        }
        candidate_seeds = candidate_seeds
            .checked_add(recipe.count)
            .context("candidate count overflow")?;
        let last = u64::from(recipe.start) + recipe.count - 1;
        let seed_bytes = (64 - last.leading_zeros()).max(1).div_ceil(8);
        record_payload_bytes_upper_bound = record_payload_bytes_upper_bound
            .checked_add(
                recipe
                    .count
                    .checked_mul(u64::from(tag_bits / 8) + u64::from(seed_bytes))
                    .context("record size overflow")?,
            )
            .context("record size overflow")?;
        unique.push(recipe);
    }
    Ok(Plan {
        recipes: unique,
        candidate_seeds,
        record_payload_bytes_upper_bound,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selection() -> Selection {
        Selection {
            suite: Suite::All,
            curves: vec![Curve::P256, Curve::P384, Curve::P521],
            hashes: vec![],
            encodings: vec![SeedEncoding::Decimal],
            seed_patterns: vec![],
            patterns: vec![],
            count: 1_000_000,
            class_counts: vec![],
            tag_bits: 24,
        }
    }

    #[test]
    fn default_plan_and_per_class_budgets() -> Result<()> {
        let plan = build(selection())?;
        assert_eq!(plan.recipes.len(), 303);
        assert_eq!(plan.candidate_seeds, 53_969_517);
        let mut s = selection();
        s.class_counts = vec![
            "seed:counter=2000000".into(),
            "scalar:prefix-u32be=5000000".into(),
        ];
        let expanded = build(s)?;
        assert_eq!(
            expanded.candidate_seeds,
            plan.candidate_seeds + 39_000_000 + 12_000_000
        );
        assert!(
            expanded
                .recipes
                .iter()
                .filter(|r| r.pattern() == Some(Pattern::PrefixU32be))
                .all(|r| r.count == 5_000_000)
        );
        Ok(())
    }

    #[test]
    fn explicit_default_count_is_capped_at_a_finite_seed_domain() -> Result<()> {
        let plan = build(Selection {
            suite: Suite::Hashes,
            curves: vec![Curve::P384],
            hashes: vec![Hash::Sha256],
            encodings: vec![SeedEncoding::Decimal],
            seed_patterns: vec![SeedPattern::RepeatByte],
            patterns: vec![],
            count: 257,
            class_counts: vec![],
            tag_bits: 24,
        })?;
        assert_eq!(plan.recipes.len(), 1);
        assert_eq!(plan.recipes[0].count, 256);
        assert_eq!(plan.candidate_seeds, 256);
        Ok(())
    }

    #[test]
    fn invalid_or_unused_overrides_fail_before_generation() {
        for class in [
            "seed:repeat-byte=257",
            "seed:no-such-class=1",
            "scalar:single-bit=522",
            "seed:counter=0",
            "seed:counter=4294967297",
            "seed:counter=-1",
            "seed:counter",
            "seed:counter=1=2",
        ] {
            let mut s = selection();
            s.class_counts.push(class.into());
            assert!(build(s).is_err(), "{class}");
        }
        let mut s = selection();
        s.class_counts = vec!["seed:counter=1".into(), "seed:counter=2".into()];
        assert!(build(s).is_err());
        let mut s = selection();
        s.suite = Suite::Patterns;
        s.class_counts.push("seed:counter=10".into());
        assert!(build(s).is_err());
        let mut s = selection();
        s.encodings.push(SeedEncoding::U32le);
        s.class_counts.push("seed:single-bit=64".into());
        assert!(build(s).is_err());
    }
}
