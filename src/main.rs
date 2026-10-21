mod database;
mod inventory;
mod output;
mod pack;
mod plan;
mod recipe;
mod scan;
mod small;

use anyhow::{Context, Result, ensure};
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use database::Database;
use plan::{Selection, Suite};
use recipe::{Curve, Hash, Pattern, Recipe, SeedEncoding, SeedPattern};
use std::{fs, path::PathBuf, time::Instant};

#[derive(Parser)]
#[command(
    version,
    about = "Offline checks for defined weak EC key-generation recipes"
)]
struct Args {
    /// Replace existing output files. By default outputs are published without overwriting.
    #[arg(long, global = true)]
    force: bool,
    /// Worker threads; defaults to available CPUs.
    #[arg(long, global = true)]
    threads: Option<usize>,
    #[command(subcommand)]
    command: Command,
}

#[derive(ClapArgs, Default)]
struct PackInputs {
    /// Candidate pack; repeat to combine packs.
    #[arg(long)]
    pack: Vec<PathBuf>,
    /// Load all .wkp files directly inside a directory; repeat as needed.
    #[arg(long)]
    pack_dir: Vec<PathBuf>,
    /// A unified database containing multiple recipes; repeat to combine databases.
    #[arg(long, alias = "database")]
    db: Vec<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Build one self-describing database from selected curves and recipes.
    BuildDb {
        #[arg(long, value_enum, default_value = "all")]
        suite: Suite,
        #[arg(long, value_enum, default_values = ["p256", "p384", "p521"])]
        curve: Vec<Curve>,
        #[arg(long, value_enum)]
        hash: Vec<Hash>,
        #[arg(long, value_enum, default_value = "decimal")]
        encoding: Vec<SeedEncoding>,
        #[arg(long, value_enum)]
        pattern: Vec<Pattern>,
        #[arg(long, value_enum)]
        seed_pattern: Vec<SeedPattern>,
        /// Default candidate seeds per selected class, capped at finite class limits.
        #[arg(long, default_value_t = 1_000_000)]
        count: u64,
        /// Override a class budget, for example seed:counter=2000000; repeatable.
        #[arg(long = "class-count", value_name = "CLASS=N")]
        class_count: Vec<String>,
        /// Print a validated recipe plan and candidate-size estimate without generating.
        #[arg(long, conflicts_with = "output")]
        dry_run: bool,
        #[arg(long, default_value_t = 24)]
        tag_bits: u8,
        #[arg(long, required_unless_present = "dry_run")]
        output: Option<PathBuf>,
    },
    /// Combine packs and databases into one file, deduplicating identical packs.
    MergeDb {
        #[command(flatten)]
        inputs: PackInputs,
        #[arg(long)]
        output: PathBuf,
    },
    /// Join downloaded CCADB metadata and PEM CSVs by certificate fingerprint.
    ImportCcadb {
        #[arg(long)]
        inventory: PathBuf,
        #[arg(long, required = true)]
        pem: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Generate a deterministic compact hash-seed candidate pack.
    Generate {
        #[arg(long, value_enum)]
        curve: Curve,
        #[arg(long, value_enum)]
        hash: Hash,
        #[arg(long, value_enum, default_value = "decimal")]
        encoding: SeedEncoding,
        #[arg(long, value_enum, default_value = "counter")]
        seed_pattern: SeedPattern,
        #[arg(long, default_value_t = 0)]
        start: u32,
        /// Defaults to the remaining seed range, capped at 100,000.
        #[arg(long)]
        count: Option<u64>,
        /// Lookup tag width. Every hit is verified against the full public key.
        #[arg(long, default_value_t = 24)]
        tag_bits: u8,
        #[arg(long)]
        output: PathBuf,
    },
    /// Generate a pattern pack using point additions or doublings in batches.
    GeneratePattern {
        #[arg(long, value_enum)]
        curve: Curve,
        #[arg(long, value_enum)]
        pattern: Pattern,
        #[arg(long, default_value_t = 0)]
        start: u32,
        /// Defaults to the remaining pattern range, capped at 100,000 seeds.
        #[arg(long)]
        count: Option<u64>,
        #[arg(long, default_value_t = 24)]
        tag_bits: u8,
        #[arg(long)]
        output: PathBuf,
    },
    /// Check public certificates in files, directories or a CCADB CSV.
    Check {
        #[command(flatten)]
        inputs: PackInputs,
        /// Inclusive small-scalar bound; zero disables this rule.
        #[arg(long, default_value_t = 1_000_000)]
        small_max: u32,
        #[arg(long)]
        ccadb: Option<PathBuf>,
        /// A specific public certificate or PEM bundle; repeat as needed.
        #[arg(long = "cert", alias = "certificate")]
        cert: Vec<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        /// Exit with status 2 when an exactly verified weak-key match is found.
        #[arg(long)]
        fail_on_match: bool,
        certificates: Vec<PathBuf>,
    },
    /// Validate and describe a candidate pack.
    Inspect { pack: PathBuf },
    /// List supported curves, hashes, seed encodings and pattern classes.
    Recipes,
}

fn write_output(path: Option<PathBuf>, bytes: &[u8], force: bool) -> Result<()> {
    if let Some(path) = path {
        output::write(&path, bytes, force)?;
    } else {
        use std::io::Write;
        std::io::stdout().lock().write_all(bytes)?;
    }
    Ok(())
}

fn read_packs(inputs: PackInputs) -> Result<Vec<pack::Pack>> {
    let mut paths = inputs.pack;
    for directory in inputs.pack_dir {
        let mut count = 0;
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            if entry.file_type()?.is_file() && entry.path().extension().is_some_and(|e| e == "wkp")
            {
                paths.push(entry.path());
                count += 1;
            }
        }
        ensure!(count > 0, "no .wkp packs in {}", directory.display());
    }
    paths.sort();
    paths.dedup();
    let mut packs: Vec<_> = paths
        .iter()
        .map(|p| pack::Pack::open(p))
        .collect::<Result<_>>()?;
    let mut database_paths = std::collections::BTreeSet::new();
    for path in inputs.db {
        let identity = fs::canonicalize(&path)
            .with_context(|| format!("resolve database path {}", path.display()))?;
        if database_paths.insert(identity) {
            packs.extend(Database::open(&path)?.packs);
        }
    }
    let unique: std::collections::BTreeMap<_, _> =
        packs.into_iter().map(|p| (p.sha256.clone(), p)).collect();
    Ok(unique.into_values().collect())
}

fn run(args: Args) -> Result<i32> {
    match args.command {
        Command::BuildDb {
            suite,
            curve,
            hash,
            encoding,
            pattern,
            seed_pattern,
            count,
            class_count,
            dry_run,
            tag_bits,
            output,
        } => {
            let plan = plan::build(Selection {
                suite,
                curves: curve,
                hashes: hash,
                encodings: encoding,
                seed_patterns: seed_pattern,
                patterns: pattern,
                count,
                class_counts: class_count,
                tag_bits,
            })?;
            if dry_run {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "candidate_seeds": plan.candidate_seeds,
                        "record_payload_bytes_upper_bound": plan.record_payload_bytes_upper_bound,
                        "recipes": plan.recipes,
                    }))?
                );
                return Ok(0);
            }
            let output = output.context("--output is required unless --dry-run is used")?;
            let mut packs = Vec::new();
            let started = Instant::now();
            for recipe in plan.recipes {
                let class = if let Some(hash) = recipe.hash {
                    let seed_pattern = recipe
                        .seed_pattern
                        .unwrap_or(SeedPattern::Counter)
                        .to_possible_value()
                        .expect("seed pattern name")
                        .get_name()
                        .to_owned();
                    format!("{hash:?}/{seed_pattern}/{:?}", recipe.encoding.unwrap())
                } else {
                    recipe
                        .pattern()
                        .expect("scalar pattern recipe")
                        .to_possible_value()
                        .expect("scalar pattern name")
                        .get_name()
                        .to_owned()
                };
                eprintln!(
                    "Generating {:?}/{class}: {} candidates",
                    recipe.curve, recipe.count
                );
                packs.push(pack::Pack::from_bytes(pack::generate(
                    recipe,
                    tag_bits / 8,
                )?)?);
            }
            Database::write(&output, &packs, args.force)?;
            eprintln!(
                "Database written in {:.3}s",
                started.elapsed().as_secs_f64()
            );
            Ok(0)
        }
        Command::MergeDb { inputs, output } => {
            let packs = read_packs(inputs)?;
            Database::write(&output, &packs, args.force)?;
            eprintln!("Combined {} unique packs", packs.len());
            Ok(0)
        }
        Command::ImportCcadb {
            inventory: path,
            pem,
            output,
        } => {
            let bytes = inventory::join(&path, &pem)?;
            write_output(Some(output), &bytes, args.force)?;
            Ok(0)
        }
        Command::Generate {
            curve,
            hash,
            encoding,
            seed_pattern,
            start,
            count,
            tag_bits,
            output,
        } => {
            ensure!(
                [24, 32, 48, 64].contains(&tag_bits),
                "--tag-bits must be 24, 32, 48 or 64"
            );
            let count = count.unwrap_or_else(|| {
                seed_pattern
                    .limit(encoding)
                    .saturating_sub(u64::from(start))
                    .min(100_000)
            });
            let recipe = Recipe {
                curve,
                hash: Some(hash),
                encoding: Some(encoding),
                seed_pattern: (seed_pattern != SeedPattern::Counter).then_some(seed_pattern),
                start,
                count,
                mapping: "digest-be-mod-order-v1".into(),
            };
            let started = Instant::now();
            eprintln!("Generating {count} candidate seeds for {curve:?}/{hash:?}/{encoding:?}");
            let bytes = pack::generate(recipe, tag_bits / 8)?;
            let pack = pack::Pack::from_bytes(bytes.clone())?;
            write_output(Some(output), &bytes, args.force)?;
            eprintln!(
                "{} records, {} bytes, {:.3}s, SHA-256 {}",
                pack.len(),
                pack.byte_len(),
                started.elapsed().as_secs_f64(),
                pack.sha256
            );
            Ok(0)
        }
        Command::GeneratePattern {
            curve,
            pattern,
            start,
            count,
            tag_bits,
            output,
        } => {
            ensure!(
                [24, 32, 48, 64].contains(&tag_bits),
                "--tag-bits must be 24, 32, 48 or 64"
            );
            let count = count.unwrap_or_else(|| {
                pattern
                    .limit(curve)
                    .saturating_sub(u64::from(start))
                    .min(pattern.default_count(curve))
            });
            let recipe = Recipe::patterned(curve, pattern, start, count);
            let started = Instant::now();
            let bytes = pack::generate(recipe, tag_bits / 8)?;
            let pack = pack::Pack::from_bytes(bytes.clone())?;
            write_output(Some(output), &bytes, args.force)?;
            eprintln!(
                "{} records, {} bytes, {:.3}s, SHA-256 {}",
                pack.len(),
                pack.byte_len(),
                started.elapsed().as_secs_f64(),
                pack.sha256
            );
            Ok(0)
        }
        Command::Check {
            inputs,
            small_max,
            ccadb,
            cert,
            output,
            fail_on_match,
            mut certificates,
        } => {
            certificates.extend(cert);
            let started = Instant::now();
            let packs = read_packs(inputs)?;
            ensure!(
                small_max > 0 || !packs.is_empty(),
                "select a small-scalar rule or at least one pack"
            );
            ensure!(
                ccadb.is_some() || !certificates.is_empty(),
                "supply certificates or --ccadb"
            );
            let inputs = scan::load(&certificates, ccadb.as_deref())?;
            let report = scan::check(inputs, &packs, small_max)?;
            let has_matches = !report.findings.is_empty();
            let has_errors = !report.input_errors.is_empty();
            eprintln!(
                "{} certificates; {} distinct supported EC keys; {} covered; {} weak-key matches; {} input errors; {:.3}s total",
                report.input_certificates,
                report.distinct_ec_keys,
                report.covered_distinct_ec_keys,
                report.findings.len(),
                report.input_errors.len(),
                started.elapsed().as_secs_f64()
            );
            let mut bytes = serde_json::to_vec_pretty(&report)?;
            bytes.push(b'\n');
            write_output(output, &bytes, args.force)?;
            Ok(if has_errors {
                1
            } else if fail_on_match && has_matches {
                2
            } else {
                0
            })
        }
        Command::Inspect { pack: path } => {
            if Database::is_database(&path)? {
                let db = Database::open(&path)?;
                let packs: Vec<_> = db.packs.iter().map(|p| serde_json::json!({"header": p.header, "file_bytes": p.byte_len(), "sha256": p.sha256})).collect();
                let mut bytes = serde_json::to_vec_pretty(
                    &serde_json::json!({"format": "WKDB0001", "sha256": db.sha256, "file_bytes": db.bytes, "packs": packs}),
                )?;
                bytes.push(b'\n');
                write_output(None, &bytes, args.force)?;
                return Ok(0);
            }
            let pack = pack::Pack::open(&path)?;
            let mut bytes = serde_json::to_vec_pretty(&serde_json::json!({
                "header": pack.header, "file_bytes": pack.byte_len(), "sha256": pack.sha256,
            }))?;
            bytes.push(b'\n');
            write_output(None, &bytes, args.force)?;
            Ok(0)
        }
        Command::Recipes => {
            fn names<T: ValueEnum>() -> Vec<String> {
                T::value_variants()
                    .iter()
                    .map(|v| {
                        v.to_possible_value()
                            .expect("enum value")
                            .get_name()
                            .to_owned()
                    })
                    .collect()
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "curves": names::<Curve>(), "hashes": names::<Hash>(), "encodings": names::<SeedEncoding>(),
                    "seed_patterns": names::<SeedPattern>(),
                    "patterns": names::<Pattern>(),
                    "mapping": "digest-be-mod-order-v1", "zero_scalar": "skipped",
                    "default_tag_bits": 24, "record_bytes": "tag_bytes + minimal seed-index bytes (6 bytes for one million seeds)",
                    "small_scalar_rule": "1..=small_max; baby-step giant-step; no downloaded table needed",
                }))?
            );
            Ok(0)
        }
    }
}

fn main() {
    let args = Args::parse();
    let mut builder = rayon::ThreadPoolBuilder::new();
    if let Some(threads) = args.threads {
        if threads == 0 {
            eprintln!("error: --threads must be positive");
            std::process::exit(1);
        }
        builder = builder.num_threads(threads);
    }
    let result = builder
        .build()
        .map_err(anyhow::Error::from)
        .and_then(|pool| pool.install(|| run(args)));
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_database_paths_are_opened_once_and_distinct_inputs_are_validated() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("weak-ca-db-inputs-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let valid_path = dir.join("valid.wkdb");
        let invalid_path = dir.join("invalid.wkdb");
        let pack = pack::Pack::from_bytes(pack::generate(
            Recipe::patterned(Curve::P256, Pattern::LowOnes, 0, 8),
            3,
        )?)?;
        Database::write(&valid_path, &[pack], false)?;
        let selected = read_packs(PackInputs {
            db: vec![valid_path.clone(), valid_path.clone()],
            ..PackInputs::default()
        })?;
        assert_eq!(selected.len(), 1);
        fs::write(&invalid_path, b"invalid")?;
        assert!(
            read_packs(PackInputs {
                db: vec![valid_path.clone(), invalid_path],
                ..PackInputs::default()
            })
            .is_err()
        );
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn independent_certificates_match_all_recipes_through_database_and_certificate_cli()
    -> Result<()> {
        let fixtures =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/reference-certificates");
        let index: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../tests/reference-certificates/index.json"))?;
        let dir = std::env::temp_dir().join(format!("weak-ca-reference-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let db_path = dir.join("reference.wkdb");
        let mut packs = Vec::new();
        for item in &index {
            let mut recipe: Recipe = serde_json::from_value(item["recipe"].clone())?;
            recipe.start = item["seed"].as_u64().unwrap() as u32;
            recipe.count = 1;
            assert_eq!(
                hex::encode(recipe.point(recipe.start)?.unwrap()),
                item["point"].as_str().unwrap()
            );
            packs.push(pack::Pack::from_bytes(pack::generate(recipe, 3)?)?);
        }
        Database::write(&db_path, &packs, true)?;
        let report_path = dir.join("report.json");
        let args = Args::try_parse_from([
            "weak-ca-check",
            "--force",
            "check",
            "--db",
            db_path.to_str().unwrap(),
            "--small-max",
            "0",
            "--fail-on-match",
            "--output",
            report_path.to_str().unwrap(),
            fixtures.to_str().unwrap(),
        ])?;
        assert_eq!(run(args)?, 2);
        let report: serde_json::Value = serde_json::from_slice(&fs::read(&report_path)?)?;
        assert_eq!(
            report["input_certificates"].as_u64(),
            Some(index.len() as u64)
        );
        assert!(report["input_errors"].as_array().unwrap().is_empty());
        assert_eq!(
            report["candidate_packs"].as_array().unwrap().len(),
            index.len()
        );
        for item in &index {
            let finding = report["findings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| {
                    f["certificates"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|c| c["certificate_sha256"] == item["certificate_sha256"])
                })
                .expect("reference certificate must be detected");
            assert!(finding["evidence"].as_array().unwrap().iter().any(|e| {
                e["seed"] == item["seed"]
                    && e["recipe"]["mapping"] == item["recipe"]["mapping"]
                    && e["recipe"]["hash"] == item["recipe"]["hash"]
                    && e["recipe"]["curve"] == item["recipe"]["curve"]
            }));
        }
        let one = fixtures.join(index[0]["file"].as_str().unwrap());
        let args = Args::try_parse_from([
            "weak-ca-check",
            "--force",
            "check",
            "--db",
            db_path.to_str().unwrap(),
            "--small-max",
            "0",
            "--cert",
            one.to_str().unwrap(),
            "--fail-on-match",
            "--output",
            report_path.to_str().unwrap(),
        ])?;
        assert_eq!(run(args)?, 2);
        let report: serde_json::Value = serde_json::from_slice(&fs::read(report_path)?)?;
        assert_eq!(report["input_certificates"], 1);
        assert_eq!(report["findings"].as_array().unwrap().len(), 1);
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn build_db_finds_synthetic_ca_from_a_seed_number_pattern() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("weak-ca-seed-pattern-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let db_path = dir.join("seed-pattern.wkdb");
        let invalid_db = dir.join("invalid.wkdb");
        let invalid = Args::try_parse_from([
            "weak-ca-check",
            "build-db",
            "--suite",
            "hashes",
            "--curve",
            "p384",
            "--hash",
            "sha256",
            "--seed-pattern",
            "repeat-byte",
            "--count",
            "1",
            "--class-count",
            "seed:repeat-byte=257",
            "--output",
            invalid_db.to_str().unwrap(),
        ])?;
        assert!(run(invalid).is_err());
        assert!(!invalid_db.exists());
        let args = Args::try_parse_from([
            "weak-ca-check",
            "build-db",
            "--suite",
            "hashes",
            "--curve",
            "p384",
            "--hash",
            "sha256",
            "--seed-pattern",
            "repeat-byte",
            "--count",
            "1",
            "--class-count",
            "seed:repeat-byte=256",
            "--output",
            db_path.to_str().unwrap(),
        ])?;
        assert_eq!(run(args)?, 0);

        let certificate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/seed-pattern-fixtures/seed-pattern-repeat-byte-p384.pem");
        let report_path = dir.join("report.json");
        let args = Args::try_parse_from([
            "weak-ca-check",
            "--force",
            "check",
            "--db",
            db_path.to_str().unwrap(),
            "--small-max",
            "0",
            "--cert",
            certificate.to_str().unwrap(),
            "--fail-on-match",
            "--output",
            report_path.to_str().unwrap(),
        ])?;
        assert_eq!(run(args)?, 2);
        let report: serde_json::Value = serde_json::from_slice(&fs::read(report_path)?)?;
        let evidence = report["findings"][0]["evidence"].as_array().unwrap();
        assert!(evidence.iter().any(|item| {
            item["kind"] == "hash-seed-pattern-recipe"
                && item["seed"] == 1
                && item["seed_number"] == 16_843_009u64
                && item["recipe"]["seed_pattern"] == "repeat-byte"
                && item["recipe"]["hash"] == "sha256"
                && item["recipe"]["curve"] == "p384"
        }));
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn explicit_cli_count_caps_a_finite_seed_domain() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("weak-ca-finite-count-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let db_path = dir.join("finite-count.wkdb");
        let args = Args::try_parse_from([
            "weak-ca-check",
            "build-db",
            "--suite",
            "hashes",
            "--curve",
            "p384",
            "--hash",
            "sha256",
            "--seed-pattern",
            "repeat-byte",
            "--count",
            "257",
            "--output",
            db_path.to_str().unwrap(),
        ])?;
        assert_eq!(run(args)?, 0);
        let packs = read_packs(PackInputs {
            db: vec![db_path],
            ..PackInputs::default()
        })?;
        assert_eq!(packs.len(), 1);
        assert_eq!(packs[0].header.recipe.count, 256);
        fs::remove_dir_all(dir)?;
        Ok(())
    }
}
