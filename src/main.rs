mod pack;
mod recipe;
mod scan;
mod small;

use anyhow::{Result, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use recipe::{Curve, Hash, Recipe, SeedEncoding};
use std::{fs, path::PathBuf, time::Instant};

#[derive(Parser)]
#[command(
    version,
    about = "Offline checks for defined weak EC key-generation recipes"
)]
struct Args {
    /// Worker threads; defaults to available CPUs.
    #[arg(long, global = true)]
    threads: Option<usize>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a deterministic compact hash-counter candidate pack.
    Generate {
        #[arg(long, value_enum)]
        curve: Curve,
        #[arg(long, value_enum)]
        hash: Hash,
        #[arg(long, value_enum, default_value = "decimal")]
        encoding: SeedEncoding,
        #[arg(long, default_value_t = 0)]
        start: u32,
        #[arg(long, default_value_t = 100_000)]
        count: u64,
        /// Lookup tag width. Every hit is verified against the full public key.
        #[arg(long, default_value_t = 24)]
        tag_bits: u8,
        #[arg(long)]
        output: PathBuf,
    },
    /// Check public certificates in files, directories or a CCADB CSV.
    Check {
        /// Repeat for multiple candidate packs.
        #[arg(long)]
        pack: Vec<PathBuf>,
        /// Load every .wkp file directly inside each directory.
        #[arg(long)]
        pack_dir: Vec<PathBuf>,
        /// Inclusive small-scalar bound; zero disables this rule.
        #[arg(long, default_value_t = 1_000_000)]
        small_max: u32,
        #[arg(long)]
        ccadb: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        /// Exit with status 2 when an exactly verified weak-key match is found.
        #[arg(long)]
        fail_on_match: bool,
        certificates: Vec<PathBuf>,
    },
    /// Validate and describe a candidate pack.
    Inspect { pack: PathBuf },
    /// List supported curves, hashes and seed encodings.
    Recipes,
}

fn write_output(path: Option<PathBuf>, bytes: &[u8]) -> Result<()> {
    if let Some(path) = path {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, bytes)?;
    } else {
        use std::io::Write;
        std::io::stdout().lock().write_all(bytes)?;
    }
    Ok(())
}

fn run(args: Args) -> Result<i32> {
    match args.command {
        Command::Generate {
            curve,
            hash,
            encoding,
            start,
            count,
            tag_bits,
            output,
        } => {
            ensure!(
                [24, 32, 48, 64].contains(&tag_bits),
                "--tag-bits must be 24, 32, 48 or 64"
            );
            let recipe = Recipe {
                curve,
                hash,
                encoding,
                start,
                count,
                mapping: "digest-be-mod-order-v1".into(),
            };
            let started = Instant::now();
            eprintln!("Generating {count} candidate seeds for {curve:?}/{hash:?}/{encoding:?}");
            let bytes = pack::generate(recipe, tag_bits / 8)?;
            let pack = pack::Pack::from_bytes(bytes.clone())?;
            write_output(Some(output), &bytes)?;
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
            pack: mut paths,
            pack_dir,
            small_max,
            ccadb,
            output,
            fail_on_match,
            certificates,
        } => {
            for directory in pack_dir {
                let mut count = 0;
                for entry in fs::read_dir(&directory)? {
                    let entry = entry?;
                    if entry.file_type()?.is_file()
                        && entry.path().extension().is_some_and(|e| e == "wkp")
                    {
                        paths.push(entry.path());
                        count += 1;
                    }
                }
                ensure!(count > 0, "no .wkp packs in {}", directory.display());
            }
            paths.sort();
            paths.dedup();
            ensure!(
                small_max > 0 || !paths.is_empty(),
                "select a small-scalar rule or at least one pack"
            );
            ensure!(
                ccadb.is_some() || !certificates.is_empty(),
                "supply certificates or --ccadb"
            );
            let started = Instant::now();
            let packs: Vec<_> = paths
                .iter()
                .map(|p| pack::Pack::open(p))
                .collect::<Result<_>>()?;
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
            write_output(output, &bytes)?;
            Ok(if has_errors {
                1
            } else if fail_on_match && has_matches {
                2
            } else {
                0
            })
        }
        Command::Inspect { pack: path } => {
            let pack = pack::Pack::open(&path)?;
            let mut bytes = serde_json::to_vec_pretty(&serde_json::json!({
                "header": pack.header, "file_bytes": pack.byte_len(), "sha256": pack.sha256,
            }))?;
            bytes.push(b'\n');
            write_output(None, &bytes)?;
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
                    "mapping": "digest-be-mod-order-v1", "zero_scalar": "skipped",
                    "default_tag_bits": 24, "record_bytes": "tag_bytes + minimal seed bytes (6 bytes for 100000 seeds)",
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
