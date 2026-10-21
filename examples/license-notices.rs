//! Release packaging helper. Requires Cargo and downloaded dependency sources.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use std::{fs, path::PathBuf, process::Command};
#[path = "../src/output.rs"]
mod output;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    target: Option<String>,
    #[arg(long, default_value = "dist/THIRD_PARTY_NOTICES.txt")]
    output: PathBuf,
    #[arg(long)]
    force: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut command = Command::new("cargo");
    command.args(["metadata", "--locked", "--format-version", "1"]);
    if let Some(target) = args.target {
        command.args(["--filter-platform", &target]);
    }
    let result = command.output().context("run cargo metadata")?;
    ensure!(
        result.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let metadata: serde_json::Value = serde_json::from_slice(&result.stdout)?;
    let mut packages = metadata["packages"]
        .as_array()
        .context("missing cargo packages")?
        .iter()
        .collect::<Vec<_>>();
    packages.sort_by_key(|p| (p["name"].as_str(), p["version"].as_str()));
    let mut text =
        "THIRD-PARTY DEPENDENCY LICENSE NOTICES\n\nGenerated from Cargo.lock dependency sources.\n"
            .to_owned();
    for package in packages {
        let name = package["name"].as_str().context("package name")?;
        if name == "weak-ca-check" {
            continue;
        }
        let version = package["version"].as_str().context("package version")?;
        let manifest = PathBuf::from(package["manifest_path"].as_str().context("manifest path")?);
        let mut files = fs::read_dir(manifest.parent().context("manifest directory")?)?
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .map(|e| e.path())
            .filter(|p| {
                let name = p
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_ascii_uppercase();
                p.is_file()
                    && ["LICENSE", "LICENCE", "COPYING", "NOTICE"]
                        .iter()
                        .any(|prefix| name.starts_with(prefix))
            })
            .collect::<Vec<_>>();
        files.sort();
        if files.is_empty() && name == "asn1-rs-impl" && version == "0.2.0" {
            // Published subcrate omits the repository-root MIT license.
            // Upstream blob: 290e7b9be19d39a81c8eb24c75a6b5f1e57fea71.
            files.push(
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("licenses/asn1-rs-impl-MIT.txt"),
            );
        }
        ensure!(!files.is_empty(), "no license text for {name} {version}");
        text.push_str(&format!(
            "\n{}\n{name} {version} ({})\n",
            "=".repeat(72),
            package["license"].as_str().unwrap_or("unspecified")
        ));
        for path in files {
            text.push_str(&format!(
                "\n--- {} ---\n{}\n",
                path.file_name().unwrap_or_default().to_string_lossy(),
                String::from_utf8_lossy(&fs::read(&path)?)
            ));
        }
    }
    output::write(&args.output, text.as_bytes(), args.force)
}
