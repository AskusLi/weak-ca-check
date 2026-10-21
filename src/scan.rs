use crate::{
    pack::Pack,
    recipe::{Curve, Recipe, point_digest},
    small::SmallChecker,
};
use anyhow::{Context, Result, ensure};
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use x509_parser::{parse_x509_certificate, pem::Pem};

#[derive(Clone, Debug, Serialize)]
pub struct Certificate {
    pub source: String,
    pub common_name: String,
    pub issuer: String,
    pub owner: Option<String>,
    pub reported_revocation_date: Option<String>,
    pub certificate_sha256: String,
    pub spki_sha256: String,
    pub normalized_point_sha256: Option<String>,
    pub algorithm_oid: String,
    pub curve: Option<Curve>,
    pub is_ca: bool,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
    #[serde(skip)]
    pub point: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct InputError {
    pub source: String,
    pub error: String,
}

#[derive(Default)]
pub struct Inputs {
    pub certificates: Vec<Certificate>,
    pub errors: Vec<InputError>,
}

fn certificate(
    der: &[u8],
    source: String,
    owner: Option<String>,
    revoked: Option<String>,
) -> Result<Certificate> {
    let (remaining, cert) =
        parse_x509_certificate(der).map_err(|e| anyhow::anyhow!("X.509 parsing: {e}"))?;
    ensure!(remaining.is_empty(), "trailing bytes after DER certificate");
    let spki = cert.public_key();
    let algorithm_oid = spki.algorithm.algorithm.to_id_string();
    let curve = if algorithm_oid == "1.2.840.10045.2.1" {
        spki.algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .and_then(|oid| Curve::from_oid(&oid.to_id_string()))
    } else {
        None
    };
    let point = match curve {
        Some(curve) => curve.canonical_point(spki.subject_public_key.data.as_ref())?,
        None => Vec::new(),
    };
    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|v| v.as_str().ok())
        .unwrap_or("")
        .to_owned();
    let is_ca = cert
        .basic_constraints()
        .map_err(|e| anyhow::anyhow!("basic constraints: {e}"))?
        .is_some_and(|v| v.value.ca);
    Ok(Certificate {
        source,
        common_name,
        issuer: cert.issuer().to_string(),
        owner,
        reported_revocation_date: revoked,
        certificate_sha256: hex::encode(Sha256::digest(der)),
        spki_sha256: hex::encode(Sha256::digest(spki.raw)),
        normalized_point_sha256: curve.map(|curve| hex::encode(point_digest(curve, &point))),
        algorithm_oid,
        curve,
        is_ca,
        not_before_unix: cert.validity().not_before.timestamp(),
        not_after_unix: cert.validity().not_after.timestamp(),
        point,
    })
}

fn pem_certificates(bytes: &[u8], source: &str) -> Result<Vec<Certificate>> {
    let mut certs = Vec::new();
    for (i, pem) in Pem::iter_from_buffer(bytes).enumerate() {
        let pem = pem.map_err(|e| anyhow::anyhow!("PEM parsing: {e}"))?;
        ensure!(
            pem.label == "CERTIFICATE",
            "expected CERTIFICATE PEM block, got {}",
            pem.label
        );
        certs.push(certificate(
            &pem.contents,
            format!("{source}#{}", i + 1),
            None,
            None,
        )?);
    }
    ensure!(!certs.is_empty(), "no PEM certificates found");
    Ok(certs)
}

fn collect_paths(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(path)?.collect::<std::io::Result<_>>()?;
        entries.sort_by_key(|e| e.path());
        for entry in entries {
            let kind = entry.file_type()?;
            if kind.is_dir() {
                collect_paths(&entry.path(), files)?;
            } else if kind.is_file()
                && entry
                    .path()
                    .extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| {
                        ["pem", "crt", "cer", "der"].contains(&s.to_ascii_lowercase().as_str())
                    })
            {
                files.push(entry.path());
            }
        }
    } else {
        ensure!(path.is_file(), "input does not exist: {}", path.display());
        files.push(path.to_owned());
    }
    Ok(())
}

pub fn load(paths: &[PathBuf], csv_path: Option<&Path>) -> Result<Inputs> {
    let mut inputs = Inputs::default();
    let mut files = Vec::new();
    for path in paths {
        collect_paths(path, &mut files)?;
    }
    files.sort();
    files.dedup();
    for path in files {
        let source = path.display().to_string();
        let loaded = (|| -> Result<Vec<Certificate>> {
            let bytes = fs::read(&path)?;
            if bytes.starts_with(b"-----BEGIN") {
                pem_certificates(&bytes, &source)
            } else {
                Ok(vec![certificate(&bytes, source.clone(), None, None)?])
            }
        })();
        match loaded {
            Ok(certs) => inputs.certificates.extend(certs),
            Err(e) => inputs.errors.push(InputError {
                source,
                error: format!("{e:#}"),
            }),
        }
    }
    if let Some(path) = csv_path {
        let mut csv = csv::Reader::from_path(path).context("read CCADB CSV")?;
        let headers = csv.headers()?.clone();
        let column = |name: &str| {
            headers
                .iter()
                .position(|s| s == name)
                .with_context(|| format!("missing CSV column {name}"))
        };
        let pem_column = column("PEM Info")?;
        let fingerprint_column = column("SHA-256 Fingerprint")?;
        let owner_column = column("CA Owner")?;
        let revoked_column = headers.iter().position(|s| s == "Date of Revocation");
        for (i, row) in csv.records().enumerate() {
            let source = format!("{}:row:{}", path.display(), i + 2);
            let parsed = (|| -> Result<Certificate> {
                let row = row?;
                let text = &row[pem_column];
                let start = text
                    .find("-----BEGIN CERTIFICATE-----")
                    .context("missing certificate PEM")?;
                let end = text[start..]
                    .find("-----END CERTIFICATE-----")
                    .context("missing PEM end")?
                    + start
                    + "-----END CERTIFICATE-----".len();
                let (_, pem) = x509_parser::pem::parse_x509_pem(&text.as_bytes()[start..end])
                    .map_err(|e| anyhow::anyhow!("PEM parsing: {e}"))?;
                let cert = certificate(
                    &pem.contents,
                    source.clone(),
                    Some(row[owner_column].to_owned()),
                    revoked_column.map(|col| row[col].to_owned()),
                )?;
                ensure!(
                    cert.certificate_sha256
                        .eq_ignore_ascii_case(&row[fingerprint_column].replace(':', "")),
                    "CCADB fingerprint mismatch"
                );
                Ok(cert)
            })();
            match parsed {
                Ok(cert) => inputs.certificates.push(cert),
                Err(e) => inputs.errors.push(InputError {
                    source,
                    error: format!("{e:#}"),
                }),
            }
        }
    }
    ensure!(
        !inputs.certificates.is_empty() || !inputs.errors.is_empty(),
        "no certificates supplied"
    );
    Ok(inputs)
}

#[derive(Debug, Serialize)]
pub struct Evidence {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub small_scalar: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipe: Option<Recipe>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack_sha256: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub curve: Curve,
    pub normalized_point_sha256: String,
    pub certificates: Vec<Certificate>,
    pub evidence: Vec<Evidence>,
}

#[derive(Serialize)]
pub struct Report {
    pub tool_version: String,
    pub time_unix_seconds: u64,
    pub small_scalar_max_inclusive: u32,
    pub input_certificates: usize,
    pub supported_ec_certificates: usize,
    pub ec_certificates: Vec<Certificate>,
    pub unsupported_certificates: Vec<Certificate>,
    pub distinct_ec_keys: usize,
    pub covered_distinct_ec_keys: usize,
    pub pack_count: usize,
    pub exact_verification: bool,
    pub rejected_tag_collisions: usize,
    pub seconds: f64,
    pub findings: Vec<Finding>,
    pub input_errors: Vec<InputError>,
    pub limitations: Vec<String>,
}

pub fn check(inputs: Inputs, packs: &[Pack], small_max: u32) -> Result<Report> {
    let started = Instant::now();
    let mut keys: BTreeMap<(Curve, Vec<u8>), Vec<usize>> = BTreeMap::new();
    for (i, cert) in inputs.certificates.iter().enumerate() {
        if let Some(curve) = cert.curve {
            keys.entry((curve, cert.point.clone())).or_default().push(i);
        }
    }
    let curves: BTreeMap<_, _> = keys.keys().map(|(curve, _)| (*curve, ())).collect();
    let small: BTreeMap<_, _> = curves
        .keys()
        .filter(|_| small_max > 0)
        .map(|curve| (*curve, SmallChecker::new(*curve, small_max)))
        .collect();
    let checked: Result<Vec<_>> = keys
        .par_iter()
        .map(|((curve, point), indexes)| {
            let mut evidence = Vec::new();
            let mut rejected = 0;
            if let Some(checker) = small.get(curve)
                && let Some(scalar) = checker.find(point)?
            {
                evidence.push(Evidence {
                    kind: "small-scalar".into(),
                    small_scalar: Some(scalar),
                    recipe: None,
                    seed: None,
                    pack_sha256: None,
                });
            }
            for pack in packs.iter().filter(|p| p.header.recipe.curve == *curve) {
                let (seeds, hits) = pack.lookup(point)?;
                rejected += hits - seeds.len();
                for seed in seeds {
                    evidence.push(Evidence {
                        kind: pack.header.recipe.evidence_kind().into(),
                        small_scalar: None,
                        recipe: Some(pack.header.recipe.clone()),
                        seed: Some(seed),
                        pack_sha256: Some(pack.sha256.clone()),
                    });
                }
            }
            let finding = (!evidence.is_empty()).then(|| Finding {
                curve: *curve,
                normalized_point_sha256: hex::encode(point_digest(*curve, point)),
                certificates: indexes
                    .iter()
                    .map(|&i| inputs.certificates[i].clone())
                    .collect(),
                evidence,
            });
            Ok((finding, rejected))
        })
        .collect();
    let checked = checked?;
    let rejected_tag_collisions = checked.iter().map(|(_, count)| count).sum();
    let mut findings: Vec<_> = checked
        .into_iter()
        .filter_map(|(finding, _)| finding)
        .collect();
    findings.sort_by(|a, b| {
        (a.curve, &a.normalized_point_sha256).cmp(&(b.curve, &b.normalized_point_sha256))
    });
    Ok(Report {
        tool_version: env!("CARGO_PKG_VERSION").into(),
        time_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        small_scalar_max_inclusive: small_max,
        input_certificates: inputs.certificates.len(),
        supported_ec_certificates: inputs.certificates.iter().filter(|c| c.curve.is_some()).count(),
        ec_certificates: inputs.certificates.iter().filter(|c| c.curve.is_some()).cloned().collect(),
        unsupported_certificates: inputs.certificates.iter().filter(|c| c.curve.is_none()).cloned().collect(),
        distinct_ec_keys: keys.len(),
        covered_distinct_ec_keys: keys.keys().filter(|(c,_)| small_max > 0 || packs.iter().any(|p| p.header.recipe.curve == *c)).count(),
        pack_count: packs.len(), exact_verification: true, rejected_tag_collisions,
        seconds: started.elapsed().as_secs_f64(), findings, input_errors: inputs.errors,
        limitations: vec![
            "Only the reported curves, scalar interval and exact pack recipes are checked.".into(),
            "No match is not proof of adequate entropy or a secure RNG.".into(),
            "RSA and unsupported EC curves are explicitly outside this check.".into(),
            "This does not validate certificate signatures, trust chains, expiry or live revocation status.".into(),
            "A candidate match establishes a weak-key match, not how the CA originally generated it.".into(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cross_certificates_share_one_verified_key_finding() -> Result<()> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let inputs = load(&[path], None)?;
        assert_eq!(inputs.certificates.len(), 4);
        assert!(inputs.errors.is_empty());
        let report = check(inputs, &[], 10_000)?;
        assert_eq!(report.supported_ec_certificates, 3);
        assert_eq!(report.distinct_ec_keys, 2);
        assert_eq!(report.unsupported_certificates.len(), 1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].certificates.len(), 2);
        assert!(
            report.findings[0].evidence[0]
                .small_scalar
                .is_some_and(|s| s < 256)
        );
        Ok(())
    }

    #[test]
    fn malformed_der_and_non_certificate_pem_are_errors() {
        assert!(certificate(b"bad DER", "test".into(), None, None).is_err());
        assert!(
            pem_certificates(
                b"-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n",
                "test"
            )
            .is_err()
        );
    }
}
