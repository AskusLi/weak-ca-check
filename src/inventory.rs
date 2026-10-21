use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

/// Preserve the original inventory fields while joining the official PEM exports.
pub fn join(inventory: &Path, pem_paths: &[PathBuf]) -> Result<Vec<u8>> {
    let mut certificates = BTreeMap::new();
    for path in pem_paths {
        let mut reader = csv::Reader::from_path(path)?;
        let headers = reader.headers()?.clone();
        let fp = headers
            .iter()
            .position(|s| s == "SHA-256 Fingerprint")
            .context("missing PEM fingerprint column")?;
        let pem = headers
            .iter()
            .position(|s| s == "X.509 Certificate (PEM)")
            .context("missing PEM data column")?;
        for row in reader.records() {
            let row = row?;
            let text = &row[pem];
            let Some(start) = text.find("-----BEGIN CERTIFICATE-----") else {
                continue;
            };
            let end = text[start..]
                .find("-----END CERTIFICATE-----")
                .context("missing PEM end")?
                + start
                + "-----END CERTIFICATE-----".len();
            let fingerprint = row[fp].replace(':', "").to_ascii_lowercase();
            let certificate = text[start..end].to_owned();
            if let Some(previous) = certificates.insert(fingerprint, certificate.clone()) {
                ensure!(
                    previous == certificate,
                    "conflicting certificates share a reported fingerprint"
                );
            }
        }
    }
    let mut reader = csv::Reader::from_path(inventory)?;
    let mut headers = reader.headers()?.clone();
    let fp = headers
        .iter()
        .position(|s| s == "SHA-256 Fingerprint")
        .context("missing inventory fingerprint column")?;
    ensure!(
        !headers.iter().any(|s| s == "PEM Info"),
        "inventory already contains PEM Info"
    );
    headers.push_field("PEM Info");
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer.write_record(&headers)?;
    for row in reader.records() {
        let mut row = row?;
        let fingerprint = row[fp].replace(':', "").to_ascii_lowercase();
        row.push_field(
            certificates
                .get(&fingerprint)
                .map(String::as_str)
                .unwrap_or(""),
        );
        writer.write_record(&row)?;
    }
    Ok(writer.into_inner()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joined_inventory_preserves_status_and_missing_pem_errors() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("weak-ca-inventory-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let cert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/weak.pem");
        let cert = crate::scan::load(std::slice::from_ref(&cert_path), None)?
            .certificates
            .remove(0);
        let metadata = dir.join("inventory.csv");
        let pem = dir.join("pems.csv");
        let mut writer = csv::Writer::from_path(&metadata)?;
        writer.write_record([
            "CA Owner",
            "SHA-256 Fingerprint",
            "Revocation Status",
            "Certificate Record Type",
            "Status of Root Cert",
        ])?;
        writer.write_record([
            "Test owner",
            &cert.certificate_sha256,
            "Not Revoked",
            "Intermediate Certificate",
            "Mozilla: Included",
        ])?;
        writer.write_record([
            "Missing owner",
            &"00".repeat(32),
            "Revoked",
            "Intermediate Certificate",
            "Mozilla: Removed",
        ])?;
        writer.flush()?;
        let mut writer = csv::Writer::from_path(&pem)?;
        writer.write_record(["SHA-256 Fingerprint", "X.509 Certificate (PEM)"])?;
        writer.write_record([
            cert.certificate_sha256.as_str(),
            &std::fs::read_to_string(cert_path)?,
        ])?;
        writer.flush()?;
        let joined = dir.join("joined.csv");
        std::fs::write(&joined, join(&metadata, &[pem])?)?;
        let inputs = crate::scan::load(&[], Some(&joined))?;
        assert_eq!(inputs.certificates.len(), 1);
        assert_eq!(inputs.errors.len(), 1);
        assert_eq!(
            inputs.certificates[0].reported_revocation_status.as_deref(),
            Some("Not Revoked")
        );
        let report = crate::scan::check(inputs, &[], 10000)?;
        let current = report.current_inventory.unwrap();
        assert_eq!(current.certificate_count, 1);
        assert_eq!(current.distinct_ec_keys, 1);
        assert_eq!(current.with_included_root_metadata, 1);
        assert_eq!(current.findings.len(), 1);
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
}
