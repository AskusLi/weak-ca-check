use crate::{output::AtomicOutput, pack::Pack};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufReader, Read, Write},
    path::Path,
};

const MAGIC: &[u8; 8] = b"WKDB0001";
const MAX_INDEX: usize = 16 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    offset: u64,
    bytes: u64,
    sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u32,
    packs: Vec<Entry>,
}

pub struct Database {
    pub packs: Vec<Pack>,
    pub sha256: String,
    pub bytes: u64,
}

impl Database {
    pub fn write(path: &Path, packs: &[Pack], force: bool) -> Result<()> {
        let unique: BTreeMap<_, _> = packs.iter().map(|p| (p.sha256.as_str(), p)).collect();
        ensure!(
            !unique.is_empty() && unique.len() <= 10000,
            "database needs 1..=10000 unique packs"
        );
        let mut offset = 0u64;
        let mut entries = Vec::new();
        for pack in unique.values() {
            entries.push(Entry {
                offset,
                bytes: pack.byte_len() as u64,
                sha256: pack.sha256.clone(),
            });
            offset = offset
                .checked_add(pack.byte_len() as u64)
                .context("database size overflow")?;
        }
        let index = serde_json::to_vec(&Index {
            version: 1,
            packs: entries,
        })?;
        ensure!(index.len() <= MAX_INDEX, "database index exceeds limit");
        let mut output = AtomicOutput::new(path, force)?;
        let mut hash = Sha256::new();
        let mut append = |bytes: &[u8]| -> Result<()> {
            output.file.write_all(bytes)?;
            hash.update(bytes);
            Ok(())
        };
        append(MAGIC)?;
        append(&(index.len() as u32).to_be_bytes())?;
        append(&index)?;
        for pack in unique.values() {
            append(pack.bytes())?;
        }
        output.file.write_all(&hash.finalize())?;
        output.commit()
    }

    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("open database {}", path.display()))?;
        let file_len = file.metadata()?.len();
        ensure!(file_len >= 44, "truncated database");
        let mut reader = BufReader::new(file);
        let mut prefix = [0u8; 12];
        reader.read_exact(&mut prefix)?;
        ensure!(&prefix[..8] == MAGIC, "invalid database magic");
        let index_len = u32::from_be_bytes(prefix[8..].try_into()?) as usize;
        ensure!(
            index_len <= MAX_INDEX && index_len as u64 <= file_len - 44,
            "invalid database index length"
        );
        let mut index_bytes = vec![0; index_len];
        reader.read_exact(&mut index_bytes)?;
        let index: Index = serde_json::from_slice(&index_bytes)?;
        ensure!(
            index.version == 1 && !index.packs.is_empty() && index.packs.len() <= 10000,
            "unsupported database index"
        );
        let payload_len = file_len - 44 - index_len as u64;
        let mut offset = 0u64;
        let mut seen = BTreeSet::new();
        for entry in &index.packs {
            ensure!(
                entry.offset == offset && entry.bytes >= 44,
                "invalid database pack offsets"
            );
            ensure!(
                hex::decode(&entry.sha256)?.len() == 32 && seen.insert(&entry.sha256),
                "invalid or duplicate pack identity"
            );
            offset = offset
                .checked_add(entry.bytes)
                .context("database size overflow")?;
            ensure!(offset <= payload_len, "pack extends past database payload");
        }
        ensure!(offset == payload_len, "database contains unindexed bytes");
        let mut hash = Sha256::new();
        hash.update(prefix);
        hash.update(index_bytes);
        let mut packs = Vec::with_capacity(index.packs.len());
        for entry in index.packs {
            let mut bytes = vec![0; usize::try_from(entry.bytes)?];
            reader.read_exact(&mut bytes)?;
            hash.update(&bytes);
            let pack = Pack::from_bytes(bytes)?;
            ensure!(
                pack.sha256 == entry.sha256,
                "database pack identity mismatch"
            );
            packs.push(pack);
        }
        let mut trailer = [0u8; 32];
        reader.read_exact(&mut trailer)?;
        ensure!(
            hash.clone().finalize().as_slice() == trailer,
            "database checksum mismatch"
        );
        let mut extra = [0];
        ensure!(reader.read(&mut extra)? == 0, "trailing database bytes");
        hash.update(trailer);
        Ok(Self {
            packs,
            sha256: hex::encode(hash.finalize()),
            bytes: file_len,
        })
    }

    pub fn is_database(path: &Path) -> Result<bool> {
        let mut file = File::open(path)?;
        let mut magic = [0u8; 8];
        let n = file.read(&mut magic)?;
        Ok(n == 8 && &magic == MAGIC)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        pack,
        recipe::{Curve, Pattern, Recipe},
    };

    #[test]
    fn forged_index_sizes_and_offsets_are_rejected_before_pack_allocation() -> Result<()> {
        let path =
            std::env::temp_dir().join(format!("weak-ca-db-invalid-{}.wkdb", std::process::id()));
        for (offset, bytes) in [(1, 44), (0, u64::MAX), (0, 45)] {
            let index = serde_json::to_vec(&Index {
                version: 1,
                packs: vec![Entry {
                    offset,
                    bytes,
                    sha256: "00".repeat(32),
                }],
            })?;
            let mut data = MAGIC.to_vec();
            data.extend_from_slice(&(index.len() as u32).to_be_bytes());
            data.extend_from_slice(&index);
            data.extend_from_slice(&[0; 44]);
            let hash = Sha256::digest(&data);
            data.extend_from_slice(&hash);
            std::fs::write(&path, data)?;
            assert!(Database::open(&path).is_err());
        }
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn deterministic_merge_deduplicates_packs_and_rejects_corruption() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("weak-ca-db-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let make =
            |p| Pack::from_bytes(pack::generate(Recipe::patterned(Curve::P384, p, 0, 8), 3)?);
        let first = dir.join("first.wkdb");
        let second = dir.join("second.wkdb");
        Database::write(
            &first,
            &[
                make(Pattern::LowOnes)?,
                make(Pattern::RepeatByte)?,
                make(Pattern::LowOnes)?,
            ],
            true,
        )?;
        Database::write(
            &second,
            &[make(Pattern::RepeatByte)?, make(Pattern::LowOnes)?],
            true,
        )?;
        assert_eq!(std::fs::read(&first)?, std::fs::read(&second)?);
        let db = Database::open(&first)?;
        assert_eq!(db.packs.len(), 2);
        let point = Recipe::patterned(Curve::P384, Pattern::LowOnes, 0, 8)
            .point(7)?
            .unwrap();
        assert!(
            db.packs
                .iter()
                .any(|p| p.lookup(&point).unwrap().0.contains(&7))
        );
        let original = std::fs::read(&first)?;
        for length in [0, 8, 12, original.len() - 1] {
            std::fs::write(&second, &original[..length])?;
            assert!(Database::open(&second).is_err());
        }
        let mut corrupt = original.clone();
        let len = corrupt.len();
        corrupt[len - 1] ^= 1;
        std::fs::write(&second, corrupt)?;
        assert!(Database::open(&second).is_err());
        let mut corrupt = original;
        corrupt.extend_from_slice(b"extra");
        std::fs::write(&second, corrupt)?;
        assert!(Database::open(&second).is_err());
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
}
