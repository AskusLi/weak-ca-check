use crate::recipe::{Recipe, point_tag};
use anyhow::{Context, Result, bail, ensure};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

const MAGIC: &[u8; 8] = b"WKPACK01";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub format_version: u32,
    pub recipe: Recipe,
    pub records: u64,
    pub record_bytes: u32,
    pub tag_bytes: u8,
    pub seed_bytes: u8,
    pub tag: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Record {
    tag: u64,
    seed: u32,
}

pub struct Pack {
    pub header: Header,
    bytes: Vec<u8>,
    offset: usize,
    pub sha256: String,
}

fn seed_bytes(recipe: &Recipe) -> u8 {
    let last = (u64::from(recipe.start) + recipe.count - 1) as u32;
    (32 - last.leading_zeros()).max(1).div_ceil(8) as u8
}

fn tag(curve: crate::recipe::Curve, point: &[u8], tag_bytes: u8) -> u64 {
    point_tag(curve, point) >> (64 - u32::from(tag_bytes) * 8)
}

pub fn generate(recipe: Recipe, tag_bytes: u8) -> Result<Vec<u8>> {
    recipe.validate()?;
    ensure!(
        [3, 4, 6, 8].contains(&tag_bytes),
        "tag width must be 24, 32, 48 or 64 bits"
    );
    let order = recipe.curve.order();
    let end = u64::from(recipe.start) + recipe.count;
    let records: Result<Vec<_>> = (u64::from(recipe.start)..end)
        .into_par_iter()
        .map(|seed| {
            let seed = seed as u32;
            let Some(scalar) = recipe.scalar(seed, &order) else {
                return Ok(None);
            };
            let point = recipe.curve.point(&scalar)?;
            Ok(Some(Record {
                tag: tag(recipe.curve, &point, tag_bytes),
                seed,
            }))
        })
        .collect();
    let mut records: Vec<_> = records?.into_iter().flatten().collect();
    records.par_sort_unstable();
    let seed_bytes = seed_bytes(&recipe);
    let header = Header {
        format_version: 1,
        recipe,
        records: records.len() as u64,
        record_bytes: u32::from(tag_bytes + seed_bytes),
        tag_bytes,
        seed_bytes,
        tag: "sha256-domain-v1-prefix-be".into(),
    };
    encode(&header, &records)
}

fn encode(header: &Header, records: &[Record]) -> Result<Vec<u8>> {
    let header_bytes = serde_json::to_vec(header)?;
    ensure!(header_bytes.len() <= 65536, "header too large");
    let mut bytes = Vec::with_capacity(
        12 + header_bytes.len() + records.len() * header.record_bytes as usize + 32,
    );
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&header_bytes);
    for record in records {
        bytes.extend_from_slice(&record.tag.to_be_bytes()[8 - header.tag_bytes as usize..]);
        bytes.extend_from_slice(&record.seed.to_be_bytes()[4 - header.seed_bytes as usize..]);
    }
    let digest = Sha256::digest(&bytes);
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

impl Pack {
    pub fn open(path: &Path) -> Result<Self> {
        Self::from_bytes(fs::read(path).with_context(|| format!("read {}", path.display()))?)
            .with_context(|| format!("invalid pack {}", path.display()))
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        ensure!(
            bytes.len() >= 44 && &bytes[..8] == MAGIC,
            "invalid pack magic or truncated file"
        );
        let header_len = u32::from_be_bytes(bytes[8..12].try_into()?) as usize;
        ensure!(header_len <= 65536, "header exceeds format limit");
        let offset = 12usize
            .checked_add(header_len)
            .context("header size overflow")?;
        ensure!(offset <= bytes.len() - 32, "truncated header");
        let header: Header = serde_json::from_slice(&bytes[12..offset])?;
        header.recipe.validate()?;
        ensure!(
            header.format_version == 1
                && [3, 4, 6, 8].contains(&header.tag_bytes)
                && header.seed_bytes == seed_bytes(&header.recipe)
                && header.record_bytes == u32::from(header.tag_bytes + header.seed_bytes)
                && header.tag == "sha256-domain-v1-prefix-be",
            "unsupported format"
        );
        ensure!(header.records <= header.recipe.count, "too many records");
        let records_len = usize::try_from(header.records)?
            .checked_mul(header.record_bytes as usize)
            .context("record length overflow")?;
        ensure!(
            offset
                .checked_add(records_len)
                .and_then(|v| v.checked_add(32))
                == Some(bytes.len()),
            "incorrect file length"
        );
        ensure!(
            Sha256::digest(&bytes[..bytes.len() - 32]).as_slice() == &bytes[bytes.len() - 32..],
            "checksum mismatch"
        );
        let sha256 = hex::encode(Sha256::digest(&bytes));
        let pack = Self {
            header,
            bytes,
            offset,
            sha256,
        };
        let mut previous = None;
        for i in 0..pack.len() {
            let record = pack.record(i);
            ensure!(
                pack.header.recipe.contains(record.seed),
                "seed outside recipe range"
            );
            if previous.is_some_and(|prev| prev >= record) {
                bail!("records are not strictly sorted");
            }
            previous = Some(record);
        }
        Ok(pack)
    }

    pub fn len(&self) -> usize {
        self.header.records as usize
    }

    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    fn record(&self, index: usize) -> Record {
        let p = self.offset + index * self.header.record_bytes as usize;
        let tag_end = p + self.header.tag_bytes as usize;
        let seed_end = tag_end + self.header.seed_bytes as usize;
        let mut tag = [0u8; 8];
        let mut seed = [0u8; 4];
        tag[8 - self.header.tag_bytes as usize..].copy_from_slice(&self.bytes[p..tag_end]);
        seed[4 - self.header.seed_bytes as usize..].copy_from_slice(&self.bytes[tag_end..seed_end]);
        Record {
            tag: u64::from_be_bytes(tag),
            seed: u32::from_be_bytes(seed),
        }
    }

    pub fn lookup(&self, point: &[u8]) -> Result<(Vec<u32>, usize)> {
        let tag = tag(self.header.recipe.curve, point, self.header.tag_bytes);
        let (mut low, mut high) = (0, self.len());
        while low < high {
            let mid = low + (high - low) / 2;
            if self.record(mid).tag < tag {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        let mut matches = Vec::new();
        let mut tag_hits = 0;
        while low < self.len() && self.record(low).tag == tag {
            let seed = self.record(low).seed;
            tag_hits += 1;
            // A truncated tag is only an index. A full curve-point comparison is mandatory.
            if self.header.recipe.point(seed)?.as_deref() == Some(point) {
                matches.push(seed);
            }
            low += 1;
        }
        Ok((matches, tag_hits))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recipe::{Curve, Hash, SeedEncoding};

    fn recipe() -> Recipe {
        Recipe {
            curve: Curve::P256,
            hash: Hash::Sha256,
            encoding: SeedEncoding::Decimal,
            mapping: "digest-be-mod-order-v1".into(),
            start: 0,
            count: 16,
        }
    }

    #[test]
    fn round_trip_and_boundary_seeds() -> Result<()> {
        let r = recipe();
        let pack = Pack::from_bytes(generate(r.clone(), 3)?)?;
        assert_eq!(pack.len(), 16);
        for seed in [0, 1, 15] {
            assert_eq!(pack.lookup(&r.point(seed)?.unwrap())?.0, vec![seed]);
        }
        assert!(pack.lookup(&r.point(16)?.unwrap())?.0.is_empty());
        assert_eq!(
            pack.byte_len(),
            44 + serde_json::to_vec(&pack.header)?.len() + 16 * pack.header.record_bytes as usize
        );
        Ok(())
    }

    #[test]
    fn corrupt_and_truncated_packs_are_rejected() -> Result<()> {
        let bytes = generate(recipe(), 3)?;
        let mut corrupt = bytes.clone();
        let end = corrupt.len() - 33;
        corrupt[end] ^= 1;
        assert!(Pack::from_bytes(corrupt).is_err());
        for end in [0, 8, 12, bytes.len() - 1] {
            assert!(Pack::from_bytes(bytes[..end].to_vec()).is_err());
        }
        Ok(())
    }

    #[test]
    fn tag_collision_is_not_a_weak_key_finding() -> Result<()> {
        let mut r = recipe();
        r.count = 1;
        let different_point = r.point(1)?.unwrap();
        let header = Header {
            format_version: 1,
            recipe: r.clone(),
            records: 1,
            record_bytes: 4,
            tag_bytes: 3,
            seed_bytes: 1,
            tag: "sha256-domain-v1-prefix-be".into(),
        };
        let records = [Record {
            tag: tag(r.curve, &different_point, 3),
            seed: 0,
        }];
        let pack = Pack::from_bytes(encode(&header, &records)?)?;
        let (matches, hits) = pack.lookup(&different_point)?;
        assert_eq!(hits, 1);
        assert!(matches.is_empty());
        Ok(())
    }

    #[test]
    fn generation_is_deterministic() -> Result<()> {
        assert_eq!(generate(recipe(), 3)?, generate(recipe(), 3)?);
        Ok(())
    }

    #[test]
    fn compact_seed_and_tag_widths_round_trip() -> Result<()> {
        for (start, expected_width) in [(255, 2), (65_535, 3), (u32::MAX - 1, 4)] {
            let mut r = recipe();
            r.start = start;
            r.count = 2;
            for tag_bytes in [3, 4, 6, 8] {
                let pack = Pack::from_bytes(generate(r.clone(), tag_bytes)?)?;
                assert_eq!(pack.header.seed_bytes, expected_width);
                for seed in [start, start + 1] {
                    assert_eq!(pack.lookup(&r.point(seed)?.unwrap())?.0, vec![seed]);
                }
            }
        }
        Ok(())
    }
}
