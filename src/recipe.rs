use anyhow::{Context, Result, ensure};
use clap::ValueEnum;
use num_bigint::BigUint;
use num_traits::Zero;
use p384::elliptic_curve::{Curve as _, sec1::ToSec1Point};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
pub enum Curve {
    P256,
    P384,
    P521,
}

impl Curve {
    pub fn scalar_bytes(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }

    pub fn scalar_bits(self) -> u64 {
        match self {
            Self::P256 => 256,
            Self::P384 => 384,
            Self::P521 => 521,
        }
    }
    pub fn from_oid(oid: &str) -> Option<Self> {
        match oid {
            "1.2.840.10045.3.1.7" => Some(Self::P256),
            "1.3.132.0.34" => Some(Self::P384),
            "1.3.132.0.35" => Some(Self::P521),
            _ => None,
        }
    }

    pub fn order(self) -> BigUint {
        match self {
            Self::P256 => BigUint::from_bytes_be(&p256::NistP256::ORDER.to_be_bytes()),
            Self::P384 => BigUint::from_bytes_be(&p384::NistP384::ORDER.to_be_bytes()),
            Self::P521 => BigUint::from_bytes_be(&p521::NistP521::ORDER.to_be_bytes()),
        }
    }

    pub fn point(self, scalar: &BigUint) -> Result<Vec<u8>> {
        let raw = scalar.to_bytes_be();
        let size = self.scalar_bytes();
        ensure!(raw.len() <= size, "scalar is too large for {self:?}");
        let mut bytes = vec![0; size];
        bytes[size - raw.len()..].copy_from_slice(&raw);
        Ok(match self {
            Self::P256 => p256::SecretKey::from_slice(&bytes)
                .context("invalid P-256 scalar")?
                .public_key()
                .to_sec1_point(true)
                .as_bytes()
                .to_vec(),
            Self::P384 => p384::SecretKey::from_slice(&bytes)
                .context("invalid P-384 scalar")?
                .public_key()
                .to_sec1_point(true)
                .as_bytes()
                .to_vec(),
            Self::P521 => p521::SecretKey::from_slice(&bytes)
                .context("invalid P-521 scalar")?
                .public_key()
                .to_sec1_point(true)
                .as_bytes()
                .to_vec(),
        })
    }

    pub fn canonical_point(self, point: &[u8]) -> Result<Vec<u8>> {
        Ok(match self {
            Self::P256 => p256::PublicKey::from_sec1_bytes(point)
                .context("invalid P-256 public key")?
                .to_sec1_point(true)
                .as_bytes()
                .to_vec(),
            Self::P384 => p384::PublicKey::from_sec1_bytes(point)
                .context("invalid P-384 public key")?
                .to_sec1_point(true)
                .as_bytes()
                .to_vec(),
            Self::P521 => p521::PublicKey::from_sec1_bytes(point)
                .context("invalid P-521 public key")?
                .to_sec1_point(true)
                .as_bytes()
                .to_vec(),
        })
    }

    fn domain_id(self) -> u8 {
        match self {
            Self::P256 => 1,
            Self::P384 => 2,
            Self::P521 => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Pattern {
    RepeatByte,
    RepeatU16be,
    PrefixU32be,
    OrderMinusCounter,
    SingleBit,
}

impl Pattern {
    pub fn mapping(self) -> &'static str {
        match self {
            Self::RepeatByte => "repeat-byte-mod-order-v1",
            Self::RepeatU16be => "repeat-u16be-mod-order-v1",
            Self::PrefixU32be => "prefix-u32be-mod-order-v1",
            Self::OrderMinusCounter => "order-minus-counter-v1",
            Self::SingleBit => "single-bit-v1",
        }
    }

    pub fn from_mapping(mapping: &str) -> Option<Self> {
        [
            Self::RepeatByte,
            Self::RepeatU16be,
            Self::PrefixU32be,
            Self::OrderMinusCounter,
            Self::SingleBit,
        ]
        .into_iter()
        .find(|p| p.mapping() == mapping)
    }

    pub fn limit(self, curve: Curve) -> u64 {
        match self {
            Self::RepeatByte => 256,
            Self::RepeatU16be => 65_536,
            Self::SingleBit => curve.scalar_bits(),
            _ => u64::from(u32::MAX) + 1,
        }
    }

    pub fn default_count(self, curve: Curve) -> u64 {
        self.limit(curve).min(100_000)
    }

    /// Linear recipes have scalar(seed) = seed * multiplier modulo the order.
    pub fn multiplier(self, curve: Curve) -> Option<BigUint> {
        let size = curve.scalar_bytes();
        Some(match self {
            Self::RepeatByte => BigUint::from_bytes_be(&vec![1; size]),
            Self::RepeatU16be => BigUint::from_bytes_be(&[0, 1].repeat(size / 2)),
            Self::PrefixU32be => BigUint::from(1u8) << (8 * (size - 4)),
            Self::OrderMinusCounter => curve.order() - BigUint::from(1u8),
            Self::SingleBit => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Hash {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    #[serde(rename = "sha512-224")]
    #[value(name = "sha512-224")]
    Sha512224,
    #[serde(rename = "sha512-256")]
    #[value(name = "sha512-256")]
    Sha512256,
    #[serde(rename = "sha3-256")]
    #[value(name = "sha3-256")]
    Sha3256,
    #[serde(rename = "sha3-384")]
    #[value(name = "sha3-384")]
    Sha3384,
    #[serde(rename = "sha3-512")]
    #[value(name = "sha3-512")]
    Sha3512,
    Blake2b512,
    Blake2s256,
}

impl Hash {
    pub fn digest(self, input: &[u8]) -> Vec<u8> {
        macro_rules! digest {
            ($module:ident, $name:ident) => {
                <$module::$name as $module::Digest>::digest(input).to_vec()
            };
        }
        match self {
            Self::Md5 => digest!(md5, Md5),
            Self::Sha1 => digest!(sha1, Sha1),
            Self::Sha224 => digest!(sha2, Sha224),
            Self::Sha256 => digest!(sha2, Sha256),
            Self::Sha384 => digest!(sha2, Sha384),
            Self::Sha512 => digest!(sha2, Sha512),
            Self::Sha512224 => digest!(sha2, Sha512_224),
            Self::Sha512256 => digest!(sha2, Sha512_256),
            Self::Sha3256 => digest!(sha3, Sha3_256),
            Self::Sha3384 => digest!(sha3, Sha3_384),
            Self::Sha3512 => digest!(sha3, Sha3_512),
            Self::Blake2b512 => digest!(blake2, Blake2b512),
            Self::Blake2s256 => digest!(blake2, Blake2s256),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum SeedEncoding {
    Decimal,
    U32be,
    U32le,
    U64be,
    U64le,
}

impl SeedEncoding {
    pub fn encode(self, seed: u32) -> Vec<u8> {
        match self {
            Self::Decimal => seed.to_string().into_bytes(),
            Self::U32be => seed.to_be_bytes().to_vec(),
            Self::U32le => seed.to_le_bytes().to_vec(),
            Self::U64be => u64::from(seed).to_be_bytes().to_vec(),
            Self::U64le => u64::from(seed).to_le_bytes().to_vec(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipe {
    pub curve: Curve,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<SeedEncoding>,
    pub mapping: String,
    pub start: u32,
    pub count: u64,
}

impl Recipe {
    pub fn pattern(&self) -> Option<Pattern> {
        Pattern::from_mapping(&self.mapping)
    }

    pub fn patterned(curve: Curve, pattern: Pattern, start: u32, count: u64) -> Self {
        Self {
            curve,
            hash: None,
            encoding: None,
            mapping: pattern.mapping().into(),
            start,
            count,
        }
    }

    pub fn evidence_kind(&self) -> &'static str {
        if self.pattern().is_some() {
            "pattern-recipe"
        } else {
            "hash-counter-recipe"
        }
    }

    pub fn validate(&self) -> Result<()> {
        let limit = if let Some(pattern) = self.pattern() {
            ensure!(
                self.hash.is_none() && self.encoding.is_none(),
                "pattern recipes cannot specify a hash or encoding"
            );
            pattern.limit(self.curve)
        } else {
            ensure!(
                self.mapping == "digest-be-mod-order-v1",
                "unknown scalar mapping"
            );
            ensure!(
                self.hash.is_some() && self.encoding.is_some(),
                "hash recipes require hash and encoding"
            );
            u64::from(u32::MAX) + 1
        };
        ensure!(self.count > 0, "count must be positive");
        ensure!(
            u64::from(self.start)
                .checked_add(self.count)
                .is_some_and(|end| end <= limit),
            "seed range exceeds recipe limit {limit}"
        );
        Ok(())
    }

    pub fn contains(&self, seed: u32) -> bool {
        u64::from(seed) >= u64::from(self.start)
            && u64::from(seed) < u64::from(self.start) + self.count
    }

    pub fn scalar(&self, seed: u32, order: &BigUint) -> Option<BigUint> {
        let scalar = if let Some(pattern) = self.pattern() {
            match pattern.multiplier(self.curve) {
                Some(multiplier) => (BigUint::from(seed) * multiplier) % order,
                None => (BigUint::from(1u8) << seed as usize) % order,
            }
        } else {
            BigUint::from_bytes_be(
                &self
                    .hash
                    .expect("validated hash")
                    .digest(&self.encoding.expect("validated encoding").encode(seed)),
            ) % order
        };
        (!scalar.is_zero()).then_some(scalar)
    }

    pub fn point(&self, seed: u32) -> Result<Option<Vec<u8>>> {
        self.scalar(seed, &self.curve.order())
            .map(|d| self.curve.point(&d))
            .transpose()
    }
}

pub fn point_digest(curve: Curve, point: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"weak-ca-check/point/v1\0");
    hash.update([curve.domain_id()]);
    hash.update(point);
    hash.finalize().into()
}

pub fn point_tag(curve: Curve, point: &[u8]) -> u64 {
    u64::from_be_bytes(
        point_digest(curve, point)[..8]
            .try_into()
            .expect("eight bytes"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_match_independent_python_openssl_vectors() -> Result<()> {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/pattern-vectors.json"))?;
        for vector in vectors.as_array().unwrap() {
            let curve: Curve = serde_json::from_value(vector["curve"].clone())?;
            let pattern: Pattern = serde_json::from_value(vector["pattern"].clone())?;
            let seed = vector["seed"].as_u64().unwrap() as u32;
            let recipe = Recipe::patterned(curve, pattern, seed, 1);
            recipe.validate()?;
            assert_eq!(
                hex::encode(recipe.point(seed)?.unwrap()),
                vector["point"].as_str().unwrap()
            );
        }
        Ok(())
    }

    #[test]
    fn pattern_limits_and_recipe_fields_are_enforced() {
        for (pattern, limit) in [
            (Pattern::RepeatByte, 256),
            (Pattern::RepeatU16be, 65536),
            (Pattern::SingleBit, 521),
        ] {
            let mut recipe = Recipe::patterned(Curve::P521, pattern, 0, limit);
            assert!(recipe.validate().is_ok());
            recipe.count += 1;
            assert!(recipe.validate().is_err());
            recipe.count -= 1;
            recipe.hash = Some(Hash::Sha256);
            assert!(recipe.validate().is_err());
        }
    }

    #[test]
    fn recipes_match_independent_python_openssl_vectors() -> Result<()> {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/recipe-vectors.json"))?;
        for vector in vectors.as_array().unwrap() {
            let recipe = Recipe {
                curve: serde_json::from_value(vector["curve"].clone())?,
                hash: Some(serde_json::from_value(vector["hash"].clone())?),
                encoding: Some(serde_json::from_value(vector["encoding"].clone())?),
                mapping: "digest-be-mod-order-v1".into(),
                start: 0,
                count: 100_000,
            };
            let actual = recipe
                .point(vector["seed"].as_u64().unwrap() as u32)?
                .unwrap();
            assert_eq!(hex::encode(actual), vector["point"].as_str().unwrap());
        }
        Ok(())
    }

    #[test]
    fn all_hashes_match_python_hashlib_vectors() -> Result<()> {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/digest-vectors.json"))?;
        for (name, expected) in vectors.as_object().unwrap() {
            let hash: Hash = serde_json::from_value(serde_json::Value::String(name.clone()))?;
            assert_eq!(hex::encode(hash.digest(b"0")), expected.as_str().unwrap());
        }
        Ok(())
    }

    #[test]
    fn range_validation_rejects_overflow_and_unknown_mappings() {
        let mut r = Recipe {
            curve: Curve::P384,
            hash: Some(Hash::Sha256),
            encoding: Some(SeedEncoding::Decimal),
            mapping: "digest-be-mod-order-v1".into(),
            start: u32::MAX,
            count: 1,
        };
        assert!(r.validate().is_ok());
        r.count = 2;
        assert!(r.validate().is_err());
        r.start = 0;
        r.count = 0;
        assert!(r.validate().is_err());
        r.count = 1;
        r.mapping = "guess".into();
        assert!(r.validate().is_err());
    }
}
