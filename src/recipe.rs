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
    RepeatU32be,
    PrefixU16be,
    LowOnes,
    AllOnesMinusCounter,
    ClearBit,
}

impl Pattern {
    pub const ALL: [Self; 10] = [
        Self::RepeatByte,
        Self::RepeatU16be,
        Self::PrefixU32be,
        Self::OrderMinusCounter,
        Self::SingleBit,
        Self::RepeatU32be,
        Self::PrefixU16be,
        Self::LowOnes,
        Self::AllOnesMinusCounter,
        Self::ClearBit,
    ];

    pub fn mapping(self) -> &'static str {
        match self {
            Self::RepeatByte => "repeat-byte-mod-order-v1",
            Self::RepeatU16be => "repeat-u16be-mod-order-v1",
            Self::PrefixU32be => "prefix-u32be-mod-order-v1",
            Self::OrderMinusCounter => "order-minus-counter-v1",
            Self::SingleBit => "single-bit-v1",
            Self::RepeatU32be => "repeat-u32be-mod-order-v1",
            Self::PrefixU16be => "prefix-u16be-mod-order-v1",
            Self::LowOnes => "low-ones-mod-order-v1",
            Self::AllOnesMinusCounter => "all-ones-minus-counter-mod-order-v1",
            Self::ClearBit => "clear-bit-mod-order-v1",
        }
    }

    pub fn from_mapping(mapping: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.mapping() == mapping)
    }

    pub fn limit(self, curve: Curve) -> u64 {
        match self {
            Self::RepeatByte => 256,
            Self::RepeatU16be | Self::PrefixU16be => 65_536,
            Self::SingleBit | Self::LowOnes | Self::ClearBit => curve.scalar_bits(),
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
            Self::RepeatU32be => BigUint::from_bytes_be(&[0, 0, 0, 1].repeat(size / 4)),
            Self::PrefixU16be => BigUint::from(1u8) << (8 * (size - 2)),
            Self::AllOnesMinusCounter => curve.order() - BigUint::from(1u8),
            Self::SingleBit | Self::LowOnes | Self::ClearBit => return None,
        })
    }

    /// Q(seed + 1) = (double ? 2*Q(seed) : Q(seed)) + increment*G.
    pub fn recurrence(self, curve: Curve) -> (bool, BigUint) {
        match self {
            Self::SingleBit => (true, BigUint::zero()),
            Self::LowOnes => (true, BigUint::from(1u8)),
            Self::ClearBit => {
                let order = curve.order();
                let mask = ((BigUint::from(1u8) << curve.scalar_bits() as usize)
                    - BigUint::from(1u8))
                    % &order;
                (true, (&order - mask) % &order)
            }
            _ => (false, self.multiplier(curve).expect("linear pattern")),
        }
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
    pub fn encode(self, seed: u64) -> Result<Vec<u8>> {
        Ok(match self {
            Self::Decimal => seed.to_string().into_bytes(),
            Self::U32be => u32::try_from(seed)
                .context("seed number exceeds u32 encoding")?
                .to_be_bytes()
                .to_vec(),
            Self::U32le => u32::try_from(seed)
                .context("seed number exceeds u32 encoding")?
                .to_le_bytes()
                .to_vec(),
            Self::U64be => seed.to_be_bytes().to_vec(),
            Self::U64le => seed.to_le_bytes().to_vec(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum SeedPattern {
    Counter,
    RepeatByte,
    RepeatU16be,
    SingleBit,
    LowOnes,
    RepeatDigit,
    DigitWalk,
}

impl SeedPattern {
    pub const ALL: [Self; 7] = [
        Self::Counter,
        Self::RepeatByte,
        Self::RepeatU16be,
        Self::SingleBit,
        Self::LowOnes,
        Self::RepeatDigit,
        Self::DigitWalk,
    ];

    pub fn limit(self, encoding: SeedEncoding) -> u64 {
        let narrow = matches!(encoding, SeedEncoding::U32be | SeedEncoding::U32le);
        match self {
            Self::Counter => u64::from(u32::MAX) + 1,
            Self::RepeatByte => 256,
            Self::RepeatU16be => 65536,
            Self::SingleBit | Self::LowOnes => {
                if narrow {
                    32
                } else {
                    64
                }
            }
            Self::RepeatDigit => {
                if narrow {
                    4
                } else {
                    10
                }
            }
            Self::DigitWalk => {
                if narrow {
                    19
                } else {
                    20
                }
            }
        }
    }

    pub fn value(self, index: u32) -> Result<u64> {
        ensure!(
            u64::from(index) < self.limit(SeedEncoding::Decimal),
            "seed-pattern index outside its domain"
        );
        Ok(match self {
            Self::Counter => u64::from(index),
            Self::RepeatByte => u64::from(index) * 0x01010101,
            Self::RepeatU16be => u64::from(index) * 0x00010001,
            Self::SingleBit => 1u64 << index,
            Self::LowOnes => u64::MAX >> (63 - index),
            Self::RepeatDigit => u64::from(index) * 1_111_111_111,
            Self::DigitWalk => {
                let length = index % 10 + 1;
                let mut value = 0;
                for i in 0..length {
                    let digit = if index < 10 { (i + 1) % 10 } else { 9 - i };
                    value = value * 10 + u64::from(digit);
                }
                value
            }
        })
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_pattern: Option<SeedPattern>,
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
            seed_pattern: None,
            mapping: pattern.mapping().into(),
            start,
            count,
        }
    }

    pub fn evidence_kind(&self) -> &'static str {
        if self.pattern().is_some() {
            "pattern-recipe"
        } else if self.seed_pattern.is_some() {
            "hash-seed-pattern-recipe"
        } else {
            "hash-counter-recipe"
        }
    }

    pub fn validate(&self) -> Result<()> {
        let limit = if let Some(pattern) = self.pattern() {
            ensure!(
                self.hash.is_none() && self.encoding.is_none() && self.seed_pattern.is_none(),
                "scalar pattern recipes cannot specify hash seed fields"
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
            self.seed_pattern
                .unwrap_or(SeedPattern::Counter)
                .limit(self.encoding.context("hash recipe encoding")?)
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

    pub fn seed_number(&self, index: u32) -> Result<u64> {
        self.seed_pattern
            .unwrap_or(SeedPattern::Counter)
            .value(index)
    }

    pub fn scalar(&self, seed: u32, order: &BigUint) -> Result<Option<BigUint>> {
        let scalar = if let Some(pattern) = self.pattern() {
            match pattern {
                Pattern::AllOnesMinusCounter => {
                    ((BigUint::from(1u8) << (8 * self.curve.scalar_bytes()))
                        - BigUint::from(1u8)
                        - BigUint::from(seed))
                        % order
                }
                Pattern::LowOnes => {
                    ((BigUint::from(1u8) << (seed as usize + 1)) - BigUint::from(1u8)) % order
                }
                Pattern::ClearBit => {
                    ((BigUint::from(1u8) << self.curve.scalar_bits() as usize)
                        - BigUint::from(1u8)
                        - (BigUint::from(1u8) << seed as usize))
                        % order
                }
                _ => match pattern.multiplier(self.curve) {
                    Some(multiplier) => (BigUint::from(seed) * multiplier) % order,
                    None => (BigUint::from(1u8) << seed as usize) % order,
                },
            }
        } else {
            BigUint::from_bytes_be(
                &self.hash.context("hash recipe hash")?.digest(
                    &self
                        .encoding
                        .context("hash recipe encoding")?
                        .encode(self.seed_number(seed)?)?,
                ),
            ) % order
        };
        Ok((!scalar.is_zero()).then_some(scalar))
    }

    pub fn point(&self, seed: u32) -> Result<Option<Vec<u8>>> {
        self.scalar(seed, &self.curve.order())?
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
    fn patterns_match_independent_openssl_vectors() -> Result<()> {
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
        for pattern in Pattern::ALL {
            let limit = pattern.limit(Curve::P521);
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
    fn recipes_match_independent_openssl_vectors() -> Result<()> {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/recipe-vectors.json"))?;
        for vector in vectors.as_array().unwrap() {
            let recipe = Recipe {
                curve: serde_json::from_value(vector["curve"].clone())?,
                hash: Some(serde_json::from_value(vector["hash"].clone())?),
                encoding: Some(serde_json::from_value(vector["encoding"].clone())?),
                seed_pattern: None,
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
    fn all_hashes_match_independent_digest_vectors() -> Result<()> {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/digest-vectors.json"))?;
        for (name, expected) in vectors.as_object().unwrap() {
            let hash: Hash = serde_json::from_value(serde_json::Value::String(name.clone()))?;
            assert_eq!(hex::encode(hash.digest(b"0")), expected.as_str().unwrap());
        }
        Ok(())
    }

    #[test]
    fn seed_number_patterns_match_defined_values_and_binary_encodings() -> Result<()> {
        let cases = [
            (SeedPattern::Counter, 42, 42),
            (SeedPattern::RepeatByte, 1, 0x01010101),
            (SeedPattern::RepeatU16be, 0x1234, 0x12341234),
            (SeedPattern::SingleBit, 63, 1u64 << 63),
            (SeedPattern::LowOnes, 63, u64::MAX),
            (SeedPattern::RepeatDigit, 9, 9_999_999_999),
            (SeedPattern::DigitWalk, 9, 1_234_567_890),
            (SeedPattern::DigitWalk, 19, 9_876_543_210),
        ];
        for (pattern, index, expected) in cases {
            assert_eq!(pattern.value(index)?, expected, "{pattern:?}/{index}");
        }
        assert_eq!(SeedEncoding::Decimal.encode(16_843_009)?, b"16843009");
        assert_eq!(SeedEncoding::U32be.encode(0x01020304)?, [1, 2, 3, 4]);
        assert_eq!(SeedEncoding::U32le.encode(0x01020304)?, [4, 3, 2, 1]);
        assert_eq!(
            SeedEncoding::U64be.encode(1u64 << 63)?,
            [0x80, 0, 0, 0, 0, 0, 0, 0]
        );
        assert!(SeedEncoding::U32be.encode(u64::from(u32::MAX) + 1).is_err());
        assert_eq!(SeedPattern::SingleBit.limit(SeedEncoding::U32be), 32);
        assert_eq!(SeedPattern::SingleBit.limit(SeedEncoding::U64le), 64);
        assert_eq!(SeedPattern::RepeatDigit.limit(SeedEncoding::U32le), 4);
        assert_eq!(SeedPattern::DigitWalk.limit(SeedEncoding::U32be), 19);
        Ok(())
    }

    #[test]
    fn seed_pattern_hash_recipes_match_independent_points_and_packs() -> Result<()> {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/seed-pattern-vectors.json"))?;
        for vector in vectors.as_array().unwrap() {
            let curve: Curve = serde_json::from_value(vector["curve"].clone())?;
            let hash: Hash = serde_json::from_value(vector["hash"].clone())?;
            let encoding: SeedEncoding = serde_json::from_value(vector["encoding"].clone())?;
            let seed_pattern: SeedPattern = serde_json::from_value(vector["seed_pattern"].clone())?;
            let seed = vector["seed"].as_u64().unwrap() as u32;
            let recipe = Recipe {
                curve,
                hash: Some(hash),
                encoding: Some(encoding),
                seed_pattern: (seed_pattern != SeedPattern::Counter).then_some(seed_pattern),
                mapping: "digest-be-mod-order-v1".into(),
                start: seed,
                count: 1,
            };
            recipe.validate()?;
            assert_eq!(
                recipe.seed_number(seed)?,
                vector["seed_number"].as_u64().unwrap()
            );
            assert_eq!(
                hex::encode(encoding.encode(recipe.seed_number(seed)?)?),
                vector["input_hex"].as_str().unwrap()
            );
            let point = recipe.point(seed)?.unwrap();
            assert_eq!(hex::encode(&point), vector["point"].as_str().unwrap());
            let pack = crate::pack::Pack::from_bytes(crate::pack::generate(recipe, 3)?)?;
            assert_eq!(pack.lookup(&point)?.0, vec![seed]);
        }
        Ok(())
    }

    #[test]
    fn range_validation_rejects_overflow_and_unknown_mappings() {
        let mut r = Recipe {
            curve: Curve::P384,
            hash: Some(Hash::Sha256),
            encoding: Some(SeedEncoding::Decimal),
            seed_pattern: None,
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
