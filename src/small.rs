use crate::recipe::Curve;
use anyhow::{Context, Result, ensure};
use num_bigint::BigUint;
use p384::elliptic_curve::{BatchNormalize, sec1::ToSec1Point};
use std::collections::HashMap;

macro_rules! curve_checker {
    ($name:ident, $curve:ident) => {
        pub struct $name {
            max: u32,
            width: u32,
            stride: $curve::ProjectivePoint,
            babies: HashMap<Vec<u8>, u32>,
        }

        impl $name {
            fn new(max: u32) -> Self {
                let width = max.isqrt() + 1;
                let mut points = Vec::with_capacity(width as usize);
                let mut point = $curve::ProjectivePoint::IDENTITY;
                for _ in 0..width {
                    points.push(point);
                    point += $curve::ProjectivePoint::GENERATOR;
                }
                let affine = <$curve::ProjectivePoint as BatchNormalize<
                    [$curve::ProjectivePoint],
                >>::batch_normalize(points.as_slice());
                let babies = affine
                    .iter()
                    .enumerate()
                    .map(|(i, p)| (p.to_sec1_point(true).as_bytes().to_vec(), i as u32))
                    .collect();
                Self {
                    max,
                    width,
                    stride: -point,
                    babies,
                }
            }

            fn find(&self, bytes: &[u8]) -> Result<Option<u32>> {
                let public_key =
                    $curve::PublicKey::from_sec1_bytes(bytes).context("invalid public point")?;
                let mut point = $curve::ProjectivePoint::from(*public_key.as_affine());
                let mut giants = Vec::with_capacity((self.max / self.width + 1) as usize);
                for _ in 0..=self.max / self.width {
                    giants.push(point);
                    point += self.stride;
                }
                let affine = <$curve::ProjectivePoint as BatchNormalize<
                    [$curve::ProjectivePoint],
                >>::batch_normalize(giants.as_slice());
                for (i, point) in affine.iter().enumerate() {
                    if let Some(&j) = self.babies.get(point.to_sec1_point(true).as_bytes()) {
                        let candidate = i as u64 * u64::from(self.width) + u64::from(j);
                        if candidate >= 1 && candidate <= u64::from(self.max) {
                            return Ok(Some(candidate as u32));
                        }
                    }
                }
                Ok(None)
            }
        }
    };
}

curve_checker!(P256Checker, p256);
curve_checker!(P384Checker, p384);
curve_checker!(P521Checker, p521);

pub enum SmallChecker {
    P256(P256Checker),
    P384(P384Checker),
    P521(P521Checker),
}

impl SmallChecker {
    pub fn new(curve: Curve, max: u32) -> Self {
        match curve {
            Curve::P256 => Self::P256(P256Checker::new(max)),
            Curve::P384 => Self::P384(P384Checker::new(max)),
            Curve::P521 => Self::P521(P521Checker::new(max)),
        }
    }

    pub fn find(&self, point: &[u8]) -> Result<Option<u32>> {
        let (curve, result) = match self {
            Self::P256(c) => (Curve::P256, c.find(point)?),
            Self::P384(c) => (Curve::P384, c.find(point)?),
            Self::P521(c) => (Curve::P521, c.find(point)?),
        };
        if let Some(candidate) = result {
            ensure!(
                curve.point(&BigUint::from(candidate))? == point,
                "small-scalar verification failed"
            );
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_giant_steps_and_upper_boundary_on_every_curve() -> Result<()> {
        for curve in [Curve::P256, Curve::P384, Curve::P521] {
            let max = 10_000;
            let checker = SmallChecker::new(curve, max);
            for scalar in [1u32, 100, 101, 102, 2_345, max - 1, max] {
                assert_eq!(
                    checker.find(&curve.point(&BigUint::from(scalar))?)?,
                    Some(scalar)
                );
            }
            assert_eq!(checker.find(&curve.point(&BigUint::from(max + 1))?)?, None);
        }
        Ok(())
    }

    #[test]
    fn million_boundary_is_inclusive() -> Result<()> {
        let checker = SmallChecker::new(Curve::P384, 1_000_000);
        for scalar in [999_999u32, 1_000_000] {
            assert_eq!(
                checker.find(&Curve::P384.point(&BigUint::from(scalar))?)?,
                Some(scalar)
            );
        }
        assert_eq!(
            checker.find(&Curve::P384.point(&BigUint::from(1_000_001u32))?)?,
            None
        );
        Ok(())
    }

    #[test]
    fn a_one_element_interval_and_zero_length_interval() -> Result<()> {
        assert_eq!(
            SmallChecker::new(Curve::P256, 1).find(&Curve::P256.point(&BigUint::from(1u32))?)?,
            Some(1)
        );
        assert_eq!(
            SmallChecker::new(Curve::P256, 0).find(&Curve::P256.point(&BigUint::from(1u32))?)?,
            None
        );
        Ok(())
    }
}
