//! IEEE 754-2008 decimal128 (BID encoding, as BSON stores it) to and from an exact decimal,
//! as `org.bson.types.Decimal128` does it. The bson crate carries the bytes only.

use mongodb::bson::Decimal128;

use crate::value::Decimal;

const EXPONENT_BIAS: i64 = 6176;
const MIN_EXPONENT: i64 = -6176;
const MAX_EXPONENT: i64 = 6111;
const MAX_DIGITS: usize = 34;

/// Why a decimal cannot be held (Java's NumberFormatException / AssertionError).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutOfRange(pub String);

/// `new Decimal128(BigDecimal)`: clamped and rounded only where no digit is lost.
pub fn from_decimal(d: &Decimal) -> Result<Decimal128, OutOfRange> {
    let mut digits = d.unscaled_digits().to_string();
    let mut scale = d.scale() as i64;

    let exponent = -scale;
    if exponent > MAX_EXPONENT {
        let diff = exponent - MAX_EXPONENT;
        if d.is_zero() {
            scale = -MAX_EXPONENT;
        } else if diff as usize + digits.len() > MAX_DIGITS {
            return Err(OutOfRange(format!("Exponent is out of range for Decimal128 encoding of {d}")));
        } else {
            digits.push_str(&"0".repeat(diff as usize));
            scale += diff;
        }
    } else if exponent < MIN_EXPONENT {
        let diff = (scale + MIN_EXPONENT) as usize;
        if !d.is_zero() {
            let tail = &digits[digits.len().saturating_sub(diff)..];
            if diff > digits.len() || tail.bytes().any(|b| b != b'0') {
                return Err(OutOfRange(format!("Conversion to Decimal128 would require inexact rounding of {d}")));
            }
            digits.truncate(digits.len() - diff);
        }
        scale -= diff as i64;
    } else if digits.len() > MAX_DIGITS {
        let extra = digits.len() - MAX_DIGITS;
        if digits[MAX_DIGITS..].bytes().any(|b| b != b'0') {
            return Err(OutOfRange(format!("Conversion to Decimal128 would require inexact rounding of {d}")));
        }
        digits.truncate(MAX_DIGITS);
        scale -= extra as i64;
    }

    let exponent = -scale;
    if !(MIN_EXPONENT..=MAX_EXPONENT).contains(&exponent) {
        return Err(OutOfRange(format!("Exponent is out of range for Decimal128 encoding: {exponent}")));
    }
    let coefficient: u128 = if digits.is_empty() { 0 } else { digits.parse().map_err(|_| OutOfRange(d.to_string()))? };
    if coefficient >= 10u128.pow(MAX_DIGITS as u32) {
        return Err(OutOfRange(format!("Unscaled roundedValue is out of range for Decimal128 encoding:{coefficient}")));
    }

    let biased = (exponent + EXPONENT_BIAS) as u128;
    let mut bits: u128 = (biased << 113) | coefficient;
    if d.is_negative() {
        bits |= 1u128 << 127;
    }
    Ok(Decimal128::from_bytes(bits.to_le_bytes()))
}

/// What a stored decimal128 means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    Finite(Decimal),
    /// -0, which `bigDecimalValue()` refuses.
    NegativeZero,
    NaN,
    Infinite(bool),
}

pub fn to_decimal(d: &Decimal128) -> Decoded {
    let bits = u128::from_le_bytes(d.bytes());
    let negative = bits >> 127 == 1;
    let combination = (bits >> 122) & 0x1f;
    if combination == 0x1f {
        return Decoded::NaN;
    }
    if combination == 0x1e {
        return Decoded::Infinite(negative);
    }
    let (exponent, coefficient) = if (bits >> 125) & 0b11 == 0b11 {
        // The coefficient does not fit 113 bits, so it is non-canonical: zero.
        (((bits >> 111) & 0x3fff) as i64, 0u128)
    } else {
        (((bits >> 113) & 0x3fff) as i64, bits & ((1u128 << 113) - 1))
    };
    let scale = -(exponent - EXPONENT_BIAS);
    if coefficient == 0 && negative {
        return Decoded::NegativeZero;
    }
    Decoded::Finite(Decimal::from_parts(negative, &coefficient.to_string(), scale as i32))
}

/// `Decimal128.toString()`, which follows the same scientific-string rules as
/// `BigDecimal.toString()` for every finite value.
pub fn to_java_string(d: &Decimal128) -> String {
    match to_decimal(d) {
        Decoded::Finite(x) => x.to_java_string(),
        Decoded::NegativeZero => "-0".into(),
        Decoded::NaN => "NaN".into(),
        Decoded::Infinite(neg) => if neg { "-Infinity".into() } else { "Infinity".into() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(s: &str) -> String {
        let d = Decimal::parse(s).unwrap();
        match to_decimal(&from_decimal(&d).unwrap()) {
            Decoded::Finite(x) => x.to_plain_string(),
            other => format!("{other:?}"),
        }
    }

    #[test]
    fn round_trips() {
        assert_eq!(round_trip("10.50"), "10.50");
        assert_eq!(round_trip("-1.25"), "-1.25");
        assert_eq!(round_trip("0"), "0");
        assert_eq!(round_trip("1234567890123456789012345678901234"), "1234567890123456789012345678901234");
        assert_eq!(round_trip("12345678901234567890123456789012340"), "12345678901234567890123456789012340");
        assert!(from_decimal(&Decimal::parse("12345678901234567890123456789012345").unwrap()).is_err());
    }

    #[test]
    fn known_encoding() {
        // 10.50 as the Java driver writes it: coefficient 1050, exponent -2.
        let bytes = from_decimal(&Decimal::parse("10.50").unwrap()).unwrap().bytes();
        let bits = u128::from_le_bytes(bytes);
        assert_eq!(bits & ((1u128 << 113) - 1), 1050);
        assert_eq!((bits >> 113) as i64 - EXPONENT_BIAS, -2);
    }
}
