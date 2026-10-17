//! `java.math.BigDecimal`, as far as billing uses it: values read from `DECIMAL(19,4)` columns
//! (or JSON numbers), added, subtracted, multiplied, compared, divided down to a whole number, and
//! written with `BigDecimal.toString()` (which is what Jackson writes). The scale is kept the way
//! Java keeps it, so `1.0000` stays `1.0000` and `BigDecimal.ZERO` is `0`.
//!
//! The columns are read as text (`CAST(x AS CHAR)`) and bound as text: MySQL converts both ways
//! exactly, and no decimal crate is needed.

use std::cmp::Ordering;
use std::fmt;

#[derive(Debug, Clone, Copy, Default)]
pub struct Dec {
    unscaled: i128,
    scale: u32,
}

impl Dec {
    pub const ZERO: Dec = Dec { unscaled: 0, scale: 0 };
    pub const ONE: Dec = Dec { unscaled: 1, scale: 0 };

    pub fn from_i64(v: i64) -> Self {
        Self { unscaled: i128::from(v), scale: 0 }
    }

    /// `new BigDecimal(String)` for plain and exponent notation.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (mantissa, exp) = match s.find(['e', 'E']) {
            Some(i) => (&s[..i], s[i + 1..].parse::<i32>().ok()?),
            None => (s, 0),
        };
        let (neg, digits) = match mantissa.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, mantissa.strip_prefix('+').unwrap_or(mantissa)),
        };
        let (int, frac) = digits.split_once('.').unwrap_or((digits, ""));
        if int.is_empty() && frac.is_empty() {
            return None;
        }
        if !int.chars().chain(frac.chars()).all(|c| c.is_ascii_digit()) {
            return None;
        }
        let mut unscaled: i128 = format!("{int}{frac}").parse().ok()?;
        let mut scale = frac.len() as i32 - exp;
        if scale < 0 {
            unscaled = unscaled.checked_mul(10i128.checked_pow((-scale) as u32)?)?;
            scale = 0;
        }
        Some(Self { unscaled: if neg { -unscaled } else { unscaled }, scale: scale as u32 })
    }

    /// A JSON number as Jackson reads it into a `BigDecimal` (`USE_BIG_DECIMAL_FOR_FLOATS` is
    /// not needed: integers keep scale 0, decimals keep their written digits).
    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        match v {
            serde_json::Value::Number(n) => Self::parse(&n.to_string()),
            serde_json::Value::String(s) => Self::parse(s),
            _ => None,
        }
    }

    fn rescaled(self, scale: u32) -> i128 {
        self.unscaled * 10i128.pow(scale - self.scale)
    }

    pub fn add(self, o: Dec) -> Dec {
        let scale = self.scale.max(o.scale);
        Dec { unscaled: self.rescaled(scale) + o.rescaled(scale), scale }
    }

    pub fn sub(self, o: Dec) -> Dec {
        let scale = self.scale.max(o.scale);
        Dec { unscaled: self.rescaled(scale) - o.rescaled(scale), scale }
    }

    pub fn mul(self, o: Dec) -> Dec {
        Dec { unscaled: self.unscaled * o.unscaled, scale: self.scale + o.scale }
    }

    /// `divide(divisor, 0, RoundingMode.DOWN)`: the quotient truncated towards zero, scale 0.
    pub fn div_down(self, divisor: i128) -> Dec {
        let q = self.unscaled / (divisor * 10i128.pow(self.scale));
        Dec { unscaled: q, scale: 0 }
    }

    /// `signum()`.
    pub fn signum(self) -> i32 {
        self.unscaled.signum() as i32
    }

    /// `max(other)`: the larger; on a tie, this one (as `compareTo >= 0 ? this : val`).
    pub fn max(self, o: Dec) -> Dec {
        if self.cmp_value(&o) != Ordering::Less {
            self
        } else {
            o
        }
    }

    /// `compareTo`: by value, ignoring scale.
    pub fn cmp_value(&self, o: &Dec) -> Ordering {
        let scale = self.scale.max(o.scale);
        self.rescaled(scale).cmp(&o.rescaled(scale))
    }

    /// Jackson writes `toString()`; the digits travel as a raw number so the scale survives.
    pub fn to_json(self) -> serde_json::Value {
        crate::jackson::raw_number(self)
    }
}

impl PartialEq for Dec {
    fn eq(&self, o: &Self) -> bool {
        self.unscaled == o.unscaled && self.scale == o.scale
    }
}

/// `BigDecimal.toString()`: plain unless the adjusted exponent is below -6.
impl fmt::Display for Dec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let neg = self.unscaled < 0;
        let digits = self.unscaled.unsigned_abs().to_string();
        let scale = self.scale as i64;
        let adjusted = digits.len() as i64 - 1 - scale;
        let sign = if neg { "-" } else { "" };
        if scale == 0 {
            return write!(f, "{sign}{digits}");
        }
        if adjusted >= -6 {
            let s = scale as usize;
            if digits.len() > s {
                let (i, d) = digits.split_at(digits.len() - s);
                write!(f, "{sign}{i}.{d}")
            } else {
                write!(f, "{sign}0.{}{digits}", "0".repeat(s - digits.len()))
            }
        } else {
            let (first, rest) = digits.split_at(1);
            let rest = if rest.is_empty() { String::new() } else { format!(".{rest}") };
            write!(f, "{sign}{first}{rest}E{adjusted}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Dec {
        Dec::parse(s).unwrap()
    }

    #[test]
    fn to_string_like_big_decimal() {
        assert_eq!(d("1.0000").to_string(), "1.0000");
        assert_eq!(d("0.0000").to_string(), "0.0000");
        assert_eq!(d("-12.5").to_string(), "-12.5");
        assert_eq!(Dec::ZERO.to_string(), "0");
        assert_eq!(d("0.0000001").to_string(), "1E-7");
        assert_eq!(d("0.00000012").to_string(), "1.2E-7");
        assert_eq!(d("0.000001").to_string(), "0.000001");
        assert_eq!(d("1e3").to_string(), "1000");
        assert_eq!(d("+7").to_string(), "7");
        assert!(Dec::parse("abc").is_none() && Dec::parse("").is_none() && Dec::parse(".").is_none());
    }

    #[test]
    fn arithmetic_keeps_java_scales() {
        assert_eq!(d("10.0000").sub(Dec::from_i64(3)).to_string(), "7.0000");
        assert_eq!(d("2.50").add(d("0.125")).to_string(), "2.625");
        assert_eq!(d("1.5").mul(d("2.00")).to_string(), "3.000");
        // 100 users * 500 tokens a month over a 30-day month's 2880 windows: 17.36 -> 17.
        assert_eq!(d("100").mul(d("500.0000")).div_down(2880).to_string(), "17");
        assert_eq!(d("-7.9").div_down(1).to_string(), "-7");
        assert_eq!(d("5.0000").max(d("5")).to_string(), "5.0000");
        assert_eq!(d("4").max(d("5.00")).to_string(), "5.00");
        assert_eq!(d("-1").signum(), -1);
        assert_eq!(d("0.0").cmp_value(&Dec::ZERO), Ordering::Equal);
        assert_eq!(crate::jackson::pretty(&d("2.0").to_json()), "2.0");
        assert_eq!(Dec::from_json(&serde_json::json!(12)).unwrap().to_string(), "12");
        assert_eq!(Dec::from_json(&serde_json::json!("3.25")).unwrap().to_string(), "3.25");
        assert!(Dec::from_json(&serde_json::json!(true)).is_none());
        assert_ne!(d("1.0"), d("1.00"));
    }
}
