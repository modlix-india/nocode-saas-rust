//! The `BigDecimal` arithmetic billing needs beyond [`Dec`]: a division to a scale with
//! `HALF_UP` (the GST), the exact division by 100 (paise to rupees, whose scale may be
//! negative), `longValue()`, and `Double.toString()` (Gson hands every JSON number over as a
//! `Double`, and the webhook reads them back as text).

use std::cmp::Ordering;

use crate::decimal::Dec;

/// A `BigDecimal` whose scale may be negative (`new BigDecimal("1.062E7")`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Big {
    pub unscaled: i128,
    pub scale: i32,
}

impl Big {
    /// `new BigDecimal(text)`: plain or exponent notation, nothing else.
    pub fn parse(s: &str) -> Option<Big> {
        let (mantissa, exp) = match s.find(['e', 'E']) {
            Some(i) => (&s[..i], s[i + 1..].parse::<i32>().ok()?),
            None => (s, 0),
        };
        let (neg, digits) = match mantissa.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, mantissa.strip_prefix('+').unwrap_or(mantissa)),
        };
        let (int, frac) = digits.split_once('.').unwrap_or((digits, ""));
        if (int.is_empty() && frac.is_empty()) || !int.chars().chain(frac.chars()).all(|c| c.is_ascii_digit()) {
            return None;
        }
        let unscaled: i128 = format!("{int}{frac}").parse().ok()?;
        Some(Big { unscaled: if neg { -unscaled } else { unscaled }, scale: frac.len() as i32 - exp })
    }

    pub fn of(d: Dec) -> Big {
        Big::parse(&d.to_string()).unwrap_or(Big { unscaled: 0, scale: 0 })
    }

    /// The value as a [`Dec`]: exact for a scale of zero or more; a negative scale becomes the
    /// same value at scale 0.
    pub fn to_dec(self) -> Dec {
        Dec::parse(&format!("{}E{}", self.unscaled, -self.scale)).unwrap_or(Dec::ZERO)
    }

    pub fn cmp_value(&self, o: &Big) -> Ordering {
        let scale = self.scale.max(o.scale);
        let a = self.unscaled.checked_mul(10i128.pow((scale - self.scale) as u32));
        let b = o.unscaled.checked_mul(10i128.pow((scale - o.scale) as u32));
        match (a, b) {
            (Some(a), Some(b)) => a.cmp(&b),
            _ => self.to_f64().partial_cmp(&o.to_f64()).unwrap_or(Ordering::Equal),
        }
    }

    pub fn to_f64(self) -> f64 {
        format!("{}E{}", self.unscaled, -self.scale).parse().unwrap_or(0.0)
    }

    /// `divide(divisor)` (exact): the quotient at the dividend's scale or the least larger one
    /// that holds it. Only used with divisors whose quotient terminates (100).
    pub fn divide_exact(self, divisor: i128) -> Big {
        // value / 10^k for divisor = 10^k: same digits, k more places; then strip back down to
        // the preferred scale (the dividend's) while the digits allow.
        let mut d = divisor;
        let mut places = 0;
        while d > 1 && d % 10 == 0 {
            d /= 10;
            places += 1;
        }
        let mut out = Big { unscaled: self.unscaled / d, scale: self.scale + places };
        while out.scale > self.scale && out.unscaled % 10 == 0 {
            out.unscaled /= 10;
            out.scale -= 1;
        }
        out
    }
}

/// `value.divide(BigDecimal.valueOf(divisor), scale, RoundingMode.HALF_UP)`.
pub fn divide_half_up(value: Dec, divisor: i128, scale: u32) -> Dec {
    let b = Big::of(value);
    // value = u / 10^s; quotient * 10^scale = u * 10^scale / (divisor * 10^s).
    let (mut num, mut den) = (b.unscaled * 10i128.pow(scale), divisor);
    if b.scale >= 0 {
        den *= 10i128.pow(b.scale as u32);
    } else {
        num *= 10i128.pow((-b.scale) as u32);
    }
    let mut q = num / den;
    let rem = num % den;
    if 2 * rem.abs() >= den.abs() {
        q += if (num < 0) != (den < 0) { -1 } else { 1 };
    }
    Big { unscaled: q, scale: scale as i32 }.to_dec()
}

/// `BigDecimal.longValue()`: the integer part, truncated towards zero.
pub fn long_value(value: Dec) -> i64 {
    let b = Big::of(value);
    if b.scale <= 0 {
        return (b.unscaled * 10i128.pow((-b.scale) as u32)) as i64;
    }
    (b.unscaled / 10i128.pow(b.scale as u32)) as i64
}

/// `Double.toString(d)`: the shortest digits that read back as `d`, plain between 10^-3 and
/// 10^7, `d.dddE<n>` outside.
pub fn java_double(d: f64) -> String {
    if d == 0.0 {
        return if d.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    if !d.is_finite() {
        return if d.is_nan() { "NaN".into() } else if d > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    let sci = format!("{:e}", d.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let sign = if d < 0.0 { "-" } else { "" };
    let abs = d.abs();
    if (1e-3..1e7).contains(&abs) {
        if exp >= 0 {
            let int_len = exp as usize + 1;
            let padded = format!("{digits:0<int_len$}");
            let (int, frac) = padded.split_at(int_len);
            let frac = if frac.is_empty() { "0" } else { frac };
            format!("{sign}{int}.{frac}")
        } else {
            format!("{sign}0.{}{digits}", "0".repeat((-exp - 1) as usize))
        }
    } else {
        let (first, rest) = digits.split_at(1);
        let rest = if rest.is_empty() { "0" } else { rest };
        format!("{sign}{first}.{rest}E{exp}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Dec {
        Dec::parse(s).unwrap()
    }

    #[test]
    fn gst_rounds_half_up_to_two_places() {
        // BundlePurchaseServiceTest: 900 x 18 / 100 = 162.00.
        assert_eq!(divide_half_up(d("900").mul(d("18")), 100, 2).to_string(), "162.00");
        // The local 2K bundle: 999.0000 x 18.00 = 17982.000000 -> 179.82.
        assert_eq!(divide_half_up(d("999.0000").mul(d("18.00")), 100, 2).to_string(), "179.82");
        assert_eq!(divide_half_up(d("0.125"), 1, 2).to_string(), "0.13");
        assert_eq!(divide_half_up(d("-0.125"), 1, 2).to_string(), "-0.13");
        assert_eq!(divide_half_up(d("0.124"), 1, 2).to_string(), "0.12");
        assert_eq!(divide_half_up(d("1e3"), 100, 2).to_string(), "10.00");
        assert_eq!(divide_half_up(Dec::ZERO, 100, 2).to_string(), "0.00");
    }

    #[test]
    fn rupees_keep_the_exact_scale() {
        let r = Big::parse("106200.0").unwrap().divide_exact(100);
        assert_eq!((r, r.to_dec().to_string()), (Big { unscaled: 10620, scale: 1 }, "1062.0".into()));
        let r = Big::parse("117882.0").unwrap().divide_exact(100);
        assert_eq!(r.to_dec().to_string(), "1178.82");
        let r = Big::parse("1.062E7").unwrap().divide_exact(100);
        assert_eq!(r, Big { unscaled: 1062, scale: -2 });
        assert_eq!(r.to_dec().to_string(), "106200");
        assert_eq!(r.to_f64(), 106200.0);
        assert_eq!(Big::parse("2124").unwrap().divide_exact(100).to_dec().to_string(), "21.24");
        assert!(Big::parse("x").is_none() && Big::parse("").is_none() && Big::parse("1e").is_none());
        assert_eq!(Big::parse("-1.5").unwrap(), Big { unscaled: -15, scale: 1 });
        assert_eq!(Big::parse("+2").unwrap(), Big { unscaled: 2, scale: 0 });
    }

    #[test]
    fn comparisons_ignore_scale() {
        let a = Big::parse("1062.0").unwrap();
        assert_eq!(a.cmp_value(&Big::of(d("1062.0000"))), Ordering::Equal);
        assert_eq!(a.cmp_value(&Big::of(d("1000"))), Ordering::Greater);
        assert_eq!(Big::parse("1.062E3").unwrap().cmp_value(&a), Ordering::Equal);
        let huge = Big { unscaled: i128::MAX / 2, scale: -30 };
        assert_eq!(huge.cmp_value(&a), Ordering::Greater);
    }

    #[test]
    fn long_values_truncate() {
        assert_eq!(long_value(d("1178.8200").mul(d("100"))), 117882);
        assert_eq!(long_value(d("10.99")), 10);
        assert_eq!(long_value(d("-10.99")), -10);
        assert_eq!(long_value(d("5")), 5);
        assert_eq!(long_value(Big { unscaled: 12, scale: -2 }.to_dec()), 1200);
    }

    #[test]
    fn doubles_print_like_java() {
        assert_eq!(java_double(106200.0), "106200.0");
        assert_eq!(java_double(1062.5), "1062.5");
        assert_eq!(java_double(1e7), "1.0E7");
        assert_eq!(java_double(12345678.0), "1.2345678E7");
        assert_eq!(java_double(0.001), "0.001");
        assert_eq!(java_double(0.0001), "1.0E-4");
        assert_eq!(java_double(-2.5), "-2.5");
        assert_eq!(java_double(0.0), "0.0");
        assert_eq!(java_double(-0.0), "-0.0");
        assert_eq!(java_double(1.0), "1.0");
        assert_eq!(java_double(f64::NAN), "NaN");
        assert_eq!(java_double(f64::INFINITY), "Infinity");
        assert_eq!(java_double(f64::NEG_INFINITY), "-Infinity");
        assert_eq!(java_double(1792126800.0), "1.7921268E9");
    }
}
