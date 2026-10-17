//! Values the Java services compute that leave the process, reproduced bit for bit.
//!
//! A Rust instance and a Java instance serve the same URLs while a service is being moved, so
//! anything a browser or another service keeps and sends back (an ETag, an exception id, a hash
//! in a cache key) has to come out identical from both.

use chrono::Local;
use sha2::{Digest, Sha256};

/// `java.lang.String.hashCode()`: `s[0]*31^(n-1) + ... + s[n-1]` over UTF-16 code units,
/// wrapping at 32 bits.
pub fn string_hash_code(s: &str) -> i32 {
    s.encode_utf16()
        .fold(0i32, |h, c| h.wrapping_mul(31).wrapping_add(c as i32))
}

/// `HashUtil.sha256Hash(Object)`: SHA-256 of `toString().getBytes()`, lower-case hex.
pub fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// `GenericException.uniqueId()`: the local date, then the milliseconds into the UTC day in hex.
///
/// Java takes `System.currentTimeMillis() % 86_400_000`, which is the UTC day, while the date
/// part is formatted in the JVM's zone. The two halves can therefore disagree around midnight;
/// that is reproduced, not fixed, so ids stay comparable across the two implementations.
pub fn exception_id() -> String {
    let now = Local::now();
    let millis_of_utc_day = now.timestamp_millis().rem_euclid(86_400_000);
    format!("{}-{:x}", now.format("%Y-%m-%d"), millis_of_utc_day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_code_matches_java() {
        // Values taken from a running JVM.
        assert_eq!(string_hash_code(""), 0);
        assert_eq!(string_hash_code("a"), 97);
        assert_eq!(string_hash_code("hello"), 99_162_322);
        // Observed in a live ETag from the Java files service on 2026-10-13.
        assert_eq!(string_hash_code("loopzump-32-v1.png"), -220_649_959);
    }

    #[test]
    fn hash_code_counts_utf16_units() {
        // One code point outside the BMP is two UTF-16 units: 0xD83D, 0xDE00.
        assert_eq!(string_hash_code("😀"), 0xD83D * 31 + 0xDE00);
    }

    #[test]
    fn sha256_is_lower_hex() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn exception_id_shape() {
        let id = exception_id();
        assert_eq!(&id[4..5], "-");
        assert_eq!(&id[10..11], "-");
        assert!(u64::from_str_radix(&id[11..], 16).is_ok());
    }
}
