//! `UniqueUtil.ulid()`: 26 Crockford base32 characters, ten of time and sixteen random,
//! so ids sort by when they were issued.

use rand::Rng;

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn ulid() -> String {
    let mut out = [0u8; 26];
    let mut time = chrono::Utc::now().timestamp_millis() as u64;
    for i in (0..10).rev() {
        out[i] = CROCKFORD[(time & 0x1f) as usize];
        time >>= 5;
    }
    let mut rng = rand::thread_rng();
    for slot in out.iter_mut().skip(10) {
        *slot = CROCKFORD[rng.gen_range(0..32)];
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape() {
        let a = ulid();
        assert_eq!(a.len(), 26);
        assert!(a.bytes().all(|b| CROCKFORD.contains(&b)));
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(ulid()[..10] >= a[..10]);
    }
}
