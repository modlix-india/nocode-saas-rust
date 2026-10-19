//! Two counters over the last few seconds, in one-second buckets: what the circuit breaker
//! (requests, failures) and the retry budget (requests, retries) measure.

#[derive(Debug, Clone, Copy, Default)]
struct Bucket {
    /// The second (since the owner's start) this bucket counts; older counts are stale.
    second: u64,
    a: u64,
    b: u64,
}

#[derive(Debug, Clone)]
pub struct Window {
    buckets: Vec<Bucket>,
}

impl Window {
    pub fn new(seconds: u64) -> Self {
        Self { buckets: vec![Bucket::default(); seconds.max(1) as usize] }
    }

    fn len(&self) -> u64 {
        self.buckets.len() as u64
    }

    pub fn add(&mut self, second: u64, a: u64, b: u64) {
        let i = (second % self.len()) as usize;
        let bucket = &mut self.buckets[i];
        if bucket.second != second {
            *bucket = Bucket { second, a: 0, b: 0 };
        }
        bucket.a += a;
        bucket.b += b;
    }

    /// Both counters over the window ending with `second`.
    pub fn sum(&self, second: u64) -> (u64, u64) {
        let len = self.len();
        self.buckets
            .iter()
            .filter(|b| b.second <= second && b.second + len > second)
            .fold((0, 0), |(a, b), k| (a + k.a, b + k.b))
    }

    /// Both counters for `second` alone.
    pub fn at(&self, second: u64) -> (u64, u64) {
        let b = &self.buckets[(second % self.len()) as usize];
        if b.second == second { (b.a, b.b) } else { (0, 0) }
    }

    pub fn clear(&mut self) {
        self.buckets.fill(Bucket::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_roll_off_after_the_window() {
        let mut w = Window::new(3);
        w.add(0, 1, 0);
        w.add(1, 2, 1);
        w.add(1, 1, 1);
        assert_eq!(w.sum(1), (4, 2));
        assert_eq!(w.at(1), (3, 2));
        assert_eq!(w.at(2), (0, 0));
        w.add(2, 1, 0);
        assert_eq!(w.sum(2), (5, 2));
        // Second 3 reuses second 0's bucket; second 0 is out of the window anyway.
        w.add(3, 1, 1);
        assert_eq!(w.sum(3), (5, 3));
        assert_eq!(w.sum(5), (1, 1), "only second 3 is left");
        assert_eq!(w.sum(9), (0, 0));
        w.clear();
        assert_eq!(w.sum(3), (0, 0));
        assert_eq!(Window::new(0).len(), 1);
    }
}
