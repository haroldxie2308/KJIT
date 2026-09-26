//! SplitMix64: small, deterministic and dependency-free. The fuzzer's only
//! source of randomness, so a (seed, program index) pair reproduces a program.

#[derive(Clone, Debug)]
pub struct Rng {
    state: u64,
}

const GOLDEN_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Independent stream for program `index` of a run seeded with `seed`.
    pub fn for_program(seed: u64, index: u64) -> Self {
        let mut mixer = Self::new(seed ^ index.wrapping_mul(GOLDEN_GAMMA));
        Self::new(mixer.next_u64())
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(GOLDEN_GAMMA);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `[0, n)`.
    pub fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0, "Rng::below(0)");
        ((self.next_u64() as u128 * n as u128) >> 64) as u64
    }

    /// Uniform in `[lo, hi]`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        assert!(lo <= hi, "Rng::range({lo}, {hi})");
        lo + self.below(hi - lo + 1)
    }

    /// Uniform in `[lo, hi]`.
    pub fn range_i64(&mut self, lo: i64, hi: i64) -> i64 {
        assert!(lo <= hi, "Rng::range_i64({lo}, {hi})");
        lo.wrapping_add(self.below(hi.abs_diff(lo) + 1) as i64)
    }

    /// True with probability `per_mille / 1000`.
    pub fn chance(&mut self, per_mille: u32) -> bool {
        self.below(1000) < per_mille as u64
    }

    pub fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len() as u64) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streams_are_deterministic_and_distinct() {
        let a: Vec<u64> = (0..4)
            .map(|_| 0)
            .scan(Rng::for_program(7, 3), |r, _: u64| Some(r.next_u64()))
            .collect();
        let b: Vec<u64> = (0..4)
            .map(|_| 0)
            .scan(Rng::for_program(7, 3), |r, _: u64| Some(r.next_u64()))
            .collect();
        let c: Vec<u64> = (0..4)
            .map(|_| 0)
            .scan(Rng::for_program(7, 4), |r, _: u64| Some(r.next_u64()))
            .collect();
        assert_eq!(a, b);
        assert_ne!(a, c);
        let mut rng = Rng::new(1);
        for _ in 0..1000 {
            assert!(rng.below(5) < 5);
            let v = rng.range_i64(-12, 12);
            assert!((-12..=12).contains(&v));
        }
    }
}
