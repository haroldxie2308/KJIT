//! Small formatting/statistics helpers shared by the measurement report
//! binaries (`coverage-scan`, `e1-report`).

use std::fmt::Write as _;

/// Nearest-rank distribution summary.
pub struct Dist {
    pub n: usize,
    pub min: u64,
    pub median: u64,
    pub p90: u64,
    pub p99: u64,
    pub max: u64,
}

pub fn dist(mut values: Vec<u64>) -> Option<Dist> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let n = values.len();
    let rank = |p: f64| values[((p * n as f64).ceil() as usize).clamp(1, n) - 1];
    Some(Dist {
        n,
        min: values[0],
        median: rank(0.5),
        p90: rank(0.9),
        p99: rank(0.99),
        max: values[n - 1],
    })
}

pub fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => write!(out, "\\u{:04x}", c as u32).unwrap(),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::dist;

    #[test]
    fn dist_uses_nearest_rank() {
        let d = dist((1..=100).collect()).unwrap();
        assert_eq!(
            (d.n, d.min, d.median, d.p90, d.p99, d.max),
            (100, 1, 50, 90, 99, 100)
        );
        let d = dist(vec![7]).unwrap();
        assert_eq!((d.min, d.median, d.p99, d.max), (7, 7, 7, 7));
        assert!(dist(Vec::new()).is_none());
    }
}
