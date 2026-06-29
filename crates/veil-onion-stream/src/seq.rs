//! Modular `u32` sequence-number arithmetic (RFC 1982 / TCP-style).
//!
//! Byte offsets in the stream are `u32` and WRAP at 4 GiB, so a stream longer
//! than 4 GiB reuses sequence values. Comparisons therefore can't be the plain
//! `<`/`>=`; they must be done on the SIGNED difference, which is correct as long
//! as the two values are less than 2³¹ apart (always true here: the in-flight
//! window is far smaller than 2 GiB). `a.wrapping_sub(b) as i32` is the signed
//! distance from `b` to `a`.

/// `a < b` in modular order.
#[inline]
pub fn lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// `a <= b` in modular order.
#[inline]
pub fn leq(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

/// `a > b` in modular order.
#[inline]
pub fn gt(a: u32, b: u32) -> bool {
    lt(b, a)
}

/// `a >= b` in modular order.
#[inline]
pub fn geq(a: u32, b: u32) -> bool {
    leq(b, a)
}

/// The smaller of `a`, `b` in modular order.
#[inline]
pub fn min(a: u32, b: u32) -> u32 {
    if lt(a, b) { a } else { b }
}

/// The larger of `a`, `b` in modular order.
#[inline]
pub fn max(a: u32, b: u32) -> u32 {
    if lt(a, b) { b } else { a }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_order() {
        assert!(lt(1, 2));
        assert!(!lt(2, 1));
        assert!(leq(2, 2));
        assert!(gt(5, 3));
        assert!(geq(5, 5));
        assert_eq!(min(3, 9), 3);
        assert_eq!(max(3, 9), 9);
    }

    #[test]
    fn wraparound_near_u32_max() {
        let a = u32::MAX - 4; // just below wrap
        let b = a.wrapping_add(10); // wrapped past 0 → 5
        assert!(lt(a, b), "{a} should be < {b} across the wrap");
        assert!(gt(b, a));
        assert_eq!(min(a, b), a);
        assert_eq!(max(a, b), b);
        // The half-line boundary: distance exactly 1 across the seam.
        assert!(lt(u32::MAX, 0));
        assert!(gt(0, u32::MAX));
    }

    #[test]
    fn equality_is_leq_and_geq() {
        let x = 123_456u32;
        assert!(leq(x, x) && geq(x, x));
        assert!(!lt(x, x) && !gt(x, x));
    }
}
