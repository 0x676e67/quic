//! Wire coding for the `initial_rtt` transport parameter (`0x3127`).

use std::time::Duration;

use crate::VarInt;

/// Minimum accepted value for an untrusted initial RTT.
const MIN_INITIAL_RTT: Duration = Duration::from_millis(10);

/// Maximum accepted value for an initial RTT.
const MAX_INITIAL_RTT: Duration = Duration::from_secs(1);

pub(crate) fn encode(rtt: Duration) -> Option<(Duration, VarInt)> {
    let rtt = sanitize(rtt)?;
    // `sanitize` caps the duration at one second, so this conversion cannot truncate.
    let micros = rtt.as_micros() as u32;
    Some((rtt, VarInt::from_u32(micros)))
}

pub(crate) fn decode(value: VarInt) -> Option<Duration> {
    sanitize(Duration::from_micros(value.into_inner()))
}

fn sanitize(rtt: Duration) -> Option<Duration> {
    (!rtt.is_zero()).then(|| rtt.clamp(MIN_INITIAL_RTT, MAX_INITIAL_RTT))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_rtt_is_clamped_to_bounds() {
        assert_eq!(encode(Duration::ZERO), None);
        assert_eq!(decode(VarInt::from_u32(0)), None);

        let (rtt, encoded) = encode(Duration::from_millis(1)).unwrap();
        assert_eq!(rtt, MIN_INITIAL_RTT);
        assert_eq!(encoded.into_inner(), 10_000);
        assert_eq!(decode(VarInt::from_u32(1)), Some(MIN_INITIAL_RTT));

        let (rtt, encoded) = encode(Duration::from_millis(20)).unwrap();
        assert_eq!(rtt, Duration::from_millis(20));
        assert_eq!(decode(encoded), Some(rtt));

        let (rtt, encoded) = encode(Duration::from_secs(2)).unwrap();
        assert_eq!(rtt, MAX_INITIAL_RTT);
        assert_eq!(encoded.into_inner(), 1_000_000);
        assert_eq!(decode(VarInt::from_u32(2_000_000)), Some(MAX_INITIAL_RTT));
    }
}
