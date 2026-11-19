//! Timestamps stored in the registry, in the same JSON form as Go's
//! time.Time (RFC 3339, zero value 0001-01-01T00:00:00Z), so servers
//! installed by older builds keep reading them.

use std::fmt;

use chrono::{DateTime, SecondsFormat, TimeDelta, TimeZone, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Time(pub DateTime<Utc>);

impl Time {
    pub fn now() -> Time {
        Time(Utc::now())
    }

    pub fn zero() -> Time {
        Time(Utc.with_ymd_and_hms(1, 1, 1, 0, 0, 0).unwrap())
    }

    pub fn is_zero(&self) -> bool {
        *self == Time::zero()
    }

    /// self - earlier.
    pub fn since(&self, earlier: Time) -> TimeDelta {
        self.0 - earlier.0
    }

    #[cfg(test)]
    pub fn add(&self, d: TimeDelta) -> Time {
        Time(self.0 + d)
    }

    #[cfg(test)]
    pub fn ymd_hms(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> Time {
        Time(Utc.with_ymd_and_hms(y, mo, d, h, mi, s).unwrap())
    }
}

impl Default for Time {
    fn default() -> Self {
        Time::zero()
    }
}

impl fmt::Debug for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_rfc3339_opts(SecondsFormat::AutoSi, true))
    }
}

impl Serialize for Time {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_rfc3339_opts(SecondsFormat::AutoSi, true))
    }
}

impl<'de> Deserialize<'de> for Time {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        DateTime::parse_from_rfc3339(&s)
            .map(|t| Time(t.with_timezone(&Utc)))
            .map_err(|e| serde::de::Error::custom(format!("bad time {s:?}: {e}")))
    }
}

/// Formats whole seconds like Go's time.Duration String: "1h2m3s", "4m0s",
/// "5s".
pub fn duration_string(secs: i64) -> String {
    if secs == 0 {
        return "0s".into();
    }
    let sign = if secs < 0 { "-" } else { "" };
    let s = secs.unsigned_abs();
    let (h, m, s) = (s / 3600, s / 60 % 60, s % 60);
    match (h, m) {
        (0, 0) => format!("{sign}{s}s"),
        (0, _) => format!("{sign}{m}m{s}s"),
        _ => format!("{sign}{h}h{m}m{s}s"),
    }
}

/// Rounds a duration in milliseconds to whole units of unit ms, halves away
/// from zero (Go's Duration.Round).
pub fn round_ms(ms: i64, unit: i64) -> i64 {
    let half = unit / 2;
    if ms >= 0 { (ms + half) / unit * unit } else { -((-ms + half) / unit * unit) }
}

/// Serde helper: null decodes as the default value, like a nil slice in Go.
pub fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_form_matches_go() {
        assert_eq!(serde_json::to_string(&Time::zero()).unwrap(), r#""0001-01-01T00:00:00Z""#);
        let t: Time = serde_json::from_str(r#""2026-09-19T14:00:00.123456789+02:00""#).unwrap();
        assert_eq!(serde_json::to_string(&t).unwrap(), r#""2026-09-19T12:00:00.123456789Z""#);
        let t: Time = serde_json::from_str(r#""0001-01-01T00:00:00Z""#).unwrap();
        assert!(t.is_zero());
    }

    #[test]
    fn durations() {
        assert_eq!(duration_string(0), "0s");
        assert_eq!(duration_string(45), "45s");
        assert_eq!(duration_string(180), "3m0s");
        assert_eq!(duration_string(3723), "1h2m3s");
        assert_eq!(round_ms(1499, 1000), 1000);
        assert_eq!(round_ms(1500, 1000), 2000);
        assert_eq!(round_ms(89_999, 60_000), 60_000);
        assert_eq!(round_ms(90_000, 60_000), 120_000);
    }
}
