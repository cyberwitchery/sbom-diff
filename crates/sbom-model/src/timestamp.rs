//! the timestamp form readers store in [`Metadata::timestamp`](crate::Metadata).

use jiff::fmt::temporal::{DateTimePrinter, Pieces};

/// reads an rfc 3339 timestamp in any offset and writes it in utc with a `Z`,
/// fractional seconds in groups of three digits: `2010-01-29T20:30:22.5+02:00`
/// becomes `2010-01-29T18:30:22.500Z`.
///
/// a date without a time, a missing offset or a time zone annotation is
/// `None`.
pub fn normalize_timestamp(s: &str) -> Option<String> {
    let pieces = Pieces::parse(s).ok()?;
    if pieces.time_zone_annotation().is_some() {
        return None;
    }
    let offset = pieces.to_numeric_offset()?;
    let datetime = pieces.date().to_datetime(pieces.time()?);
    let instant = offset.to_timestamp(datetime).ok()?;
    let nanos = instant.subsec_nanosecond();
    let precision = if nanos == 0 {
        0
    } else if nanos % 1_000_000 == 0 {
        3
    } else if nanos % 1_000 == 0 {
        6
    } else {
        9
    };
    Some(
        DateTimePrinter::new()
            .precision(Some(precision))
            .timestamp_to_string(&instant),
    )
}

#[cfg(test)]
mod tests {
    use super::normalize_timestamp;

    #[test]
    fn writes_utc_with_z() {
        for (input, expected) in [
            ("2010-01-29T18:30:22Z", "2010-01-29T18:30:22Z"),
            ("2010-01-29T18:30:22+00:00", "2010-01-29T18:30:22Z"),
            ("2010-01-29T20:30:22+02:00", "2010-01-29T18:30:22Z"),
            ("2010-01-29t18:30:22z", "2010-01-29T18:30:22Z"),
            ("2010-01-29 18:30:22Z", "2010-01-29T18:30:22Z"),
        ] {
            assert_eq!(
                normalize_timestamp(input).as_deref(),
                Some(expected),
                "{input}"
            );
        }
    }

    #[test]
    fn fractional_seconds_in_groups_of_three() {
        for (input, expected) in [
            ("2010-01-29T18:30:22.5Z", "2010-01-29T18:30:22.500Z"),
            ("2010-01-29T18:30:22.12345Z", "2010-01-29T18:30:22.123450Z"),
            (
                "2010-01-29T18:30:22.1234567Z",
                "2010-01-29T18:30:22.123456700Z",
            ),
        ] {
            assert_eq!(
                normalize_timestamp(input).as_deref(),
                Some(expected),
                "{input}"
            );
        }
    }

    #[test]
    fn rejects_non_timestamps() {
        for input in [
            "not a date",
            "2010-01-29",
            "2010-01-29T18:30:22",
            "2010-01-29T18:30:22+01:00[Europe/Berlin]",
        ] {
            assert_eq!(normalize_timestamp(input), None, "{input}");
        }
    }
}
