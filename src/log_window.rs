//! A bounded window of a runtime's timestamped output, read from a point in
//! time, so that a caller can follow it with one bounded read after another.
//!
//! Each line starts with Docker's RFC 3339 UTC timestamp. Times here are
//! nanoseconds since the Unix epoch.

/// The most output one window holds.
pub const LIMIT: usize = 1024 * 1024;

/// A window of output and where the next one starts.
pub struct Window {
    /// Whole lines, each with its timestamp prefix, in Docker's order.
    pub output: Vec<u8>,
    /// The time to read from next. A read from it returns no line of this
    /// window, and skips none written since. None when nothing was read and
    /// no start was given.
    pub next: Option<i128>,
    /// Output after this window was already there when it was read.
    pub more: bool,
}

/// Docker's `--since` argument: Unix seconds with optional nanoseconds,
/// such as `1700000000` or `1700000000.000000001`.
pub fn parse_since(value: &str) -> Option<i128> {
    let (seconds, fraction) = value.split_once('.').unwrap_or((value, ""));
    if seconds.is_empty()
        || seconds.len() > 12
        || !seconds.bytes().all(|b| b.is_ascii_digit())
        || value.contains('.') && (fraction.is_empty() || fraction.len() > 9)
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let nanos: i128 = format!("{fraction:0<9}").parse().ok()?;
    Some(seconds.parse::<i128>().ok()? * 1_000_000_000 + nanos)
}

/// The `--since` argument for a time.
pub fn since_arg(time: i128) -> String {
    format!(
        "{}.{:09}",
        time.div_euclid(1_000_000_000),
        time.rem_euclid(1_000_000_000)
    )
}

/// The time of a line from its `YYYY-MM-DDTHH:MM:SS[.fraction]Z ` prefix.
pub fn line_time(line: &[u8]) -> Option<i128> {
    let end = line.iter().position(|b| *b == b' ')?;
    let stamp = std::str::from_utf8(&line[..end]).ok()?;
    let stamp = stamp.strip_suffix('Z')?;
    let (date, time) = stamp.split_once('T')?;
    let number = |s: &str, len: usize| -> Option<i64> {
        (s.len() == len && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    };
    let mut date = date.split('-');
    let (year, month, day) = (
        number(date.next()?, 4)?,
        number(date.next()?, 2)?,
        number(date.next()?, 2)?,
    );
    let (clock, fraction) = time.split_once('.').unwrap_or((time, ""));
    let mut clock = clock.split(':');
    let (hour, minute, second) = (
        number(clock.next()?, 2)?,
        number(clock.next()?, 2)?,
        number(clock.next()?, 2)?,
    );
    if date.next().is_some()
        || clock.next().is_some()
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
        || time.contains('.') && (fraction.is_empty() || fraction.len() > 9)
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let nanos: i128 = format!("{fraction:0<9}").parse().ok()?;
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    Some(i128::from(seconds) * 1_000_000_000 + nanos)
}

/// Days from 1970-01-01 to a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The window in `bytes`, read from `since`. `complete` says the read reached
/// the end of the output rather than stopping at `LIMIT`.
///
/// A complete read keeps every line, and the next read starts just after the
/// latest. A read that stopped at the limit keeps only lines before the time
/// of its last whole line, and the next read starts at that time: lines of
/// that same nanosecond may continue past the limit. Only if every line has
/// that time does the window keep them all and move past it.
pub fn window(bytes: &[u8], complete: bool, since: Option<i128>) -> Window {
    let mut lines: Vec<(&[u8], Option<i128>)> = Vec::new();
    let mut previous = since;
    for line in bytes.split_inclusive(|b| *b == b'\n') {
        if !complete && !line.ends_with(b"\n") {
            break;
        }
        // A line without its own timestamp continues the one before it.
        let time = line_time(line).or(previous);
        previous = time;
        lines.push((line, time));
    }
    let latest = lines.iter().filter_map(|(_, t)| *t).max();
    if complete {
        return Window {
            output: join(&lines),
            next: latest.map(|t| t + 1).or(since),
            more: false,
        };
    }
    let Some(last) = lines.last().and_then(|(_, t)| *t) else {
        return Window {
            output: join(&lines),
            next: latest.map(|t| t + 1).or(since),
            more: !lines.is_empty(),
        };
    };
    let before: Vec<_> = lines
        .iter()
        .copied()
        .filter(|(_, t)| t.is_some_and(|t| t < last))
        .collect();
    if before.is_empty() {
        return Window {
            output: join(&lines),
            next: Some(last + 1),
            more: true,
        };
    }
    Window {
        output: join(&before),
        next: Some(last),
        more: true,
    }
}

fn join(lines: &[(&[u8], Option<i128>)]) -> Vec<u8> {
    lines
        .iter()
        .flat_map(|(line, _)| line.iter().copied())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i128 = 1_795_428_000_000_000_000; // 2026-11-23T10:00:00Z

    #[test]
    fn docker_timestamps_and_since_arguments_round_trip() {
        assert_eq!(line_time(b"2026-11-23T10:00:00Z x\n"), Some(T0));
        assert_eq!(
            line_time(b"2026-11-23T10:00:00.000000001Z x\n"),
            Some(T0 + 1)
        );
        assert_eq!(
            line_time(b"2026-11-23T10:00:00.5Z x"),
            Some(T0 + 500_000_000)
        );
        assert_eq!(line_time(b"1970-01-01T00:00:00Z x"), Some(0));
        assert_eq!(
            line_time(b"2000-03-01T00:00:00Z x"),
            Some(951_868_800 * 1_000_000_000)
        );
        for invalid in [
            &b"2026-11-23T10:00:00+01:00 x"[..],
            b"2026-11-23 10:00:00Z x",
            b"2026-13-23T10:00:00Z x",
            b"2026-11-23T10:00:00.Z x",
            b"2026-11-23T10:00:00.1234567890Z x",
            b"2026-11-23T10:00:00Z",
            b"plain output\n",
        ] {
            assert_eq!(line_time(invalid), None);
        }

        assert_eq!(parse_since("1795428000"), Some(T0));
        assert_eq!(parse_since("1795428000.000000001"), Some(T0 + 1));
        assert_eq!(parse_since("1795428000.5"), Some(T0 + 500_000_000));
        for invalid in [
            "",
            "-1",
            "1.",
            ".5",
            "1.1234567890",
            "1e9",
            "1795428000Z",
            "10m",
        ] {
            assert_eq!(parse_since(invalid), None, "{invalid}");
        }
        assert_eq!(since_arg(T0 + 1), "1795428000.000000001");
        assert_eq!(parse_since(&since_arg(T0 + 123)), Some(T0 + 123));
    }

    #[test]
    fn a_complete_read_keeps_every_line_and_continues_after_the_latest() {
        let bytes = b"2026-11-23T10:00:00Z one\n2026-11-23T10:00:00.000000002Z two\n\
            continued\n2026-11-23T10:00:00.000000001Z err\npartial";
        let window = window(bytes, true, None);
        assert_eq!(window.output, bytes);
        assert_eq!(window.next, Some(T0 + 3));
        assert!(!window.more);

        let empty = super::window(b"", true, Some(T0));
        assert!(empty.output.is_empty());
        assert_eq!(empty.next, Some(T0));
        assert!(!empty.more);
        assert_eq!(super::window(b"", true, None).next, None);
    }

    #[test]
    fn a_read_cut_at_the_limit_resumes_at_its_last_lines_time() {
        let bytes = b"2026-11-23T10:00:00Z one\n2026-11-23T10:00:00.000000001Z two\n\
            2026-11-23T10:00:00.000000001Z two again\n2026-11-23T10:00:00.0000000";
        let window = window(bytes, false, None);
        assert_eq!(window.output, b"2026-11-23T10:00:00Z one\n");
        assert_eq!(window.next, Some(T0 + 1));
        assert!(window.more);

        // A window that is all one nanosecond still moves on.
        let same = b"2026-11-23T10:00:00Z a\n2026-11-23T10:00:00Z b\n2026-11";
        let window = super::window(same, false, Some(T0));
        assert_eq!(
            window.output,
            b"2026-11-23T10:00:00Z a\n2026-11-23T10:00:00Z b\n"
        );
        assert_eq!(window.next, Some(T0 + 1));
        assert!(window.more);
    }
}
