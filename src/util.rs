#[cfg(test)]
#[macro_use]
pub mod test;

mod crypto;

pub use self::crypto::{gen_nonce, DigestWrite, NeverRng};

use core::num::NonZeroU8;
use std::time::SystemTime;

use time::format_description::well_known::iso8601::{self, Iso8601};
use time::OffsetDateTime;

pub fn format_iso8601_time(time: SystemTime) -> String {
    const FORMAT: Iso8601<
        {
            iso8601::Config::DEFAULT
                // Default precision of 9 digits seems to be too much.
                .set_time_precision(iso8601::TimePrecision::Second {
                    decimal_digits: NonZeroU8::new(3),
                })
                .encode()
        },
    > = Iso8601;

    // XXX: There appears to be no way to avoid the allocation of the `String`,
    // <https://github.com/time-rs/time/issues/375>
    OffsetDateTime::from(time).format(&FORMAT).unwrap()
}
