use super::{ConfigError, ConfigKey, Result};

pub(crate) fn option_to_string<T>(value: Option<T>) -> String
where
    T: ToString,
{
    value.map_or_else(|| "default".to_owned(), |value| value.to_string())
}

pub(crate) fn parse_optional_u16(key: ConfigKey, value: &str) -> Result<Option<u16>> {
    parse_optional_number(key, value)
}

pub(crate) fn parse_optional_u64(key: ConfigKey, value: &str) -> Result<Option<u64>> {
    parse_optional_number(key, value)
}

pub(crate) fn parse_optional_usize(key: ConfigKey, value: &str) -> Result<Option<usize>> {
    parse_optional_number(key, value)
}

pub(crate) fn parse_optional_string(value: &str) -> Option<String> {
    // Empty strings are normalised to `None` alongside the explicit
    // sentinels — `cfg set ipc.socket_uri ""` should clear the field, not
    // set it to an empty path that would later confuse bind/connect code.
    if value.is_empty() || is_default_value(value) {
        None
    } else {
        Some(value.to_owned())
    }
}

fn parse_optional_number<T>(key: ConfigKey, value: &str) -> Result<Option<T>>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    if is_default_value(value) {
        return Ok(None);
    }

    value
        .parse::<T>()
        .map(Some)
        .map_err(|err| ConfigError::InvalidValue {
            key: key.as_str().to_owned(),
            value: value.to_owned(),
            reason: err.to_string(),
        })
}

fn is_default_value(value: &str) -> bool {
    matches!(value, "default" | "none" | "null")
}
