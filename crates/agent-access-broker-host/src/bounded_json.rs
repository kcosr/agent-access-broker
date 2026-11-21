//! Bound serialized inspection responses before committing any response bytes.
use serde::Serialize;
use std::io::{self, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    TooLarge,
    Serialization,
}

struct Writer {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(required) = self.bytes.len().checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("inspection response limit"));
        };
        if required > self.limit {
            self.exceeded = true;
            return Err(io::Error::other("inspection response limit"));
        }
        if required > self.bytes.capacity() {
            let capacity = required
                .max(self.bytes.capacity().saturating_mul(2))
                .min(self.limit);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(|_| io::Error::other("inspection response allocation"))?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn serialize(value: &impl Serialize, limit: usize) -> Result<Vec<u8>, Error> {
    let mut writer = Writer {
        bytes: Vec::new(),
        limit,
        exceeded: false,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| {
        if writer.exceeded {
            Error::TooLarge
        } else {
            Error::Serialization
        }
    })?;
    Ok(writer.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exact_byte_limit_counts_escaping_and_utf8_before_allocation() {
        let value = json!({"text":"界\n\"\\","data":[true,null,123]});
        let expected = serde_json::to_vec(&value).unwrap();
        assert_eq!(serialize(&value, expected.len()).unwrap(), expected);
        assert_eq!(serialize(&value, expected.len() - 1), Err(Error::TooLarge));
        let mut writer = Writer {
            bytes: Vec::new(),
            limit: 5,
            exceeded: false,
        };
        assert!(writer.write_all(b"012345").is_err());
        assert_eq!(writer.bytes.capacity(), 0);
        assert!(writer.bytes.is_empty());
    }

    #[test]
    fn serializable_error_is_not_misclassified_as_an_oversize_response() {
        struct Invalid;
        impl Serialize for Invalid {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("synthetic failure"))
            }
        }
        assert_eq!(serialize(&Invalid, 100), Err(Error::Serialization));
    }
}
