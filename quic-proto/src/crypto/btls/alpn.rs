use crate::crypto::btls::error::{Error, Result};

/// A non-empty list of ALPN protocols, each of 1 to 255 bytes
/// ([RFC 7301 §3.1](https://www.rfc-editor.org/rfc/rfc7301#section-3.1)).
#[derive(Clone, Debug)]
pub(crate) struct AlpnProtocols(Vec<Vec<u8>>);

impl AlpnProtocols {
    pub(crate) const H3: &'static [u8; 2] = b"h3";

    /// Performs the server-side ALPN protocol selection, in the server's order of preference.
    pub(crate) fn select<'a>(&self, offered: &'a [u8]) -> Result<&'a [u8]> {
        self.0
            .iter()
            .find_map(|proto| parse(offered).find(|offered| offered == proto))
            .ok_or_else(|| Error::other("ALPN selection failed".into()))
    }

    /// Encodes the list in the wire format of `SSL_set_alpn_protos`.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.0.iter().map(|proto| 1 + proto.len()).sum());
        for proto in &self.0 {
            // `try_from` checked the length.
            out.push(proto.len() as u8);
            out.extend_from_slice(proto);
        }
        out
    }
}

impl Default for AlpnProtocols {
    fn default() -> Self {
        Self(vec![Self::H3.to_vec()])
    }
}

impl TryFrom<&[Vec<u8>]> for AlpnProtocols {
    type Error = Error;

    fn try_from(protos: &[Vec<u8>]) -> Result<Self> {
        if protos.is_empty() {
            return Err(Error::invalid_input("no ALPN protocols".into()));
        }
        if let Some(proto) = protos
            .iter()
            .find(|proto| !(1..=255).contains(&proto.len()))
        {
            return Err(Error::invalid_input(format!(
                "invalid ALPN protocol length: {}",
                proto.len()
            )));
        }
        Ok(Self(protos.to_vec()))
    }
}

/// Iterates over the protocols of a length-prefixed list, up to the first malformed entry.
fn parse(mut list: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::from_fn(move || {
        let (&len, rest) = list.split_first()?;
        let proto = rest.get(..usize::from(len))?;
        list = &rest[proto.len()..];
        Some(proto)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_protocols() {
        let protos = AlpnProtocols::try_from(&[b"h3".to_vec(), b"hq".to_vec()][..]).unwrap();
        assert_eq!(protos.encode(), b"\x02h3\x02hq");

        // The server's preference wins, and a malformed tail is ignored.
        assert_eq!(protos.select(b"\x02hq\x02h3").unwrap(), b"h3");
        assert_eq!(protos.select(b"\x02hq\x05h3").unwrap(), b"hq");
        assert!(protos.select(b"\x05h3").is_err());

        for invalid in [&[][..], &[Vec::new()], &[vec![0; 256]]] {
            assert!(AlpnProtocols::try_from(invalid).is_err());
        }
    }
}
