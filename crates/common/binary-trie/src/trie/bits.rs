//! Bit-level helpers. Bits are `Vec<u8>` of 0/1 values, MSB-first,
//! matching the spec's readability-first representation.

/// Expand each byte into eight bits, most significant bit first.
pub fn bytes_to_bits(data: &[u8]) -> Vec<u8> {
    data.iter()
        .flat_map(|byte| (0..8).map(move |offset| (byte >> (7 - offset)) & 1))
        .collect()
}

/// Encode a branch prefix: a two-byte big-endian bit count followed by
/// the bits packed MSB-first, zero-padded to a byte boundary.
///
/// The explicit count keeps the encoding injective: without it, two
/// prefixes differing only in trailing zero bits would pack to the
/// same bytes and two different trees could share a root.
pub fn encode_bit_prefix(prefix: &[u8]) -> Vec<u8> {
    debug_assert!(prefix.iter().all(|b| *b <= 1), "prefix bits must be 0 or 1");
    assert!(
        prefix.len() < 1 << 16,
        "prefix bit count must fit in two bytes"
    );
    let mut out = vec![0u8; 2 + prefix.len().div_ceil(8)];
    out[..2].copy_from_slice(&(prefix.len() as u16).to_be_bytes());
    for (i, bit) in prefix.iter().enumerate() {
        out[2 + i / 8] |= bit << (7 - i % 8);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_bits_msb_first() {
        assert_eq!(bytes_to_bits(&[0b1010_0001]), vec![1, 0, 1, 0, 0, 0, 0, 1]);
        assert_eq!(bytes_to_bits(&[]), Vec::<u8>::new());
        assert_eq!(bytes_to_bits(&[0x80, 0x01])[0], 1);
        assert_eq!(bytes_to_bits(&[0x80, 0x01])[15], 1);
    }

    #[test]
    fn encode_bit_prefix_empty() {
        assert_eq!(encode_bit_prefix(&[]), vec![0x00, 0x00]);
    }

    #[test]
    fn encode_bit_prefix_packs_msb_first_and_pads() {
        assert_eq!(encode_bit_prefix(&[1, 0, 1]), vec![0x00, 0x03, 0b1010_0000]);
        let nine = vec![1, 1, 1, 1, 1, 1, 1, 1, 1];
        assert_eq!(encode_bit_prefix(&nine), vec![0x00, 0x09, 0xff, 0x80]);
    }

    #[test]
    fn encode_bit_prefix_is_injective_on_trailing_zeros() {
        assert_ne!(encode_bit_prefix(&[1]), encode_bit_prefix(&[1, 0]));
    }
}
