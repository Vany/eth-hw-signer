//! Minimal SSZ merkleization, hand-written for the consensus containers this
//! crate signs (see consensus-specs `ssz/simple-serialize.md`).
//!
//! Only what signing roots need:
//! - packing a `uint64` into a 32-byte chunk (little-endian, zero-padded),
//! - padding short byte vectors (`Vector[byte, N]` with `N <= 32`) into a
//!   chunk,
//! - packing byte vectors of any fixed length (e.g. the 96-byte
//!   `BLSSignature`) into multiple chunks,
//! - merkleizing a list of chunks up to the next power of two (zero-padded),
//!   or up to a type-declared chunk *limit* (bitlists/bitvectors),
//! - `Bitlist[N]` / `Bitvector[N]` parsing (delimiter validation included)
//!   and their roots, including the `mix_in_length` rule for bitlists
//!   (needed for `AggregateAndProof`, whose `aggregate` is a full
//!   `Attestation` with aggregation bits).
//!
//! Free-standing variable-size lists of composite objects are still not
//! implemented; nothing we sign needs them.

use alloc::vec::Vec;
use core::fmt;
use sha2::{Digest, Sha256};

/// Why an SSZ value failed to parse. Parsing is strict: anything that is not
/// a canonical SSZ serialization of the target type is refused rather than
/// guessed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SszError {
    /// Empty input where at least one byte was required.
    Empty,
    /// A `Bitlist` serialization must carry a set delimiter bit; the input
    /// was zero or ended in zero bytes.
    MissingDelimiter,
    /// Bytes after the delimiter byte (SSZ serializations are minimal, so
    /// trailing zero bytes are non-canonical).
    TrailingBytes,
    /// The bit length carried by the input exceeds the type's limit `N`.
    BitLengthExceedsLimit { bit_len: usize, limit: usize },
    /// A `Bitvector[N]` serializes to exactly `ceil(N / 8)` bytes.
    WrongByteLength { got: usize, expected: usize },
    /// A `Bitvector[N]` bit count does not fit exactly in the byte width of
    /// the target type (`(BYTES-1)*8 < N <= BYTES*8` violated).
    BitLengthMismatch { bits: usize, bytes: usize },
    /// A `Bitvector[N]` has bits set at positions `>= N`.
    BitsAboveLimit,
}

impl fmt::Display for SszError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty SSZ input"),
            Self::MissingDelimiter => {
                write!(
                    f,
                    "bitlist serialization is missing its length-delimiting bit"
                )
            }
            Self::TrailingBytes => {
                write!(f, "bytes after the bitlist delimiter byte (non-canonical)")
            }
            Self::BitLengthExceedsLimit { bit_len, limit } => {
                write!(f, "bit length {bit_len} exceeds the type limit {limit}")
            }
            Self::WrongByteLength { got, expected } => {
                write!(f, "expected {expected} bytes, got {got}")
            }
            Self::BitLengthMismatch { bits, bytes } => {
                write!(
                    f,
                    "bit count {bits} does not fit exactly in the {bytes}-byte bitvector width"
                )
            }
            Self::BitsAboveLimit => write!(f, "bits set above the bitvector length"),
        }
    }
}

/// SSZ chunk size in bytes.
pub const BYTES_PER_CHUNK: usize = 32;

/// SHA-256 of the concatenation of two chunks (one tree node).
fn hash_pair(a: &[u8; BYTES_PER_CHUNK], b: &[u8; BYTES_PER_CHUNK]) -> [u8; BYTES_PER_CHUNK] {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    hasher.finalize().into()
}

/// Pack a `uint64` into a chunk: 8 little-endian bytes, zero-padded to 32.
pub fn uint64_chunk(value: u64) -> [u8; BYTES_PER_CHUNK] {
    let mut chunk = [0u8; BYTES_PER_CHUNK];
    chunk[..8].copy_from_slice(&value.to_le_bytes());
    chunk
}

/// Right-pad `bytes` (at most one chunk's worth) with zeros into a chunk.
/// This is the packed form of `Vector[byte, N]` for `N <= 32`.
///
/// # Panics
/// Panics if `bytes.len() > 32`.
pub fn byte_vector_chunk(bytes: &[u8]) -> [u8; BYTES_PER_CHUNK] {
    assert!(
        bytes.len() <= BYTES_PER_CHUNK,
        "byte vector spans multiple chunks"
    );
    let mut chunk = [0u8; BYTES_PER_CHUNK];
    chunk[..bytes.len()].copy_from_slice(bytes);
    chunk
}

/// Merkleize `chunks` after zero-padding to the next power of two (minimum
/// one leaf). This is the container rule: a container with N fields has
/// `next_pow_of_two(N)` leaves.
pub fn merkleize(chunks: &[[u8; BYTES_PER_CHUNK]]) -> [u8; BYTES_PER_CHUNK] {
    let width = chunks.len().max(1).next_power_of_two();
    merkleize_limited(chunks, width)
}

/// Merkleize `chunks` padded to `next_pow_of_two(limit_chunks)` leaves — the
/// `limit` form of consensus-specs `merkleize`, used by types that declare a
/// maximum size (`Bitlist[N]`, `Bitvector[N]`): the tree is padded to the
/// *type's* chunk count, not the value's.
///
/// # Panics
/// Panics if `chunks.len() > limit_chunks` (the value exceeds its own type;
/// the bit parsers in this module make that unreachable).
pub fn merkleize_limited(
    chunks: &[[u8; BYTES_PER_CHUNK]],
    limit_chunks: usize,
) -> [u8; BYTES_PER_CHUNK] {
    assert!(
        chunks.len() <= limit_chunks,
        "SSZ value spans {} chunks, beyond its type limit {limit_chunks}",
        chunks.len()
    );
    let width = limit_chunks.max(1).next_power_of_two();
    let mut layer: Vec<[u8; BYTES_PER_CHUNK]> = Vec::with_capacity(width);
    layer.extend_from_slice(chunks);
    layer.resize(width, [0u8; BYTES_PER_CHUNK]);
    while layer.len() > 1 {
        layer = layer
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| hash_pair(&pair[0], &pair[1]))
            .collect();
    }
    layer[0]
}

/// Partition `bytes` into 32-byte chunks, zero-padding the tail (consensus
/// -specs `pack`).
pub fn pack(bytes: &[u8]) -> Vec<[u8; BYTES_PER_CHUNK]> {
    let mut chunks = Vec::with_capacity(bytes.len().div_ceil(BYTES_PER_CHUNK));
    for part in bytes.chunks(BYTES_PER_CHUNK) {
        let mut chunk = [0u8; BYTES_PER_CHUNK];
        chunk[..part.len()].copy_from_slice(part);
        chunks.push(chunk);
    }
    chunks
}

/// `mix_in_length`: `hash(root, length)` with the length as a 32-byte
/// little-endian chunk (the spec's "uint256 little-endian"; identical to a
/// zero-padded `uint64` chunk for every length this crate handles).
pub fn mix_in_length(root: [u8; BYTES_PER_CHUNK], length: u64) -> [u8; BYTES_PER_CHUNK] {
    hash_pair(&root, &uint64_chunk(length))
}

/// Leaf count for a bit type of at most `bits` bits:
/// `(bits + 255) // 256` per consensus-specs `chunk_count`.
const fn chunk_count_bits(bits: usize) -> usize {
    bits.div_ceil(BYTES_PER_CHUNK * 8)
}

/// A parsed SSZ `Bitlist[N]`: the packed payload bits (delimiter excluded)
/// plus the bit length. Created only through [`Bitlist::from_ssz_bytes`],
/// which validates the delimiter, so a `Bitlist` is always canonical.
#[derive(Clone, PartialEq, Eq)]
pub struct Bitlist<const MAX_BITS: usize> {
    /// Packed bits, LSB-first within each byte, exactly
    /// `ceil(bit_len / 8)` bytes (possibly empty).
    payload: Vec<u8>,
    bit_len: usize,
}

impl<const MAX_BITS: usize> Bitlist<MAX_BITS> {
    /// The type limit `N`.
    pub const LIMIT: usize = MAX_BITS;

    /// Parse the SSZ serialization of a `Bitlist[N]` — the `0x`-hex bytes a
    /// consensus client carries on the wire, including the terminating
    /// delimiter bit at index `bit_len`. Strict: the delimiter must be the
    /// highest set bit, no byte may follow it, and `bit_len` must not exceed
    /// `N`.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        let Some((&last, _)) = bytes.split_last() else {
            return Err(SszError::Empty);
        };
        if last == 0 {
            // Either an all-zero input (no delimiter anywhere) or zero bytes
            // after the delimiter byte; both are non-canonical.
            return Err(if bytes.iter().any(|&b| b != 0) {
                SszError::TrailingBytes
            } else {
                SszError::MissingDelimiter
            });
        }
        let high = 7 - last.leading_zeros() as usize; // highest set bit of `last`
        let bit_len = (bytes.len() - 1) * 8 + high;
        if bit_len > MAX_BITS {
            return Err(SszError::BitLengthExceedsLimit {
                bit_len,
                limit: MAX_BITS,
            });
        }
        // Payload: the bytes carrying the bits, with the delimiter bit
        // cleared. When `bit_len` is byte-aligned the delimiter lives in its
        // own trailing byte, which the slice below already excludes. Bits
        // above `bit_len` in the final payload byte are zero by construction
        // (`high` is the highest set bit).
        let mut payload = bytes[..bit_len.div_ceil(8)].to_vec();
        if !bit_len.is_multiple_of(8) {
            if let Some(payload_last) = payload.last_mut() {
                *payload_last &= !(1 << (bit_len % 8));
            }
        }
        debug_assert_eq!(payload.len(), bit_len.div_ceil(8));
        Ok(Self { payload, bit_len })
    }

    /// Number of bits in the list.
    pub fn bit_len(&self) -> usize {
        self.bit_len
    }

    /// The canonical SSZ serialization (payload plus the delimiter bit set
    /// at index `bit_len`) — the inverse of [`Bitlist::from_ssz_bytes`].
    pub fn to_ssz_bytes(&self) -> Vec<u8> {
        let mut out = self.payload.clone();
        match self.bit_len % 8 {
            0 => out.push(1),
            offset => *out.last_mut().expect("bit_len > 0 implies a payload byte") |= 1 << offset,
        }
        out
    }
}

impl<const MAX_BITS: usize> HashTreeRoot for Bitlist<MAX_BITS> {
    /// `mix_in_length(merkleize(pack_bits(value), limit=chunk_count(type)),
    /// len(value))` — the tree covers the *type's* limit; the actual bit
    /// count is mixed in as the length.
    fn hash_tree_root(&self) -> [u8; BYTES_PER_CHUNK] {
        mix_in_length(
            merkleize_limited(&pack(&self.payload), chunk_count_bits(MAX_BITS)),
            self.bit_len as u64,
        )
    }
}

impl<const MAX_BITS: usize> fmt::Debug for Bitlist<MAX_BITS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.to_ssz_bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl<const BITS: usize> fmt::Debug for Bitvector<BITS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A parsed SSZ `Bitvector[N]`. The const parameter is the *byte* length
/// `ceil(N / 8)` (stable Rust forbids arithmetic on const parameters in
/// array types); the bit count `N` is passed to
/// [`Bitvector::from_ssz_bytes`], which checks the two agree. No delimiter,
/// no length mix-in.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Bitvector<const BYTES: usize> {
    bytes: [u8; BYTES],
}

impl<const BYTES: usize> Bitvector<BYTES> {
    /// Parse the SSZ serialization of a `Bitvector[bits]`: exactly
    /// `ceil(bits / 8) == BYTES` bytes, with no bits set at positions
    /// `>= bits`.
    pub fn from_ssz_bytes(bytes: &[u8], bits: usize) -> Result<Self, SszError> {
        if bytes.len() != BYTES {
            return Err(SszError::WrongByteLength {
                got: bytes.len(),
                expected: BYTES,
            });
        }
        // bits must be exactly the count this byte length can carry.
        if bits == 0 || bits > BYTES * 8 || bits <= (BYTES.saturating_sub(1)) * 8 {
            return Err(SszError::BitLengthMismatch { bits, bytes: BYTES });
        }
        let mut value = Self {
            bytes: [0u8; BYTES],
        };
        value.bytes.copy_from_slice(bytes);
        if !bits.is_multiple_of(8) && value.bytes[BYTES - 1] >> (bits % 8) != 0 {
            return Err(SszError::BitsAboveLimit);
        }
        Ok(value)
    }

    /// The packed bytes (exactly `BYTES`).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<const BYTES: usize> HashTreeRoot for Bitvector<BYTES> {
    /// `merkleize(pack_bits(value), limit=chunk_count(type))` — no length
    /// mix-in. The leaf limit uses the full `BYTES * 8` bits, which is the
    /// same 256-bit chunk window as `bits` because the two differ by less
    /// than one byte.
    fn hash_tree_root(&self) -> [u8; BYTES_PER_CHUNK] {
        merkleize_limited(&pack(&self.bytes), chunk_count_bits(BYTES * 8))
    }
}

/// The SSZ hash-tree-root operation, implemented for the fixed-size types
/// used as container fields in this crate.
pub trait HashTreeRoot {
    /// Merkleized SSZ hash tree root.
    fn hash_tree_root(&self) -> [u8; BYTES_PER_CHUNK];
}

impl HashTreeRoot for u64 {
    fn hash_tree_root(&self) -> [u8; BYTES_PER_CHUNK] {
        uint64_chunk(*self)
    }
}

/// `Vector[byte, 4]`: fork versions and domain types.
impl HashTreeRoot for [u8; 4] {
    fn hash_tree_root(&self) -> [u8; BYTES_PER_CHUNK] {
        byte_vector_chunk(self)
    }
}

/// `Bytes32`: roots, public keys' tree leaves, and domains.
impl HashTreeRoot for [u8; 32] {
    fn hash_tree_root(&self) -> [u8; BYTES_PER_CHUNK] {
        *self
    }
}

/// `Vector[byte, 96]` (`BLSSignature`): three chunks merkleized to four
/// leaves.
impl HashTreeRoot for [u8; 96] {
    fn hash_tree_root(&self) -> [u8; BYTES_PER_CHUNK] {
        merkleize(&pack(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::unhex;
    use alloc::vec;

    #[test]
    fn uint64_chunk_is_little_endian_padded() {
        assert_eq!(uint64_chunk(1)[..8], [1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            uint64_chunk(0x0102030405060708)[..8],
            [8, 7, 6, 5, 4, 3, 2, 1]
        );
        assert_eq!(uint64_chunk(7)[8..], [0u8; 24]);
    }

    #[test]
    fn two_chunks_merkleize_to_sha256_pair() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        assert_eq!(merkleize(&[a, b]), hash_pair(&a, &b));
    }

    #[test]
    fn five_chunks_are_padded_to_eight_leaves() {
        // 5 field roots + 3 zero chunks, then three rounds of pairing.
        let leaves: Vec<[u8; 32]> = (0u8..5).map(|i| [i + 1; 32]).collect();
        let mut padded: Vec<[u8; 32]> = leaves.clone();
        padded.resize(8, [0; 32]);
        let mut layer = padded;
        while layer.len() > 1 {
            layer = layer
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| hash_pair(&p[0], &p[1]))
                .collect();
        }
        assert_eq!(merkleize(&leaves), layer[0]);
    }

    #[test]
    fn pack_partitions_and_zero_pads() {
        let bytes = [0xabu8; 96];
        let chunks = pack(&bytes);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], [0xab; 32]);
        let mut short = [0u8; 32];
        short[..3].copy_from_slice(&[1, 2, 3]);
        assert_eq!(pack(&[1, 2, 3]), vec![short]);
        // Tail padding: 33 bytes span two chunks, the second mostly zero.
        let long = [7u8; 33];
        let chunks = pack(&long);
        assert_eq!(chunks.len(), 2);
        assert_eq!(&chunks[1][..1], &[7]);
        assert_eq!(&chunks[1][1..], &[0u8; 31]);
    }

    #[test]
    fn merkleize_limited_pads_to_the_type_limit() {
        // 3 chunks under a 3-chunk type limit: 4 leaves, like
        // Bitlist[513] / Bitlist[512..767] chunk_count = 3.
        let leaves: Vec<[u8; 32]> = (0u8..3).map(|i| [i + 1; 32]).collect();
        let mut padded = leaves.clone();
        padded.resize(4, [0; 32]);
        let mut layer = padded;
        while layer.len() > 1 {
            layer = layer
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| hash_pair(&p[0], &p[1]))
                .collect();
        }
        assert_eq!(merkleize_limited(&leaves, 3), layer[0]);
    }

    #[test]
    #[should_panic(expected = "beyond its type limit")]
    fn merkleize_limited_rejects_chunks_beyond_the_limit() {
        merkleize_limited(&[[0u8; 32]; 3], 2);
    }

    // Fixed vectors below are copied verbatim from consensus-spec-tests
    // v1.5.0 `tests/general/phase0/ssz_generic/{bitlist,bitvector}/valid`
    // (value.yaml = the SSZ serialization, meta.yaml = the root):
    // https://github.com/ethereum/consensus-spec-tests/releases/tag/v1.5.0
    // These exercise pack, the type-limit merkleization and the length
    // mix-in exactly as the spec generator computes them.

    fn root_of_hex(hex: &str) -> [u8; 32] {
        unhex(hex).try_into().expect("32-byte root")
    }

    fn bitlist_root<const N: usize>(serialized_hex: &str, expected_hex: &str) {
        let parsed = Bitlist::<N>::from_ssz_bytes(&unhex(serialized_hex))
            .unwrap_or_else(|e| panic!("{serialized_hex}: {e}"));
        assert_eq!(
            parsed.hash_tree_root(),
            root_of_hex(expected_hex),
            "serialized: {serialized_hex}"
        );
    }

    #[test]
    fn bitlist_roots_match_consensus_spec_vectors() {
        // Single-chunk limits (N <= 256): chunk_count = 1.
        // bitlist_2_nil_0: empty bitlist, delimiter only.
        bitlist_root::<2>(
            "0x01",
            "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
        );
        // bitlist_8_random_2: one zero bit (delimiter at index 1).
        bitlist_root::<8>(
            "0x02",
            "0xcb592844121d926f1ca3ad4e1d6fb9d8e260ed6e3216361f7732e975a0e8bbf6",
        );
        // bitlist_16_max_3: 13 set bits.
        bitlist_root::<16>(
            "0xff3f",
            "0x16472e350c0d8e0cf112307b5cfa66561668ffef5f9f3281c9ad0af85122ba2c",
        );
        // Multi-chunk limits: N = 512 (chunk_count 2) and N = 513
        // (chunk_count 3 -> padded to 4 leaves).
        bitlist_root::<512>(
            "0xffffffffffff07",
            "0x8cbf50b584a296a316a71c486b4d4e1fd94edae9bf75f1aff71b8f609dc8352c",
        );
        bitlist_root::<513>(
            "0x3d5d6deff83de482be7cf35d77e0f25a74cc67457b9706deda4d2052110a1b85bb2a574dc1c2d7d88088e5a92bb64b5162be2d719561fc2d8c96850cff7d60de03",
            "0x4edc0e0f8cb3511f8e89e5a9d73fdd50270e49aa8bfa62ffe8c8e99c161e76ba",
        );
        bitlist_root::<513>(
            "0xf5a16787b899b86bd473f074438bb7b4c0382a3b5d8cfd26eba9be6b48ebb342ef",
            "0x339f84a3e78443af74c3ea49f06c6d1933f3b4e3440dc631820662651085a306",
        );
    }

    #[test]
    fn bitvector_roots_match_consensus_spec_vectors() {
        let bits16_max: Bitvector<2> =
            Bitvector::from_ssz_bytes(&unhex("0xffff"), 16).expect("valid");
        assert_eq!(
            bits16_max.hash_tree_root(),
            root_of_hex("0xffff000000000000000000000000000000000000000000000000000000000000")
        );
        let bits1_zero: Bitvector<1> = Bitvector::from_ssz_bytes(&[0x00], 1).expect("valid");
        assert_eq!(
            bits1_zero.hash_tree_root(),
            root_of_hex("0x0000000000000000000000000000000000000000000000000000000000000000")
        );
        // bitvec_512_random: 64 bytes, chunk_count 2.
        let bits512: Bitvector<64> = Bitvector::from_ssz_bytes(
            &unhex(
                "0x5098d1b21db56ac5ef8f6090a40c12d30c34387b449b4f6563d1f80b2817da04341b845eda81c40168971ed1b3046bf5f40c6265ba5b4d2b25a798d41aeb46de",
            ),
            512,
        )
        .expect("valid");
        assert_eq!(
            bits512.hash_tree_root(),
            root_of_hex("0xfbdb71e991457c4fd956e16be1ae1dc959bceaf00f692fec9431de3f0175655a")
        );
    }

    #[test]
    fn bitlist_parsing_rejects_non_canonical_input() {
        // Mirrors the invalid classes of consensus-spec-tests
        // ssz_generic/bitlist/invalid.
        // Empty input.
        assert_eq!(Bitlist::<8>::from_ssz_bytes(&[]), Err(SszError::Empty));
        // No delimiter bit at all.
        assert_eq!(
            Bitlist::<8>::from_ssz_bytes(&[0x00]),
            Err(SszError::MissingDelimiter)
        );
        assert_eq!(
            Bitlist::<8>::from_ssz_bytes(&[0x00, 0x00, 0x00]),
            Err(SszError::MissingDelimiter)
        );
        // Trailing zero byte after the delimiter byte.
        assert_eq!(
            Bitlist::<8>::from_ssz_bytes(&[0x02, 0x00]),
            Err(SszError::TrailingBytes)
        );
        // Length beyond the type limit (bitlist_8_but_9-class inputs): the
        // highest set bit sits past N.
        assert_eq!(
            Bitlist::<2>::from_ssz_bytes(&[0x08]),
            Err(SszError::BitLengthExceedsLimit {
                bit_len: 3,
                limit: 2
            })
        );
        assert_eq!(
            Bitlist::<512>::from_ssz_bytes([0xff; 65].as_slice()),
            Err(SszError::BitLengthExceedsLimit {
                bit_len: 519,
                limit: 512
            })
        );
        // Exactly one bit over the limit: delimiter at bit 513.
        let mut over = [0xffu8; 64].to_vec();
        over.push(0x02);
        assert_eq!(
            Bitlist::<512>::from_ssz_bytes(&over),
            Err(SszError::BitLengthExceedsLimit {
                bit_len: 513,
                limit: 512
            })
        );
    }

    #[test]
    fn bitvector_parsing_rejects_wrong_length_and_overflow_bits() {
        // Bitvector[64] = exactly 8 bytes.
        assert_eq!(
            Bitvector::<8>::from_ssz_bytes(&[0xff; 2], 64),
            Err(SszError::WrongByteLength {
                got: 2,
                expected: 8
            })
        );
        // Bit count inconsistent with the byte length: 56 or fewer bits fit
        // in 7 bytes, more than 64 needs a ninth.
        assert_eq!(
            Bitvector::<8>::from_ssz_bytes(&[0xff; 8], 56),
            Err(SszError::BitLengthMismatch { bits: 56, bytes: 8 })
        );
        assert_eq!(
            Bitvector::<8>::from_ssz_bytes(&[0xff; 8], 65),
            Err(SszError::BitLengthMismatch { bits: 65, bytes: 8 })
        );
        // Unaligned widths within the byte length are valid when the top
        // bits are clear (63 bits, last byte 0x7f).
        let mut bytes = [0xffu8; 8];
        bytes[7] = 0x7f;
        assert!(Bitvector::<8>::from_ssz_bytes(&bytes, 63).is_ok());
        // Bits above N set (bitvec_1 with bit 1 set).
        assert_eq!(
            Bitvector::<1>::from_ssz_bytes(&[0x02], 1),
            Err(SszError::BitsAboveLimit)
        );
        assert_eq!(
            Bitvector::<2>::from_ssz_bytes(&[0xff, 0x04], 9),
            Err(SszError::BitsAboveLimit)
        );
        // Full byte count, top bits within N: bit 8 is the highest valid
        // position of a 9-bit vector.
        assert!(Bitvector::<2>::from_ssz_bytes(&[0xff, 0x01], 9).is_ok());
    }

    #[test]
    fn bitlist_serialization_roundtrips() {
        // Byte-aligned bit lengths put the delimiter in its own byte.
        for (bytes, bit_len) in [
            (Vec::new(), 0usize),
            (vec![0xff], 8),
            (vec![0xab, 0xcd], 16),
            (vec![0x01, 0x02, 0x03], 24),
        ] {
            let bits = Bitlist::<2048>::from_ssz_bytes(&{
                let mut ser = bytes.clone();
                match bit_len % 8 {
                    0 => ser.push(1),
                    _ => unreachable!("byte-aligned cases only"),
                }
                ser
            })
            .expect("valid");
            assert_eq!(bits.bit_len(), bit_len);
            assert_eq!(bits.to_ssz_bytes(), {
                let mut ser = bytes.clone();
                ser.push(1);
                ser
            });
        }
        // Unaligned bit lengths set the delimiter inside the last byte
        // (0x07 carries bits 8..=10; the delimiter is bit 10).
        let bits = Bitlist::<2048>::from_ssz_bytes(&[0xff, 0x07]).expect("valid");
        assert_eq!(bits.bit_len(), 10);
        assert_eq!(bits.to_ssz_bytes(), vec![0xff, 0x07]);
        // Parsing our own serialization always reproduces the same value.
        let again = Bitlist::<2048>::from_ssz_bytes(&bits.to_ssz_bytes()).expect("valid");
        assert_eq!(again, bits);
    }

    #[test]
    fn bls_signature_root_spans_three_chunks() {
        // Vector[byte, 96]: 3 chunks merkleized to 4 leaves — cross-checked
        // against sigp's tree_hash in tests/ssz_differential.rs; here just
        // the tree shape.
        let sig = [0x5au8; 96];
        let chunks = pack(&sig);
        assert_eq!(chunks.len(), 3);
        let mut leaves = chunks.clone();
        leaves.resize(4, [0u8; 32]);
        let mut layer = leaves;
        while layer.len() > 1 {
            layer = layer
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| hash_pair(&p[0], &p[1]))
                .collect();
        }
        assert_eq!(sig.hash_tree_root(), layer[0]);
    }
}
