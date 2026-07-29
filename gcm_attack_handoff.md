# gcm_attack4.sage Handoff

## Context

`gcm_attack4.sage` recovers AES-GCM `H = AES_K(0^128)` candidates from two TLS 1.2 AES-GCM records that reuse the same nonce.

The current input API is:

```python
packet1 = GcmPacketInput(
    record_hex="17 03 03 ...",
    seq_num=1
)

packet2 = GcmPacketInput(
    record_hex="17 03 03 ...",
    seq_num=2
)

candidates = find_h_candidates(packet1, packet2)
```

`record_hex` is the full TLS 1.2 record bytes:

```text
TLS header(5 bytes) || explicit nonce(8 bytes) || ciphertext || auth tag(16 bytes)
```

The code builds TLS 1.2 AAD internally as:

```text
seq_num(8 bytes) || content_type(1 byte) || version(2 bytes) || ciphertext_len(2 bytes)
```

Default values:

```text
content_type = 0x17
version      = 0x0303
```

## Symptom

With three records using the same key and same nonce:

- `packet1 + packet2` produced candidates.
- `packet2 + packet3` produced a single candidate.
- `packet1 + packet3` produced a single candidate.
- The single candidates were different, and there was no common `H`.

If all three records really share the same AES key and nonce, and the AAD/ciphertext/tag inputs are correct, this should not happen. The real `H` must satisfy every pair.

## Root Cause

The bug was in the GF(2^128) byte-to-field mapping.

The old implementation mapped a 128-bit block like this:

```text
block MSB -> x^127
block LSB -> x^0
```

That looks natural, but it does not match GCM GHASH multiplication when using Sage's ordinary polynomial-basis GF multiplication with modulus:

```text
x^128 + x^7 + x^2 + x + 1
```

The important mismatch is directional:

- Sage represents field elements in a polynomial basis. Multiplication advances by polynomial degree: `x^i * x^j = x^(i+j)` before reduction.
- GCM defines GHASH multiplication at the wire-bit level with a right-shift algorithm. The reduction step checks the current LSB and xors a big-endian reduction constant.
- Therefore, the byte order that looks natural as a big-endian integer is not the same orientation Sage expects for polynomial-basis multiplication.

GCM's standard multiplication is usually described with right shifts and reduction constant:

```text
R = e1 || 0^120
```

This is not a different field; it is the same GF(2^128) field represented with the opposite bit orientation at the byte boundary. The same 128 bits must be translated before handing them to Sage's field arithmetic.

To make Sage's GF multiplication produce the same byte-level GHASH result, the mapping must be bit-reversed:

```text
block MSB -> x^0
block LSB -> x^127
```

Because the old mapping used a different representation, each two-packet equation could still produce plausible roots, but those roots were not the real GCM `H` in wire-byte form. That is why different packet pairs gave inconsistent candidates.

## Fix

Updated `block_to_field()` and `field_to_block()` in `gcm_attack4.sage`.

Old degree mapping:

```python
degree = 127 - byte_index * 8 - bit_index
```

New degree mapping:

```python
degree = byte_index * 8 + bit_index
```

This change was applied symmetrically in both conversion directions.

## Verification

Added `assert_gcm_mapping_self_test()` using a standard AES-GCM test vector:

```text
H          = 66e94bd4ef8a2c3b884cfa59ca342b2e
ciphertext = 0388dace60b6a392f328c2b971b2fe78
expected GHASH = f38cbb1ad69223dcc3457ae5b6b0f885
```

The script now calls this self-test before running the sample candidate recovery.

If the bit mapping is accidentally changed back, the script should fail early with:

```text
GHASH 비트 매핑 self-test 실패
```

## Input Notes

For TLS 1.2 AES-GCM records, `GcmPacketInput` now expects the full record starting at the TLS record header:

```text
17 03 03 ll ll || explicit nonce(8 bytes) || ciphertext || tag(16 bytes)
```

The parser validates:

- content type is `0x17`
- version is `0x0303`
- record header length equals the actual fragment length

Then it removes:

- TLS record header: first 5 bytes
- explicit nonce: first 8 bytes of the fragment
- auth tag: final 16 bytes

Only the remaining encrypted payload bytes are used as GHASH ciphertext. The explicit nonce is parsed and stored as `explicit_nonce_hex`, but it is not included in GHASH input.

The `seq_num` is the TLS record sequence number for that traffic direction. Client-to-server and server-to-client sequence numbers are separate.
