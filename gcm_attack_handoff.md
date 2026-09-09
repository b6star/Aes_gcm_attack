# gcm_attack4.sage 인수인계

## 배경

`gcm_attack4.sage`는 같은 nonce를 재사용한 TLS 1.2 AES-GCM 레코드 두 개로부터 `H = AES_K(0^128)` 후보를 복구하는 코드다.

현재 입력 API는 다음 형태다.

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

`record_hex`는 TLS 1.2 record 전체 바이트다.

```text
TLS header(5 bytes) || explicit nonce(8 bytes) || ciphertext || auth tag(16 bytes)
```

코드는 TLS 1.2 AAD를 내부에서 다음 구조로 만든다.

```text
seq_num(8 bytes) || content_type(1 byte) || version(2 bytes) || ciphertext_len(2 bytes)
```

기본값은 다음과 같다.

```text
content_type = 0x17
version      = 0x0303
```

## 증상

같은 key와 같은 nonce를 사용하는 세 레코드가 있을 때 다음 현상이 있었다.

- `packet1 + packet2`에서는 후보가 나왔다.
- `packet2 + packet3`에서는 후보가 1개 나왔다.
- `packet1 + packet3`에서도 후보가 1개 나왔다.
- 그런데 두 쌍에서 나온 단일 후보 값이 서로 달랐고, 세 레코드가 공통으로 만족하는 `H`가 없었다.

세 레코드가 정말 같은 AES key와 nonce를 공유하고, AAD/ciphertext/tag 입력도 맞다면 이런 일은 없어야 한다. 실제 `H`는 모든 패킷 쌍을 만족해야 한다.

## 원인

버그는 GF(2^128)에서 바이트 블록을 field 원소로 바꾸는 비트 매핑에 있었다.

기존 구현은 128비트 블록을 다음처럼 매핑했다.

```text
block MSB -> x^127
block LSB -> x^0
```

직관적으로는 자연스러워 보이지만, Sage의 일반적인 polynomial-basis GF 곱셈과 GCM GHASH 곱셈을 맞추려면 이 매핑이 맞지 않는다.

사용한 field modulus는 다음과 같다.

```text
x^128 + x^7 + x^2 + x + 1
```

핵심 차이는 방향성이다.

- Sage는 field 원소를 polynomial basis로 표현한다. 곱셈은 reduction 전까지 `x^i * x^j = x^(i+j)`처럼 차수가 증가하는 방향으로 진행된다.
- GCM은 GHASH 곱셈을 wire-bit 기준의 오른쪽 shift 알고리즘으로 정의한다. reduction 단계에서는 현재 LSB를 보고 big-endian reduction constant를 xor한다.
- 그래서 128비트 블록을 big-endian 정수처럼 보고 MSB를 최고차항에 넣는 방식은 Sage의 polynomial-basis 곱셈 방향과 GCM GHASH의 wire-bit 처리 방향을 그대로 맞추지 못한다.

GCM 표준 곱셈은 보통 오른쪽 shift와 다음 reduction constant로 설명된다.

```text
R = e1 || 0^120
```

즉 서로 다른 field를 쓰는 문제가 아니라, 같은 GF(2^128)을 byte boundary에서 반대 bit orientation으로 표현하는 문제다. 같은 128비트를 Sage field 연산에 넘기기 전에 GCM wire-bit 방향에 맞게 변환해야 한다.

Sage의 GF 곱셈 결과가 GCM의 byte-level GHASH 결과와 같아지려면 비트 매핑을 반대로 해야 한다.

```text
block MSB -> x^0
block LSB -> x^127
```

기존 매핑은 GCM과 다른 표현에서 곱셈하고 있었기 때문에, 두 패킷만 사용한 방정식에서는 그럴듯한 root가 나올 수 있었다. 하지만 그 root는 wire byte 기준의 실제 GCM `H`가 아니어서, 다른 패킷 쌍과 비교하면 후보가 서로 달라졌다.

## 해결 방법

`gcm_attack4.sage`의 `block_to_field()`와 `field_to_block()`을 수정했다.

기존 degree 매핑:

```python
degree = 127 - byte_index * 8 - bit_index
```

수정 후 degree 매핑:

```python
degree = byte_index * 8 + bit_index
```

양방향 변환이 서로 역함수가 되어야 하므로 `block_to_field()`와 `field_to_block()` 둘 다 같은 방식으로 수정했다.

## 검증

표준 AES-GCM 테스트 벡터를 사용해 `assert_gcm_mapping_self_test()`를 추가했다.

```text
H              = 66e94bd4ef8a2c3b884cfa59ca342b2e
ciphertext     = 0388dace60b6a392f328c2b971b2fe78
expected GHASH = f38cbb1ad69223dcc3457ae5b6b0f885
```

스크립트는 예제 후보 계산을 실행하기 전에 이 self-test를 먼저 호출한다.

비트 매핑이 다시 잘못 바뀌면 다음 메시지로 초기에 실패해야 한다.

```text
GHASH 비트 매핑 self-test 실패
```

## 입력 주의사항

TLS 1.2 AES-GCM 레코드에서 `GcmPacketInput`은 TLS record header부터 시작하는 전체 record를 입력으로 받는다.

```text
17 03 03 ll ll || explicit nonce(8 bytes) || ciphertext || tag(16 bytes)
```

파서는 다음을 검증한다.

- content type이 `0x17`인지
- version이 `0x0303`인지
- record header의 length 값이 실제 fragment 길이와 같은지

그 다음 다음 바이트들을 제거한다.

- TLS record header: 처음 5바이트
- explicit nonce: fragment의 처음 8바이트
- auth tag: 마지막 16바이트

남은 encrypted payload 바이트만 GHASH ciphertext로 사용한다. explicit nonce는 `explicit_nonce_hex`로 저장하지만 GHASH 입력에는 포함하지 않는다.

`seq_num`은 해당 방향의 TLS record sequence number다. client-to-server와 server-to-client의 sequence number는 서로 별개로 증가한다.
