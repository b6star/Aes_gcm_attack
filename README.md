# AES-GCM Nonce Reuse Attack

같은 키와 nonce를 재사용한 **TLS 1.2 AES-GCM 레코드**를 분석하여, GHASH 인증 서브키 후보를 구하고 변조된 암호문의 인증 태그를 계산하는 SageMath 프로젝트입니다.

AES-GCM에서 nonce 재사용이 인증 무결성에 미치는 영향을 유한체 연산과 다항식의 근 계산으로 살펴봅니다.

## 주요 기능

- TLS 1.2 레코드에서 explicit nonce, 암호문, 인증 태그 추출
- 레코드 시퀀스 번호를 이용한 AAD 구성
- `GF(2^128)`에서 GHASH 계산 및 다항식 표현
- 두 레코드로부터 인증 서브키 `H`와 태그 마스크 `S` 후보 계산
- 세 레코드의 각 쌍에서 얻은 후보의 교집합 계산
- 알려진 평문 구간에 대응하는 암호문 변경 및 새 인증 태그 계산
- GHASH 테스트 벡터와 후보 교집합을 이용한 일관성 확인

## 공격 원리

128비트 인증 태그를 사용하는 GCM의 태그는 다음과 같이 표현할 수 있습니다.

```text
H = AES_K(0^128)
S = AES_K(J0)
T = S XOR GHASH_H(AAD, C)
```

`H`는 인증에 사용하는 서브키이며, `S`는 해당 키와 nonce로 결정되는 태그 마스크입니다. `J0`는 nonce에서 구성되는 초기 카운터 블록입니다.

같은 키와 nonce로 생성된 두 레코드에서는 `S`가 같으므로, 태그를 XOR하면 다음 관계를 얻습니다.

```text
T1 XOR T2 = GHASH_H(AAD1, C1) XOR GHASH_H(AAD2, C2)
```

GHASH를 미지수 `X`에 대한 다항식으로 표현하면 실제 `H`는 다음 다항식의 근입니다. 여기서 덧셈은 `GF(2^128)`의 덧셈, 즉 XOR입니다.

```text
P(X) = GHASH_poly(AAD1, C1)
     + GHASH_poly(AAD2, C2)
     + T1 + T2

P(H) = 0
```

각 `H` 후보에 대해 `S` 후보를 구하고, 추가 레코드로 후보를 좁힙니다. 올바른 `H`, `S`를 확보하면 같은 키와 nonce 조건에서 변경된 암호문에 대한 태그를 계산할 수 있습니다.

```text
S  = T1 XOR GHASH_H(AAD1, C1)
T' = S XOR GHASH_H(AAD', C')
```

이 과정에서 구하는 `H`는 AES 암호화 키 `K` 자체가 아닙니다.

## 실행 방법

[SageMath](https://www.sagemath.org/)가 설치되어 있고, 터미널에서 `sage` 명령을 사용할 수 있어야 합니다.

```bash
git clone https://github.com/b6star/Aes_gcm_attack.git
cd Aes_gcm_attack
sage gcm_attack.sage
```

`.sage` 파일은 SageMath 전용 문법과 유한체 연산을 사용하므로 일반적인 `python gcm_attack.sage` 명령으로 실행할 수 없습니다.

현재 스크립트는 파일 하단에 포함된 예제 데이터를 사용합니다. 별도의 명령행 인자나 패킷 캡처 파일 입력 기능은 없습니다.

## 예제 실행 흐름

1. 알려진 GHASH 벡터로 바이트와 유한체 원소 사이의 비트 매핑을 확인합니다.
2. 내장된 세 TLS 레코드와 각각의 시퀀스 번호 `1`, `2`, `3`을 읽습니다.
3. 세 번째 레코드의 암호문에서 오프셋 `32`의 1바이트를 변경합니다. 해당 위치의 기존 평문이 `0x01`이라고 가정하고, `0x05`에 대응하도록 XOR합니다.
4. 레코드 쌍 `(1, 2)`, `(2, 3)`, `(1, 3)`의 `(H, S)` 후보 교집합을 구합니다.
5. 선택한 후보로 변경된 암호문의 인증 태그를 계산합니다.
6. 변조 레코드를 포함한 후보 집합을 다시 계산하여 기존 교집합과 비교합니다.

검증 조건을 만족하면 다음 형태의 메시지를 출력합니다. 아래 값은 출력 형식을 설명하는 자리표시자입니다.

```text
H = <16바이트 hex>
S = <16바이트 hex>
forged auth tag verification success!!
tag = <16바이트 hex>
```

이 메시지는 스크립트 내부의 후보 집합 비교 결과입니다. 실제 AES-GCM 복호화 라이브러리나 TLS 서버가 변조 레코드를 수락했음을 확인하는 단계는 포함되어 있지 않습니다.

## 입력 데이터 구조

`GcmPacketInput(record_hex, seq_num)`은 **TLS 레코드 전체의 hex 문자열**과 해당 방향의 TLS 레코드 시퀀스 번호를 받습니다.

```text
TLS header       explicit nonce       ciphertext       authentication tag
  5 bytes      ||    8 bytes       ||  가변 길이     ||      16 bytes
```

현재 파서는 다음 조건을 검사합니다.

| 항목 | 조건 |
| --- | --- |
| Content Type | `0x17` — Application Data |
| Version | `0x0303` |
| Record Length | 헤더 이후 실제 fragment 길이와 일치 |
| Ciphertext | 최소 1바이트 |
| Authentication Tag | 16바이트 |

AAD는 내부에서 다음과 같이 구성합니다.

```text
seq_num(8 bytes) || content_type(1 byte) || version(2 bytes) || ciphertext_length(2 bytes)
```

이때 길이는 explicit nonce와 인증 태그를 제외한 암호문 길이입니다. `seq_num`은 TCP 시퀀스 번호가 아니며, TLS의 송신 방향별 레코드 시퀀스 번호를 입력해야 합니다.

다른 데이터를 분석하려면 파일 하단의 `packet1`, `packet2`, `packet3_hex`와 각 `seq_num`을 수정합니다. 평문 변경 예제를 바꿀 경우 `change_ciphertext()` 호출의 `offset`, `plaintext_length`, `m1_hex`, `m2_hex`도 함께 수정합니다. 기존 평문과 변경할 평문의 바이트 길이는 같아야 합니다.

## 구현에서 다룬 문제

GHASH는 다음 기약다항식으로 정의되는 유한체에서 계산합니다.

```text
x^128 + x^7 + x^2 + x + 1
```

SageMath의 다항식 표현을 GCM의 비트 표현과 맞추기 위해, 128비트 블록의 최상위 비트를 `x^0`, 최하위 비트를 `x^127`의 계수로 매핑합니다. 두 변환 함수 `block_to_field()`와 `field_to_block()`에 같은 규칙을 적용했습니다.

잘못된 비트 매핑에서는 패킷 쌍마다 서로 다른 후보가 나올 수 있어, 다음 GHASH 벡터를 확인하는 self-test를 포함했습니다.

```text
H          = 66e94bd4ef8a2c3b884cfa59ca342b2e
Ciphertext = 0388dace60b6a392f328c2b971b2fe78
AAD        = 빈 바이트열
GHASH      = f38cbb1ad69223dcc3457ae5b6b0f885
```

문제 원인과 수정 과정은 [gcm_attack_handoff.md](gcm_attack_handoff.md)에 정리되어 있습니다.

## 전제 및 현재 한계

- 분석 대상은 동일한 AES 키와 **전체 nonce**를 재사용해야 합니다. TLS 1.2에서 explicit nonce가 같다는 사실만으로는 충분하지 않으며, 고정 IV 부분도 같아야 합니다.
- 코드는 explicit nonce를 추출하지만 키와 전체 nonce의 동일성을 자동 검증하지 않습니다.
- 정확한 AAD, 암호문, 128비트 태그가 필요합니다. 현재 입력 래퍼는 TLS 1.2 형식에 맞춰져 있습니다.
- 두 레코드만으로 후보가 유일하게 결정되는 것은 아닙니다. 현재 코드는 교집합이 여러 개여도 하나를 선택하므로, 후보가 여러 개 남으면 추가 데이터로 확인해야 합니다.
- 원하는 평문 변경을 위해서는 해당 구간의 기존 평문과 위치를 알아야 합니다. 전체 평문을 자동 복구하는 기능은 없습니다.
- 새 태그는 `forgery_packet.tag_hex`에 저장되고 출력됩니다. `record_hex`의 마지막 태그 바이트를 교체해 완성된 레코드를 내보내는 기능은 없습니다.

## 파일 구성

```text
.
├── README.md                  # 프로젝트 소개 및 사용법
├── gcm_attack.sage            # GHASH, 후보 계산 및 인증 태그 변조 예제
└── gcm_attack_handoff_kor.md  # 비트 매핑 문제와 수정 기록 
```
