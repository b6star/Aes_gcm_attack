# gcm_nonce_reuse_general.sage
#
# 교육용 AES-GCM nonce 재사용 공격 예제
#
# 다음 조건을 가정한다.
#
# - 두 패킷이 같은 AES 키를 사용한다.
# - 두 패킷이 같은 nonce를 재사용한다.
# - 따라서 H = AES_K(0^128)가 동일하다.
# - 따라서 S = AES_K(J0)도 동일하다.
# - AAD 내용과 길이는 서로 다를 수 있다.
# - ciphertext 내용과 길이는 서로 다를 수 있다.
# - 전체 128비트 인증 태그를 사용한다.
#
# 실제 AES 연산은 생략하고:
#
#   H_real = 임의의 GF(2^128) 원소
#   S      = 임의의 GF(2^128) 원소
#
# 로 시뮬레이션한다.
#
# 실제 공격 단계에서는 H_real과 S를 사용하지 않고,
#
#   AAD1, C1, T1
#   AAD2, C2, T2
#
# 만 사용하여 H 후보를 구한다.


# ============================================================
# 1. GF(2^128) 정의
# ============================================================

# GCM 환원 다항식:
#
#   x^128 + x^7 + x^2 + x + 1

PR.<z> = PolynomialRing(GF(2))

modulus = (
    z^128
    + z^7
    + z^2
    + z
    + 1
)

F.<a> = GF(
    2^128,
    modulus=modulus
)

# H를 미지수 X로 나타내기 위한 다항식 환
R.<X> = PolynomialRing(F)


# ============================================================
# 2. bytes ↔ GF(2^128) 변환
# ============================================================

def block_to_field(block):
    """
    16바이트 블록을 GF(2^128) 원소로 변환한다.

    GCM에서는 블록의 최상위 비트를 x^127의 계수로,
    최하위 비트를 x^0의 계수로 해석한다.
    """

    if len(block) != 16:
        raise ValueError(
            "block_to_field 입력은 정확히 16바이트여야 합니다."
        )

    value = F.zero()

    for byte_index, byte in enumerate(block):
        for bit_index in range(8):

            # 각 바이트의 MSB부터 확인
            mask = 1 << (7 - bit_index)

            if byte & mask:
                degree = (
                    127
                    - byte_index * 8
                    - bit_index
                )

                value += a^degree

    return value


def field_to_block(value):
    """
    GF(2^128) 원소를 16바이트 블록으로 변환한다.
    """

    output = bytearray(16)

    # GF 원소를 다항식 표현으로 변환
    polynomial_value = value.polynomial()

    for byte_index in range(16):
        for bit_index in range(8):

            degree = (
                127
                - byte_index * 8
                - bit_index
            )

            if polynomial_value[degree]:
                output[byte_index] |= (
                    1 << (7 - bit_index)
                )

    return bytes(output)


# ============================================================
# 3. GHASH 입력 처리 함수
# ============================================================

def pad_to_16(data):
    """
    GHASH 입력을 16바이트 배수가 되도록
    오른쪽에 zero padding한다.

    원래 길이가 16바이트 배수라면 그대로 반환한다.
    빈 데이터는 빈 데이터 그대로 반환한다.
    """

    remainder = len(data) % 16

    if remainder == 0:
        return data

    padding_length = 16 - remainder

    return data + bytes(padding_length)


def split_blocks(data):
    """
    데이터를 16바이트 단위로 나눈다.

    빈 데이터라면 빈 리스트를 반환한다.
    """

    return [
        data[index:index + 16]
        for index in range(0, len(data), 16)
    ]


def make_length_block(aad, ciphertext):
    """
    GCM의 마지막 Length Block을 생성한다.

    구조:

        64비트 AAD 원래 길이(bit)
        ||
        64비트 ciphertext 원래 길이(bit)

    주의:
    padding 이후 길이가 아니라 원래 데이터의 길이를 기록한다.
    """

    aad_bit_length = len(aad) * 8
    ciphertext_bit_length = len(ciphertext) * 8

    return (
        aad_bit_length.to_bytes(8, "big")
        + ciphertext_bit_length.to_bytes(8, "big")
    )


def ghash_input_blocks(aad, ciphertext):
    """
    GHASH에 실제로 들어가는 모든 블록을
    GF(2^128) 원소 리스트로 반환한다.

    순서:

        padded AAD blocks
        padded ciphertext blocks
        length block
    """

    field_blocks = []

    # --------------------------------------------------------
    # AAD 블록
    # --------------------------------------------------------

    padded_aad = pad_to_16(aad)

    for block in split_blocks(padded_aad):
        field_blocks.append(
            block_to_field(block)
        )

    # --------------------------------------------------------
    # Ciphertext 블록
    # --------------------------------------------------------

    padded_ciphertext = pad_to_16(ciphertext)

    for block in split_blocks(padded_ciphertext):
        field_blocks.append(
            block_to_field(block)
        )

    # --------------------------------------------------------
    # Length Block
    # --------------------------------------------------------

    length_block = make_length_block(
        aad,
        ciphertext
    )

    field_blocks.append(
        block_to_field(length_block)
    )

    return field_blocks


# ============================================================
# 4. 일반적인 GHASH 계산
# ============================================================

def ghash(aad, ciphertext, H):
    """
    임의 길이 AAD와 ciphertext에 대한 GHASH를 계산한다.

    Y0 = 0
    Yi = (Yi-1 + Xi) * H

    GF(2^128)에서 +는 XOR이다.
    """

    Y = F.zero()

    blocks = ghash_input_blocks(
        aad,
        ciphertext
    )

    for X_i in blocks:
        Y = (Y + X_i) * H

    return Y


# ============================================================
# 5. GHASH를 H에 대한 다항식으로 표현
# ============================================================

def ghash_polynomial(aad, ciphertext):
    """
    GHASH를 미지수 X에 대한 다항식으로 만든다.

    GHASH 입력 블록이

        B1, B2, ..., Bn

    이라면:

        GHASH_H
        =
        B1*H^n
        + B2*H^(n-1)
        + ...
        + Bn*H

    따라서 H 대신 X를 넣은 다항식은:

        B1*X^n
        + B2*X^(n-1)
        + ...
        + Bn*X
    """

    blocks = ghash_input_blocks(
        aad,
        ciphertext
    )

    block_count = len(blocks)

    polynomial = R.zero()

    for index, block in enumerate(blocks):

        exponent = block_count - index

        polynomial += (
            R(block) * X^exponent
        )

    return polynomial


# ============================================================
# 6. 두 패킷으로 공격 다항식 만들기
# ============================================================

def build_attack_polynomial(
    aad1,
    ciphertext1,
    tag1,
    aad2,
    ciphertext2,
    tag2
):
    """
    동일 nonce가 재사용된 두 패킷으로부터
    H가 만족해야 하는 다항식을 만든다.

    태그:

        T1 = S + GHASH_H(A1, C1)
        T2 = S + GHASH_H(A2, C2)

    XOR하면:

        T1 + T2
        =
        GHASH_H(A1, C1)
        +
        GHASH_H(A2, C2)

    따라서:

        GHASH_poly1(X)
        +
        GHASH_poly2(X)
        +
        T1
        +
        T2
        =
        0

    실제 H는 이 다항식의 근이다.
    """

    polynomial1 = ghash_polynomial(
        aad1,
        ciphertext1
    )

    polynomial2 = ghash_polynomial(
        aad2,
        ciphertext2
    )

    tag_difference = tag1 + tag2

    attack_polynomial = (
        polynomial1
        + polynomial2
        + R(tag_difference)
    )

    return attack_polynomial


# ============================================================
# 7. 출력용 함수
# ============================================================

def print_packet_info(
    name,
    aad,
    ciphertext,
    tag
):
    """
    패킷 정보를 보기 좋게 출력한다.
    """

    aad_blocks = (
        len(pad_to_16(aad)) // 16
        if len(aad) > 0
        else 0
    )

    ciphertext_blocks = (
        len(pad_to_16(ciphertext)) // 16
        if len(ciphertext) > 0
        else 0
    )

    total_ghash_blocks = (
        aad_blocks
        + ciphertext_blocks
        + 1
    )

    print(f"\n[{name}]")

    print(
        f"AAD 길이:"
        f" {len(aad)}바이트"
        f" ({len(aad) * 8}비트)"
    )

    print(
        f"AAD GHASH 블록 수:"
        f" {aad_blocks}"
    )

    print(
        f"Ciphertext 길이:"
        f" {len(ciphertext)}바이트"
        f" ({len(ciphertext) * 8}비트)"
    )

    print(
        f"Ciphertext GHASH 블록 수:"
        f" {ciphertext_blocks}"
    )

    print(
        f"전체 GHASH 블록 수"
        f" (Length Block 포함):"
        f" {total_ghash_blocks}"
    )

    print(f"AAD(hex): {aad.hex()}")
    print(f"Ciphertext(hex): {ciphertext.hex()}")
    print(f"Tag(hex): {field_to_block(tag).hex()}")

    length_block = make_length_block(
        aad,
        ciphertext
    )

    print(
        f"Length Block(hex):"
        f" {length_block.hex()}"
    )


# ============================================================
# 8. 임의 길이 테스트 데이터 생성
# ============================================================

import os
import random


# 테스트할 최대 길이
MAX_AAD_LENGTH = 64
MAX_CIPHERTEXT_LENGTH = 80


def random_bytes(length):
    return os.urandom(length)


# AAD 길이를 각각 독립적으로 선택
aad1_length = random.randint(
    0,
    MAX_AAD_LENGTH
)

aad2_length = random.randint(
    0,
    MAX_AAD_LENGTH
)

# Ciphertext는 최소 1바이트 이상으로 설정
ciphertext1_length = random.randint(
    1,
    MAX_CIPHERTEXT_LENGTH
)

ciphertext2_length = random.randint(
    1,
    MAX_CIPHERTEXT_LENGTH
)


AAD1_bytes = random_bytes(
    aad1_length
)

AAD2_bytes = random_bytes(
    aad2_length
)

C1_bytes = random_bytes(
    ciphertext1_length
)

C2_bytes = random_bytes(
    ciphertext2_length
)


# 두 패킷이 완전히 같아지는 극히 드문 경우 방지
while (
    AAD1_bytes == AAD2_bytes
    and C1_bytes == C2_bytes
):
    C2_bytes = random_bytes(
        ciphertext2_length
    )


# ============================================================
# 9. 피해자 측 시뮬레이션
# ============================================================
#
# 실제 GCM:
#
#   H = AES_K(0^128)
#   S = AES_K(J0)
#
# 같은 키와 같은 nonce를 사용하면
# 두 패킷의 H와 S가 모두 동일하다.
#
# 여기서는 AES를 구현하지 않고 임의 원소로 대체한다.

H_real = F.random_element()
S = F.random_element()


# 태그 생성:
#
#   T = S + GHASH_H(AAD, ciphertext)

T1 = (
    S
    + ghash(
        AAD1_bytes,
        C1_bytes,
        H_real
    )
)

T2 = (
    S
    + ghash(
        AAD2_bytes,
        C2_bytes,
        H_real
    )
)


# ============================================================
# 10. 공격자 측 계산
# ============================================================
#
# 공격자가 알고 있는 값:
#
#   AAD1, C1, T1
#   AAD2, C2, T2
#
# 공격자가 모르는 값:
#
#   AES 키 K
#   H_real
#   S

attack_polynomial = build_attack_polynomial(
    AAD1_bytes,
    C1_bytes,
    T1,
    AAD2_bytes,
    C2_bytes,
    T2
)


# 다항식이 0이 되는 특수한 경우 검사
#
# 두 패킷의 GHASH 입력과 태그가 완전히 같으면
# 0 다항식이 만들어지므로 H를 특정할 수 없다.

if attack_polynomial == 0:
    raise RuntimeError(
        "공격 다항식이 0입니다. "
        "서로 다른 테스트 데이터를 사용해 다시 실행하세요."
    )


# ============================================================
# 11. 다항식 근 계산
# ============================================================

print("=" * 70)
print("AES-GCM nonce 재사용 일반형 공격")
print("=" * 70)

print_packet_info(
    "패킷 1",
    AAD1_bytes,
    C1_bytes,
    T1
)

print_packet_info(
    "패킷 2",
    AAD2_bytes,
    C2_bytes,
    T2
)


print("\n" + "=" * 70)
print("공격 다항식")
print("=" * 70)

print(
    f"다항식 차수:"
    f" {attack_polynomial.degree()}"
)

print("\nP(X) =")
print(attack_polynomial)


# 실제 H를 넣었을 때 0이 되는지 먼저 검증
verification_value = attack_polynomial(
    H_real
)

print("\nP(H_real) =")
print(verification_value)

print(
    "\n실제 H가 다항식을 만족하는가?:",
    verification_value == 0
)


print("\n" + "=" * 70)
print("다항식의 근 계산")
print("=" * 70)

roots = attack_polynomial.roots(
    multiplicities=False
)


print(
    f"\n찾은 H 후보 개수:"
    f" {len(roots)}"
)

for index, candidate in enumerate(
    roots,
    start=1
):
    print(
        f"후보 {index}:"
        f" {field_to_block(candidate).hex()}"
    )


print("\n실제 H:")
print(
    field_to_block(H_real).hex()
)

print(
    "\n실제 H가 후보에 포함되는가?:",
    H_real in roots
)


# ============================================================
# 12. 복구한 H 후보로 S 후보 계산
# ============================================================
#
# H 후보가 주어지면 패킷 1에서:
#
#   T1 = S + GHASH_H(AAD1, C1)
#
# 따라서:
#
#   S = T1 + GHASH_H(AAD1, C1)
#
# 각 H 후보마다 S 후보를 계산할 수 있다.

print("\n" + "=" * 70)
print("H 후보별 S 후보")
print("=" * 70)

for index, candidate_H in enumerate(
    roots,
    start=1
):
    candidate_S = (
        T1
        + ghash(
            AAD1_bytes,
            C1_bytes,
            candidate_H
        )
    )

    print(
        f"\n후보 {index}"
    )

    print(
        "H =",
        field_to_block(candidate_H).hex()
    )

    print(
        "S =",
        field_to_block(candidate_S).hex()
    )

    # 패킷 2의 태그도 같은 S 후보로 설명되는지 확인
    predicted_T2 = (
        candidate_S
        + ghash(
            AAD2_bytes,
            C2_bytes,
            candidate_H
        )
    )

    print(
        "패킷 2 태그와 일치하는가?:",
        predicted_T2 == T2
    )


print("\n실제 S:")
print(
    field_to_block(S).hex()
)