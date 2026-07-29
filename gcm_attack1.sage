# gcm_nonce_reuse.sage
#
# 교육용 예제:
# 같은 AES-GCM nonce를 사용한 두 개의 1블록 암호문으로부터
# 인증 서브키 H의 후보를 구한다.
#
# 단순화를 위해:
# - AAD 없음
# - 평문/암호문 길이 각각 정확히 16바이트
# - 태그는 16바이트 전체 사용

# ------------------------------------------------------------
# 1. GCM에서 사용하는 GF(2^128) 정의
# ------------------------------------------------------------

# GCM 환원 다항식:
# x^128 + x^7 + x^2 + x + 1
PR.<z> = PolynomialRing(GF(2))
modulus = z^128 + z^7 + z^2 + z + 1

F.<a> = GF(2^128, modulus=modulus)
R.<X> = PolynomialRing(F)


# ------------------------------------------------------------
# 2. 16바이트와 GF(2^128) 원소 사이의 변환
# ------------------------------------------------------------
#
# 주의:
# GCM은 블록의 최상위 비트를 x^127 계수로 해석한다.
# Sage의 일반적인 정수 변환과 비트 순서가 다를 수 있으므로
# 비트를 명시적으로 배치한다.

def block_to_field(block):
    if len(block) != 16:
        raise ValueError("블록은 정확히 16바이트여야 합니다.")

    value = F.zero()

    for byte_index, byte in enumerate(block):
        for bit_index in range(8):
            # 현재 바이트의 MSB부터 읽는다.
            if byte & (1 << (7 - bit_index)):
                degree = 127 - (byte_index * 8 + bit_index)
                value += a^degree

    return value


def field_to_block(value):
    output = bytearray(16)

    for byte_index in range(16):
        for bit_index in range(8):
            degree = 127 - (byte_index * 8 + bit_index)

            if value[degree]:
                output[byte_index] |= 1 << (7 - bit_index)

    return bytes(output)


# ------------------------------------------------------------
# 3. 1블록 메시지용 GHASH
# ------------------------------------------------------------
#
# AAD가 없고 ciphertext가 16바이트라면 GHASH 입력은:
#
#   C || len(A)||len(C)
#
# 길이 블록은:
#   64비트 AAD 길이(0) || 64비트 ciphertext 길이(128)
#
# 따라서:
#
#   GHASH_H(C) = C·H² + L·H

length_block = (
    (0).to_bytes(8, "big")
    + (128).to_bytes(8, "big")
)

L = block_to_field(length_block)


def ghash_one_block(ciphertext, H):
    C = block_to_field(ciphertext)
    return C * H^2 + L * H


# ------------------------------------------------------------
# 4. 예제 값 생성
# ------------------------------------------------------------
#
# 여기서는 AES 구현 없이, 임의의 H와 nonce 마스킹 S를 만든다.
#
# 실제 GCM에서는:
#   H = AES_K(0^128)
#   S = AES_K(J0)
#
# 인증 태그:
#   T = S + GHASH_H(C)
#
# GF(2^128)에서는 덧셈이 XOR이다.

H_real = F.random_element()
S = F.random_element()

C1_bytes = bytes.fromhex(
    "00112233445566778899aabbccddeeff"
)

C2_bytes = bytes.fromhex(
    "ffeeddccbbaa99887766554433221100"
)

T1 = S + ghash_one_block(C1_bytes, H_real)
T2 = S + ghash_one_block(C2_bytes, H_real)


# ------------------------------------------------------------
# 5. 같은 nonce 사용 시 태그 XOR
# ------------------------------------------------------------
#
# T1 + T2
# = (S + GHASH(C1)) + (S + GHASH(C2))
# = GHASH(C1) + GHASH(C2)
#
# 두 메시지의 길이가 같으므로 길이 항 L·H도 소거된다.
#
# 따라서:
#
#   T1 + T2 = (C1 + C2)·H²
#
# 이 식을 다항식으로 만들면:
#
#   (C1 + C2)X² + (T1 + T2) = 0

C1 = block_to_field(C1_bytes)
C2 = block_to_field(C2_bytes)

tag_difference = T1 + T2

polynomial = (C1 + C2) * X^2 + tag_difference


# ------------------------------------------------------------
# 6. 다항식의 근 구하기
# ------------------------------------------------------------

roots = polynomial.roots(multiplicities=False)

print("실제 H:")
print(field_to_block(H_real).hex())

print("\n생성된 다항식:")
print(polynomial)

print("\n찾은 H 후보 개수:")
print(len(roots))

for index, candidate in enumerate(roots, start=1):
    print(f"후보 {index}: {field_to_block(candidate).hex()}")

print("\n실제 H가 후보에 포함되는가?")
print(H_real in roots)