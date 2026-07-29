from operator import xor

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

    Sage의 GF 곱셈을 GCM GHASH 곱셈과 맞추기 위해
    블록의 최상위 비트를 x^0의 계수로,
    최하위 비트를 x^127의 계수로 해석한다.
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
                    byte_index * 8
                    + bit_index
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
                byte_index * 8
                + bit_index
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


def assert_gcm_mapping_self_test():
    """
    NIST SP 800-38D 예제 벡터로 GHASH 비트 매핑을 확인한다.
    """

    H = block_to_field(
        bytes.fromhex("66e94bd4ef8a2c3b884cfa59ca342b2e")
    )

    ciphertext = bytes.fromhex(
        "0388dace60b6a392f328c2b971b2fe78"
    )

    expected_ghash = bytes.fromhex(
        "f38cbb1ad69223dcc3457ae5b6b0f885"
    )

    actual_ghash = field_to_block(
        ghash(
            b"",
            ciphertext,
            H
        )
    )

    if actual_ghash != expected_ghash:
        raise RuntimeError(
            "GHASH 비트 매핑 self-test 실패: "
            f"expected={expected_ghash.hex()}, "
            f"actual={actual_ghash.hex()}"
        )


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
        + 1  # length block
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
    print(f"Tag(hex): {tag.hex()}")

    length_block = make_length_block(
        aad,
        ciphertext
    )

    print(
        f"Length Block(hex):"
        f" {length_block.hex()}"
    )


# ============================================================
# 8. TLS 1.2 입력 헬퍼
# ============================================================

TLS12_GCM_CONTENT_TYPE = 0x17
TLS12_VERSION = bytes.fromhex("03 03")
TLS12_RECORD_HEADER_LENGTH = 5
TLS12_GCM_EXPLICIT_NONCE_LENGTH = 8
GCM_AUTH_TAG_LENGTH = 16


class GcmPacketInput:
    """
    TLS record 전체에서 H 후보 계산에 필요한 값을 추출한다.

    record_hex 형식:
        17 03 03 ll ll || explicit nonce(8 bytes) || ciphertext || tag(16 bytes)
    """

    def __init__(
        self,
        record_hex,
        seq_num
    ):
        record = hex_to_bytes(record_hex)

        min_record_length = (
            TLS12_RECORD_HEADER_LENGTH
            + TLS12_GCM_EXPLICIT_NONCE_LENGTH
            + GCM_AUTH_TAG_LENGTH
        )

        if len(record) <= min_record_length:
            raise ValueError(
                "record_hex는 TLS header, explicit nonce, ciphertext, "
                "16바이트 tag를 모두 포함해야 합니다."
            )

        content_type = record[0]
        version = record[1:3]
        record_length = int.from_bytes(
            record[3:5],
            "big"
        )
        fragment = record[TLS12_RECORD_HEADER_LENGTH:]

        if content_type != TLS12_GCM_CONTENT_TYPE:
            raise ValueError(
                f"TLS content type이 0x17이 아닙니다: 0x{content_type:02x}"
            )

        if version != TLS12_VERSION:
            raise ValueError(
                f"TLS version이 0303이 아닙니다: {version.hex()}"
            )

        if record_length != len(fragment):
            raise ValueError(
                "TLS record length와 실제 fragment 길이가 다릅니다: "
                f"record length={record_length}, "
                f"actual fragment length={len(fragment)}"
            )

        ciphertext_start = TLS12_GCM_EXPLICIT_NONCE_LENGTH
        ciphertext_end = len(fragment) - GCM_AUTH_TAG_LENGTH

        if ciphertext_end <= ciphertext_start:
            raise ValueError(
                "fragment에서 explicit nonce와 tag를 제외하면 "
                "ciphertext가 남지 않습니다."
            )

        explicit_nonce = fragment[:TLS12_GCM_EXPLICIT_NONCE_LENGTH]
        ciphertext = fragment[ciphertext_start:ciphertext_end]
        tag = fragment[ciphertext_end:]

        self.record_hex = record.hex()
        self.explicit_nonce_hex = explicit_nonce.hex()
        self.ciphertext_hex = ciphertext.hex()
        self.tag_hex = tag.hex()
        self.seq_num = int(seq_num)


def hex_to_bytes(hex_string):
    """
    공백, 줄바꿈, 0x 접두사가 섞인 hex 문자열을 bytes로 바꾼다.
    """

    normalized = (
        hex_string
        .replace("0x", "")
        .replace("0X", "")
        .replace(" ", "")
        .replace("\n", "")
        .replace("\r", "")
        .replace("\t", "")
        .replace(":", "")
    )

    if len(normalized) % 2 != 0:
        raise ValueError("hex 문자열 길이는 짝수여야 합니다.")

    return bytes.fromhex(normalized)


def make_tls12_aad(
    seq_num,
    ciphertext,
    content_type=TLS12_GCM_CONTENT_TYPE,
    version=TLS12_VERSION
):
    """
    TLS 1.2 AES-GCM AAD를 만든다.

        seq_num(8바이트)
        || content_type(1바이트)
        || version(2바이트)
        || ciphertext 길이(2바이트)
    """

    seq_num = int(seq_num)
    content_type = int(content_type)

    if isinstance(version, str):
        version = hex_to_bytes(version)

    if not (0 <= seq_num < 2^64):
        raise ValueError("seq_num은 0 이상 2^64 미만이어야 합니다.")

    if not (0 <= content_type < 256):
        raise ValueError("content_type은 1바이트 정수여야 합니다.")

    if len(version) != 2:
        raise ValueError("version은 정확히 2바이트여야 합니다.")

    if len(ciphertext) >= 2^16:
        raise ValueError("ciphertext 길이가 TLS length 필드 범위를 넘습니다.")

    return (
        seq_num.to_bytes(8, "big")
        + bytes([content_type])
        + version
        + len(ciphertext).to_bytes(2, "big")
    )


def make_tls12_packet(
    packet_input,
    content_type=TLS12_GCM_CONTENT_TYPE,
    version=TLS12_VERSION
):
    """
    GcmPacketInput으로부터 공격 입력 패킷을 만든다.
    """

    ciphertext = hex_to_bytes(packet_input.ciphertext_hex)
    tag = hex_to_bytes(packet_input.tag_hex)

    if len(tag) != 16:
        raise ValueError("auth tag는 16바이트(32 hex chars)여야 합니다.")

    aad = make_tls12_aad(
        packet_input.seq_num,
        ciphertext,
        content_type=content_type,
        version=version
    )

    return {
        "aad": aad,
        "ciphertext": ciphertext,
        "tag": tag,
        "seq_num": packet_input.seq_num,
    }


def change_ciphertext(
    data,
    offset,
    plaintext_length,
    m1_hex,
    m2_hex
):
    """
    CTR 계열 암호의 malleability를 이용해 ciphertext 일부를 수정한다.

    offset은 ciphertext 시작 기준 byte offset이다.
    m1_hex는 기존 평문, m2_hex는 바꾸고 싶은 평문이다.
    """

    mutable_data = bytearray(data)
    m1 = hex_to_bytes(m1_hex)
    m2 = hex_to_bytes(m2_hex)

    if plaintext_length != len(m1) or plaintext_length != len(m2):
        raise ValueError(
            "plaintext_length는 m1_hex, m2_hex의 byte 길이와 같아야 합니다."
        )

    ciphertext_offset = (
        TLS12_RECORD_HEADER_LENGTH
        + TLS12_GCM_EXPLICIT_NONCE_LENGTH
    )
    start = ciphertext_offset + int(offset)
    end = start + int(plaintext_length)

    if start < ciphertext_offset or end > len(mutable_data) - GCM_AUTH_TAG_LENGTH:
        raise ValueError("변경 범위가 ciphertext 영역을 벗어났습니다.")

    for index in range(plaintext_length):
        mutable_data[start + index] = xor(
            xor(
                mutable_data[start + index],
                m1[index]
            ),
            m2[index]
        )

    return mutable_data.hex(" ")


def find_h_candidates(
    packet_input1,
    packet_input2,
    content_type=TLS12_GCM_CONTENT_TYPE,
    version=TLS12_VERSION,
    verbose=True,
    print_polynomial=True
):
    """
    두 TLS 1.2 AES-GCM 패킷 입력값으로 H 후보를 구한다.

    반환값:
        [
            {
                "H": GF(2^128) 원소,
                "H_hex": 16바이트 hex 문자열,
                "S": GF(2^128) 원소,
                "S_hex": 16바이트 hex 문자열,
            },
            ...
        ]
    """

    packet1 = make_tls12_packet(
        packet_input1,
        content_type=content_type,
        version=version
    )

    packet2 = make_tls12_packet(
        packet_input2,
        content_type=content_type,
        version=version
    )

    attack_polynomial = build_attack_polynomial(
        packet1["aad"],
        packet1["ciphertext"],
        block_to_field(packet1["tag"]),
        packet2["aad"],
        packet2["ciphertext"],
        block_to_field(packet2["tag"])
    )

    if attack_polynomial == 0:
        raise RuntimeError(
            "공격 다항식이 0입니다. "
            "서로 다른 테스트 데이터를 사용해 다시 실행하세요."
        )

    if verbose:
        print("=" * 70)
        print("AES-GCM nonce 재사용 일반형 공격")
        print("=" * 70)

        print_packet_info(
            "패킷 1",
            packet1["aad"],
            packet1["ciphertext"],
            packet1["tag"]
        )

        print_packet_info(
            "패킷 2",
            packet2["aad"],
            packet2["ciphertext"],
            packet2["tag"]
        )

        print("\n" + "=" * 70)
        print("공격 다항식")
        print("=" * 70)

        print(
            f"다항식 차수:"
            f" {attack_polynomial.degree()}"
        )

        if print_polynomial:
            print("\nP(X) =")
            print(attack_polynomial)

        print("\n" + "=" * 70)
        print("다항식의 근 계산")
        print("=" * 70)

    roots = attack_polynomial.roots(
        multiplicities=False
    )

    if verbose:
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

        print("\n" + "=" * 70)
        print("H 후보별 S 후보")
        print("=" * 70)

    candidates = []

    for index, candidate_H in enumerate(
        roots,
        start=1
    ):
        candidate_S = (
            block_to_field(packet1["tag"])
            + ghash(
                packet1["aad"],
                packet1["ciphertext"],
                candidate_H
            )
        )

        predicted_T2 = (
            candidate_S
            + ghash(
                packet2["aad"],
                packet2["ciphertext"],
                candidate_H
            )
        )

        if verbose:
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

            print(
                "패킷 2 태그와 일치하는가?:",
                predicted_T2 == block_to_field(packet2["tag"])
            )

        candidates.append({
            "H": candidate_H,
            "H_hex": field_to_block(candidate_H).hex(),
            "S": candidate_S,
            "S_hex": field_to_block(candidate_S).hex(),
        })

    return candidates


# ============================================================
# 9. 사용 예시
# ============================================================

assert_gcm_mapping_self_test()

packet1 = GcmPacketInput(
    record_hex="""
        17 03 03 00 3a 
        9c 26 9a 9f 29 81 0a b0 
        a9 91 41 d1 d8 4c 3d f5
        b3 c6 e3 28 f8 79 f6 4b
        2b cd 65 61 fe 7f e1 9a
        73 ed ad 45 cd 0f b9 68
        f4 f0 
        03 5d d4 f7 20 2b 87 c6 
        6b 7a 2f 24 42 f6 d5 3f
    """,
    seq_num=1
)

packet2 = GcmPacketInput(
    record_hex="""
        17 03 03 00 4a
        9c 26 9a 9f 29 81 0a b0
        a9 91 41 d1 d8 4c 3d f4
        af cd f6 77 d2 63 f3 1a
        7a 8f 2c 70 ad 62 f6 9a
        72 ea a9 43 dd 56 e4 2c
        f9 f1 e4 36 ba 7d 1e b5 
        ee 2e fe 9b 65 52 2e dc 
        68 60 
        99 93 5e bb 98 28 4a f7 
        5a 62 53 d1 b5 c1 0e c1
    """,
    seq_num=2
)

packet3_hex = """
    17 03 03 00 48
    9c 26 9a 9f 29 81 0a b0
    a9 91 41 d1 d8 4c 3d f6
    bf dc db 7d ec 7c f3 04
    62 db 20 3f bc 36 a2 97
    72 ed bf 15 96 43 b4 68
    f5 f1 e5 20 e7 34 1d ae
    e8 67 a4 96 65 54 2c d9
    b0 d6 e0 ac 2b e2 05 62
    1f 7e a4 a0 34 51 9f 95
"""

forged_packet_hex = change_ciphertext(
    data=hex_to_bytes(packet3_hex),
    offset=32,
    plaintext_length=1,
    m1_hex="01",
    m2_hex="05"
)

packet3 = GcmPacketInput(
    record_hex=packet3_hex,
    seq_num=3
)

forgery_packet = GcmPacketInput(
    record_hex=forged_packet_hex,
    seq_num=3
)

candidates12 = find_h_candidates(packet1, packet2, verbose=False)
candidates23 = find_h_candidates(packet2, packet3, verbose=False)
candidates13 = find_h_candidates(packet1, packet3, verbose=False)

s12 = set((c["H_hex"], c["S_hex"]) for c in candidates12)
s23 = set((c["H_hex"], c["S_hex"]) for c in candidates23)
s13 = set((c["H_hex"], c["S_hex"]) for c in candidates13)

common = s12 & s23 & s13

if len(common) == 0:
    raise RuntimeError("세 패킷이 공통으로 만족하는 (H, S) 후보가 없습니다.")

for h_hex, s_hex in common:
    print("H =", h_hex)
    print("S =", s_hex)

selected_h_hex, selected_s_hex = next(iter(common))


def forge_tag(
    forgery_packet,
    H,
    S,
    content_type=TLS12_GCM_CONTENT_TYPE,
    version=TLS12_VERSION
):
    packet = make_tls12_packet(
        packet_input=forgery_packet,
        content_type=content_type,
        version=version
    )
    ciphertext = packet["ciphertext"]
    aad = packet["aad"]
    forged_ghash = ghash(
        ciphertext=ciphertext,
        aad=aad,
        H=H
    )

    return S + forged_ghash


forged_tag = forge_tag(
    forgery_packet,
    block_to_field(bytes.fromhex(selected_h_hex)),
    block_to_field(bytes.fromhex(selected_s_hex))
)
forged_tag_hex = field_to_block(forged_tag).hex()
forgery_packet.tag_hex = forged_tag_hex

candidate1f = find_h_candidates(packet1, forgery_packet, verbose=False)
candidate2f = find_h_candidates(packet2, forgery_packet, verbose=False)

s1f = set((c["H_hex"], c["S_hex"]) for c in candidate1f)
s2f = set((c["H_hex"], c["S_hex"]) for c in candidate2f)

common_for_verification = s1f & s2f & s12

if (common == common_for_verification):
    print(f"forged auth tag verification success!!")
    print(f"tag = {forged_tag_hex}")
else:
    print(f"forged auth tag verification failed...")

