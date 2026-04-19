import base64
import binascii

BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
X3_BASE64_ALPHABET = "MfgqrsbcyzPQRStuvC7mn501HIJBo2DEFTKdeNOwxWXYZap89+/A4UVLhijkl63G"

# 确保两个字母表长度为 64 且为置换
assert len(BASE64_ALPHABET) == 64 and len(X3_BASE64_ALPHABET) == 64
assert set(BASE64_ALPHABET) == set(X3_BASE64_ALPHABET)

# 预生成翻译表
ENCODE_TRANS = str.maketrans(BASE64_ALPHABET, X3_BASE64_ALPHABET)
DECODE_TRANS = str.maketrans(X3_BASE64_ALPHABET, BASE64_ALPHABET)


def encode_base64_x3(input_bytes: bytes | bytearray) -> str:
    # 标准 base64 编码 -> 把标准字母表替换为 X3 字母表
    encoded = base64.b64encode(input_bytes).decode("utf-8")
    return encoded.translate(ENCODE_TRANS)


def decode_base64_x3(encoded_string: str) -> bytes:
    # 把 X3 字母表映射回标准 base64，再 decode
    standard_encoded = encoded_string.translate(DECODE_TRANS)
    try:
        return base64.b64decode(standard_encoded)
    except (binascii.Error, ValueError) as e:
        # 更友好的错误信息（不要直接 exit，抛出异常让调用者处理）
        raise ValueError(f"Base64 解码错误: {e}") from e


if __name__ == "__main__":
    data = bytes([196, 163, 162, 7, 172, 1, 78, 243, 81, 210, 5, 209])
    enc = encode_base64_x3(data)
    dec = decode_base64_x3(enc)
    print("encoded:", enc)
    print("decoded list:", list(dec))
    assert dec == data
