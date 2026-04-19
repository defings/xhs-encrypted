import base64
import string

STANDARD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
CUSTOM_B64 = "ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5"

# 构造映射表
ENCODE_TRANS = str.maketrans(STANDARD_B64, CUSTOM_B64)
DECODE_TRANS = str.maketrans(CUSTOM_B64, STANDARD_B64)


def custom_b64_encode(data: bytes) -> str:
    """
    自定义 Base64 编码
    """
    b64 = base64.b64encode(data).decode()
    return b64.translate(ENCODE_TRANS)


def custom_b64_decode(data: str) -> bytes:
    """
    自定义 Base64 解码
    """
    standard_b64 = data.translate(DECODE_TRANS)
    return base64.b64decode(standard_b64)


if __name__ == '__main__':
    input_str = input("请输入需要解码的字符串：")
    print(custom_b64_decode(input_str))