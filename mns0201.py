import struct

from common.generate_bit_arr import reverse_xs_bit_arr
from common.xs_xxtea import xxtea_encrypt, xxtea_decrypt
from common.base64_x3 import encode_base64_x3, decode_base64_x3


def mns0201_encrypt(arr: list[int]) -> str:
    """
    mns0201加密
    :param arr:
    :return:
    """
    e = len(arr)
    a = e >> 2
    if (3 & e) != 0:
        a += 1
    r = list(struct.unpack('<' + 'I' * a, bytes(arr + [0] * ((4 * a) - e))))
    r.append(e)

    enc = xxtea_encrypt(r)
    # to bytes
    data_bytes = struct.pack('<' + 'I' * len(enc), *enc)  # 返回 bytes（小端）
    # 如果需要 bytearray：
    data_bytes = bytearray(data_bytes)
    return "mns0201_" + encode_base64_x3(data_bytes)


def mns0201_decrypt(s: str) -> list[int]:
    """
    mns0201解密
    :param s:
    :return:
    """
    prefix = "mns0201_"
    if not isinstance(s, str) or not s.startswith(prefix):
        raise ValueError("输入必须是以 'mns0201_' 为前缀的字符串")
    b64part = s[len(prefix):]
    data_bytes = decode_base64_x3(b64part)
    enc = list(struct.unpack('<' + 'I' * (len(data_bytes) // 4), data_bytes))
    r = xxtea_decrypt(enc)

    e = r[-1]  # 原始字节长度
    u32s = r[:-1]  # 实际数据的 uint32 列表
    # uint32 → bytes（小端）
    data_bytes = struct.pack('<' + 'I' * len(u32s), *u32s)
    return list(data_bytes[:e])


if __name__ == '__main__':
    x3 = input("请输入x3:")
    x3_arr = mns0201_decrypt(x3)
    print(f"原始数组：{x3_arr}")
    print("=======================解析原始数组=============================================")
    reverse_xs_bit_arr(x3_arr)
