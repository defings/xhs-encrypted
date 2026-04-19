from common.base64_x3 import encode_base64_x3, decode_base64_x3
from common.generate_bit_arr import reverse_xs_bit_arr

MNS0301_key = [113, 163, 2, 37, 119, 147, 39, 29, 221, 39, 59, 206, 227, 228, 185, 141, 157, 121, 53, 225, 218, 51, 245,
               118, 94, 46, 168, 175, 182, 220, 119, 165, 26, 73, 157, 35, 182, 124, 32, 102, 0, 37, 134, 12, 191, 19,
               212, 84, 13, 146, 73, 127, 88, 104, 108, 87, 78, 80, 143, 70, 225, 149, 99, 68, 243, 145, 57, 191, 79,
               175, 34, 163, 238, 241, 32, 183, 146, 88, 20, 91, 47, 235, 81, 147, 182, 71, 134, 105, 150, 18, 152, 231,
               155, 237, 202, 100, 110, 26, 105, 58, 146, 97, 84, 165, 167, 161, 189, 28, 240, 222, 219, 116, 47, 145,
               122, 116, 122, 30, 56, 139, 35, 79, 34, 119, 81, 109, 183, 17, 96, 53, 67, 151, 48, 250, 97, 233, 130,
               42, 14, 202, 123, 255, 114, 216]


def mns0301_encrypt(arr: list[int]) -> str:
    """
    0201加密
    :param arr:
    :return:
    """
    result_bytes = bytearray(len(arr))
    for i in range(len(MNS0301_key)):
        result_bytes[i] = (arr[i] ^ MNS0301_key[i]) & 0xFF
    return "mns0301_" + encode_base64_x3(result_bytes)


def mns0301_decryption(s: str) -> list[int]:
    """
    0301解密
    :return:
    """
    prefix = "mns0301_"
    if not isinstance(s, str) or not s.startswith(prefix):
        raise ValueError("输入必须是以 'mns0301_' 为前缀的字符串")
    base64_arr = decode_base64_x3(s[len(prefix):])
    result_bytes = bytearray(len(base64_arr))
    for i in range(len(MNS0301_key)):
        result_bytes[i] = (base64_arr[i] ^ MNS0301_key[i]) & 0xFF
    return list(result_bytes)


if __name__ == '__main__':
    x3 = input("请输入x3:")
    x3_arr = mns0301_decryption(x3)
    print(f"原始数组：{x3_arr}")
    print("=======================解析原始数组=============================================")
    reverse_xs_bit_arr(x3_arr)


"""
1,124,249,65,103,103,201,181,131,99,94,7,68,250,132,21
1,238,249,65,103,103,201,181,131,99,94,7,68,250,132,21
1,91,249,65,103,103,201,181,131,99,94,7,68,250,132,21
1,32,249,65,103,103,201,181,131,99,94,7,68,250,132,21
1,238,249,65,103,103,201,181,131,99,94,7,68,250,132,21
"""