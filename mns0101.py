from common import base58_xs
from common.generate_bit_arr import reverse_xs_bit_arr

MNS0101_KEY = "af572b95ca65b2d9ec76bb5d2e97cb653299cc663399cc663399cce673399cce6733190c06030100000000008040209048241289c4e271381c0e0703018040a05028148ac56231180c0683c16030984c2693c964b259ac56abd5eaf5fafd7e3f9f4f279349a4d2e9743a9d4e279349a4d2e9f47a3d1e8f47239148a4d269341a8d4623110884422190c86432994ca6d3e974baddee773b1d8e47a35128148ac5623198cce6f3f97c3e1f8f47a3d168b45aad562b158ac5e2f1f87c3e9f4f279349a4d269b45aad56"


def mns0101_encrypt(arr: list[int]) -> str:
    """
    0101加密
    :param arr:
    :return:
    """
    result_bytes = bytearray(len(arr))
    for i in range(len(arr)):
        result_bytes[i] = (arr[i] ^ bytes.fromhex(MNS0101_KEY)[i]) & 0xFF

    return "mns0101_" + base58_xs.base58_ecode(result_bytes)


def mns0101_decryption(s: str) -> list[int]:
    """
    0101解密
    :return:
    """
    prefix = "mns0101_"
    if not isinstance(s, str) or not s.startswith(prefix):
        raise ValueError("输入必须是以 'mns0101_' 为前缀的字符串")
    base58_arr = base58_xs.base58_decode(s[len(prefix):])
    result_bytes = bytearray(len(base58_arr))
    for i in range(len(base58_arr)):
        result_bytes[i] = (base58_arr[i] ^ bytes.fromhex(MNS0101_KEY)[i]) & 0xFF

    return list(result_bytes)


if __name__ == '__main__':
    x3 = input("请输入x3:")
    x3_arr = mns0101_decryption(x3)
    print(f"原始数组：{x3_arr}")
    print("=======================解析原始数组=============================================")
    reverse_xs_bit_arr(x3_arr)