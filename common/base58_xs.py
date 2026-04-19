"""
小红书mns_0101 ---  base58编码
"""
BASE58_ALPHABET = "NOPQRStuvwxWXYZabcyz012DEFTKLMdefghijkl4563GHIJBC7mnop89+/"
BASE58_MAP = {v: k for k, v in enumerate(BASE58_ALPHABET)}


def base58_ecode(data_bytes: bytes | bytes) -> str:
    """
    xs中x3参数的mns0101核心加密 自定义base58
    :param data_bytes: 原始字节数组
    :return: 编码结果字符串
    """
    # 计算前导0
    leading_zeros = 0
    for byte in data_bytes:
        if byte == 0x00:
            leading_zeros += 1
        else:
            break

    # 将字节数组转换为可变的整数列表
    int_data = list(data_bytes)
    # 这里存放每一轮除法得到的余数（base58 的一位）
    remainders = []

    # 对整个字节数组进行长除法
    while any(int_data):
        carry = 0
        for i in range(len(int_data)):
            carry = carry * 256 + int_data[i]
            int_data[i] = carry // 58
            carry = carry % 58
        remainders.append(carry)
        # 去除计算过程中产生的前导0
        while int_data and int_data[0] == 0:
            int_data.pop(0)

    res = "".join(BASE58_ALPHABET[i] for i in remainders[::-1])
    return BASE58_ALPHABET[0] * leading_zeros + res


def base58_decode(base58_str: str) -> [int]:
    """
    xs中x3参数的mns0101核心加密 自定义base58解码
    :param base58_str:
    :return:
    """
    # 计算前导0
    leading_zeros = 0
    for byte in base58_str:
        if byte == BASE58_ALPHABET[0]:
            leading_zeros += 1
        else:
            break

    out_data = []
    for byte in base58_str:
        if byte not in BASE58_MAP:
            raise ValueError(f"Invalid Base58 character: {byte}")

        val = BASE58_MAP[byte]
        carry = val
        for i in range(len(out_data)-1, -1, -1):
            carry += out_data[i]*58
            out_data[i] = carry & 0xff
            carry >>=  8

        while carry > 0:
            out_data.insert(0, carry & 0xff)
            carry >>= 8

    for i in range(leading_zeros):
        out_data.insert(0, 0)
    return out_data




if __name__ == '__main__':
    # NNWIukLf4
    e = base58_ecode(bytes([0, 0, 104, 101, 108, 108, 111]))
    d = base58_decode(e)
    print(e)
    print(d)

