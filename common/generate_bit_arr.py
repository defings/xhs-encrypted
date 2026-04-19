import hashlib
import random
import time
from common.arx_custom import custom_hash_v2


def ts_special(ts: int) -> [int]:
    """
    "时间戳特殊处理转换" equivalent to JS ts1 function.
    """
    # low and high 32 bits
    low32 = [(ts & 0xFFFFFFFF) >> (8 * i) & 0xFF for i in range(4)]
    high32 = [(ts // 0x100000000) >> (8 * i) & 0xFF for i in range(4)]
    # xor 0x29
    xor29 = lambda arr: [b ^ 0x29 for b in arr]
    lowX = xor29(low32)
    highX = xor29(high32)
    # flag raw
    flag_raw = (low32[1] + low32[2] + low32[3] + high32[0]) & 0xFF
    flag = (flag_raw + 1) & 0xFF
    result = lowX + highX
    result[0] = flag ^ 0x29
    return result


def generate_xs_bit_arr(path: str, body_data: str, load_ts: int, a1: str,
                        xsecappid: str = "xhs-pc-web") -> list[int]:
    """
    :param path: 请求路径
    :param body_data: 如果是post请求应当为：json字符串的请求体（去除空格），如果是get请求则直接传入，空
    :param load_ts: cookie的时间戳
    :param a1: cookie的a1参数
    :param xsecappid: 客户端表示一般可选为：xhs-pc-web || ugc
    :return:
    """
    # 小端表示
    to_le = lambda n, r=4: [(n >> (i * 8)) & 0xff for i in range(r)]

    # 标记头：固定
    arr = [121, 104, 96, 41]
    # 随机种子的小端序：[0, 1] * 2的32次方-1
    random_seed = random.getrandbits(32) & 0xFFFFFFFF
    arr += to_le(random_seed)

    # 时间戳转一个长度为8的小端序
    now_ts = int(time.time() * 1000)
    arr += to_le(now_ts, 8)  # 老版本处理方法ts_special(now_ts)

    # cookie中的loadts的小端序
    arr += to_le(load_ts, 8)

    # 加密调用计数（或者说请求次数）的小端序
    arr += to_le(random.randint(1, 100), 4)

    # window上挂载元素数量的小端序
    arr += to_le(1353)  # 1292

    # 请求路径长度的小端序
    arr += to_le(len(path+body_data))

    # 请求体信息转换
    url_text = path if body_data == "" else path + body_data
    path_md5 = hashlib.md5(url_text.encode('utf-8')).hexdigest()
    key_byte = arr[4]
    temp_arr = [int(path_md5[i:i + 2], 16) ^ key_byte for i in range(0, len(path_md5), 2)]
    temp_arr = temp_arr[:8]
    arr += temp_arr

    arr.append(len(a1))
    # a1 ascii
    arr += [ord(c) for c in a1]

    arr.append(len(xsecappid))
    # "xhs-pc-web"
    arr += [ord(c) for c in xsecappid]

    # random array constant
    arr += [1, random.randint(100, 300), 249, 65, 103, 103, 201, 181, 131, 99, 94, 7, 68, 250, 132, 21]

    # 请求路径转换
    url_text = path
    url_md5 = hashlib.md5(url_text.encode('utf-8')).hexdigest()
    temp_arr = to_le(now_ts, 8)
    temp_arr.extend([int(url_md5[i:i + 2], 16) for i in range(0, len(url_md5), 2)])
    temp_arr = custom_hash_v2(bytes(temp_arr))
    arr.extend([2, 97, 51, 16])
    arr.extend([i ^ key_byte for i in temp_arr])
    return arr


def reverse_xs_bit_arr(arr: [int]):
    """
    反向解析xs字节数组
    :param arr:
    :return:
    """
    le_to = lambda l: sum([l[i] << (8 * i) for i in range(len(l))])
    # md5码反向解析
    recover_path_md5_prefix = lambda arr_md5, key_byte: ''.join(f'{b:02x}' for b in [b ^ key_byte for b in arr_md5])

    temp_data = arr[:4]
    print(f"前置标识头：{temp_data}")

    temp_data = arr[4:8]
    print(f"{temp_data} --> 随机种子：{le_to(temp_data)}，float={le_to(temp_data) / 4294967295}")

    temp_data = arr[8:16]
    print(f"{temp_data} ---> 时间戳：{le_to(temp_data)}")

    temp_data = arr[16:24]
    print(f"{temp_data} ---> cookie时间戳：{le_to(temp_data)}")

    temp_data = arr[24:28]
    print(f"{temp_data} ---> 请求次数：{le_to(temp_data)}")

    temp_data = arr[28:32]
    print(f"{temp_data} ---> windows挂载的元素数量：{le_to(temp_data)}")

    temp_data = arr[32:36]
    print(f"{temp_data} ---> 请求路径长度：{le_to(temp_data)}")

    temp_data = arr[36:44]
    print(f"{temp_data} ---> md5码前缀：{recover_path_md5_prefix(temp_data, arr[4])}")

    temp_data = arr[44]
    print(f"{temp_data} ---> a1参数长度：{temp_data}")

    temp_data = arr[45:97]
    print(f"{temp_data} ---> a1：{''.join(chr(c) for c in temp_data)}")

    temp_data = arr[97]
    print(f"{temp_data} ---> 换行符的ASCII码：{temp_data}")

    temp_data = []
    for i in arr[98:]:
        if i == 1:
            break
        temp_data.append(i)
    print(f"{temp_data} ---> 用户标识或者说cookie中的xsecappid：{''.join(chr(i) for i in temp_data)}")

    flg = 98 + len(temp_data)
    temp_data = arr[flg:flg + 16]
    print(f"其他数组：{temp_data}")

    temp_data = arr[flg + 16:]
    print(temp_data)


if __name__ == '__main__':
    path = "/api/web/sns/feed"
    body_str = "{}"
    lts = 1770689027404
    a1 = "1930000sdsdfdfggfg"
    print(generate_xs_bit_arr(path, body_str, lts, a1))

