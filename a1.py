import time
import random
from typing import List

EE = "abcdefghijklmnopqrstuvwxyz1234567890"

# 预先生成 CRC32 查表（与 JS 中生成逻辑一致）
def _build_crc_table() -> List[int]:
    table = []
    for r in range(256):
        t = r
        for _ in range(8):
            if t & 1:
                t = (0xedb88320 ^ (t >> 1)) & 0xffffffff
            else:
                t = (t >> 1) & 0xffffffff
        table.append(t)
    return table

_CRC_TABLE = _build_crc_table()

def q(s: str) -> int:
    """
    与 JS 中 q 函数等价的 CRC32 实现。
    输入 s 当作字符序列（使用 ord(c)），返回无符号 32-bit 整数。
    """
    i = 0xffffffff
    for ch in s:
        i = ((i >> 8) ^ _CRC_TABLE[(i ^ ord(ch)) & 0xff]) & 0xffffffff
    return (~i) & 0xffffffff

def en(e: str) -> int:
    """与 JS en 等价的映射"""
    if e == "Android":
        return 1
    elif e == "iOS":
        return 2
    elif e == "Mac OS":
        return 3
    elif e == "Linux":
        return 4
    else:
        return 5

def et(length: int) -> str:
    """生成随机字符串，来源于 EE，等价 JS 的 et"""
    return ''.join(EE[random.randrange(36)] for _ in range(length))

def em(e: str) -> str:
    """
    主函数：等价于你给的 JS 的 em(e)
    返回与 JS 相同格式的字符串（首 52 字符）。
    """
    t = en(e)
    n = "000"
    # 毫秒时间戳，转为十六进制小写，不带 '0x'
    ts_hex = format(int(time.time() * 1000), 'x')
    r = f"{ts_hex}{et(30)}{t}0{n}"
    o = q(r)
    return (r + str(o))[:52]

if __name__ == '__main__':
    print(em("Windows"))