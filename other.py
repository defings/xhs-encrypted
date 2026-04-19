import math
import random
import secrets
import string
import time


def generate_trace_id() -> str:
    chars = "abcdef0123456789"
    trace_id = ''.join(random.choice(chars) for _ in range(16))
    return trace_id


def generate_xx_ray_trace_id():
    # 生成两个64位随机整数（8字节）
    part1 = secrets.randbits(64)
    part2 = secrets.randbits(64)
    # 格式化为16位的十六进制字符串
    part1_hex = f"{part1:016x}"
    part2_hex = f"{part2:016x}"
    # 拼接两部分
    return part1_hex + part2_hex


MAX_VAL = 0x7ffffffe  # 2147483646


def create_request_id_fast() -> str:
    """
    等价于 JS:
      var t = BigInt(Date.now());
      var n = BigInt(Math.ceil(0x7ffffffe * Math.random()));
      return `${n}-${t}`
    返回形如 "12345678-169293..." 的字符串。
    """
    t = int(time.time() * 1000)  # 毫秒
    n = math.ceil(MAX_VAL * random.random())
    return f"{n}-{t}"


def _int_to_base36(num: int) -> str:
    """把非负整数转换为小写 base36 字符串。"""
    if num == 0:
        return "0"
    digits = []
    alphabet = string.digits + string.ascii_lowercase
    while num > 0:
        num, rem = divmod(num, 36)
        digits.append(alphabet[rem])
    return "".join(reversed(digits))


def create_search_id_fast() -> str:
    """
    等价于 JS:
      var r = BigInt(Date.now())
      var o = BigInt(Math.ceil(0x7ffffffe * Math.random()));
      r <<= BigInt(64);
      (r += o).toString(36)
    返回小写 base36 字符串。
    """
    r = int(time.time() * 1000)  # 毫秒
    r <<= 64
    o = math.ceil(MAX_VAL * random.random())
    r += o
    return _int_to_base36(r)
if __name__ == '__main__':
    print(generate_trace_id())
    print(generate_xx_ray_trace_id())