from typing import List

MASK = 0xFFFFFFFF
DELTA = 1013904243
DEFAULT_KEY = [942945893, 845243187, 1701130593, 862270820]


def _mx(sum_: int, y: int, z: int, p: int, idx: int, key: List[int]) -> int:
    """核心混合函数（与您原实现完全一致）。"""
    y &= MASK
    z &= MASK
    part1 = ((z >> 5) ^ ((y << 2) & MASK)) + ((y >> 3) ^ ((z << 4) & MASK))
    part2 = (sum_ ^ y) + (key[(p & 3) ^ idx] ^ z)
    return (part1 ^ part2) & MASK


def _idx_from_sum(sum_val: int) -> int:
    """原算法里用 sum 的旧值计算 idx：0 if sum==0 else ((sum+3)//4)%4"""
    return 0 if sum_val == 0 else ((sum_val + 3) // 4) % 4


def xxtea_encrypt(data: List[int], key: List[int] | None = None) -> List[int]:
    """
    优化后的加密（就地修改 data 并返回）。
    行为与您原先的 xxtea_encrypt 一致。
    """
    if key is None:
        key = DEFAULT_KEY
    n = len(data)
    if n == 0:
        return data

    rounds = (6 + 52 // n) & MASK
    sum_ = 0
    z = data[-1] & MASK

    for _ in range(rounds):
        idx = _idx_from_sum(sum_)
        sum_ = (sum_ + DELTA) & MASK

        # 更新前 n-1 个元素
        for p in range(n - 1):
            y = data[p + 1] & MASK
            t = _mx(sum_, y, z, p, idx, key)
            data[p] = (data[p] + t) & MASK
            z = data[p]

        # 最后一个元素（p == n-1），y 为 data[0]
        y = data[0] & MASK
        t = _mx(sum_, y, z, n - 1, idx, key)
        data[-1] = (data[-1] + t) & MASK
        z = data[-1]

    return data


def xxtea_decrypt(data: List[int], key: List[int] | None = None) -> List[int]:
    """
    优化后的解密（就地修改 data 并返回），为加密的严格逆过程。
    支持 n == 0, 1, 2, ...（与加密行为对应）。
    """
    if key is None:
        key = DEFAULT_KEY
    n = len(data)
    if n == 0:
        return data

    rounds = (6 + 52 // n) & MASK
    sum_ = (DELTA * rounds) & MASK  # 逆向时从 rounds * delta 开始
    # 逆向主循环
    while sum_ != 0:
        prev_sum = (sum_ - DELTA) & MASK
        idx = _idx_from_sum(prev_sum)

        # 反向更新：从 p = n-1 ... 1
        for p in range(n - 1, 0, -1):
            y = data[(p + 1) % n] & MASK
            z = data[p - 1] & MASK
            t = _mx(sum_, y, z, p, idx, key)
            data[p] = (data[p] - t) & MASK

        # p == 0 的反向步骤
        y = data[1 % n] & MASK
        z = data[-1] & MASK
        t = _mx(sum_, y, z, 0, idx, key)
        data[0] = (data[0] - t) & MASK

        sum_ = (sum_ - DELTA) & MASK

    return data


# ---------------------------
# 简单自测（示例）
if __name__ == "__main__":
    plain = [104,77,129,198,77,154,80,134,3,15,246,99,107,29,44,145]   #[825942930, 3217558119, 414448225, 2797412404]
    enc = xxtea_encrypt(plain, [164,60,34,248,155,1,0,0])
    print(enc)
    # print(xxtea_decrypt(enc, DEFAULT_KEY))