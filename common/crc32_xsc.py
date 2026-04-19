def xs_common_crc32():
    """
    返回一个函数 u(s: str) -> int，
    模拟下面这段 JS 逻辑：
      - 构造多项式 0xedb88320 的 256 项查表 f[]
      - 初始 c = -1（即全 1）
      - 对每个字符按 charCodeAt 处理：c = f[(c ^ b)&0xFF] ^ (c>>>8)
      - 最后 return -1 ^ c ^ poly
    """
    poly = 0xEDB88320
    # 构建查表
    f = []
    for d in range(256):
        r = d
        for _ in range(8):
            if (r & 1) != 0:
                r = (r >> 1) ^ poly
            else:
                r = r >> 1
        f.append(r & 0xFFFFFFFF)

    def u(s: str) -> int:
        # 初始全 1（相当于 JS 里的 -1 >>> 0）
        c = 0xFFFFFFFF
        for ch in s:
            b = ord(ch)
            idx = (c ^ b) & 0xFF
            # 逻辑右移 8 位等同于 (c >> 8) 且高位填零
            c = f[idx] ^ (c >> 8)
        # -1 ^ c ^ poly，并取低 32 位
        res = (-1 ^ c ^ poly) & 0xFFFFFFFF
        # 转成带符号的 32 位整数
        if res & 0x80000000:
            res -= 0x100000000
        return res

    return u
