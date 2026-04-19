# 原始「必须使用」的乱序、重复字符串
RAW_ALPHABET = "NOPQRStuvwxWXYZabcyz012DEFTKLMdefghijkl4563GHIJBC7mnop89+/AUVqrsOPQefghijkABCDEFGuvwz0123456789xy"
BASE58_BASE = 58

# 1. 从 RAW_ALPHABET 中按顺序选出前 58 个互不重复字符，作为真正的 Base58 字母表
def build_alphabet(raw: str, target_len: int = BASE58_BASE) -> str:
    seen = set()
    out = []
    for ch in raw:
        if ch not in seen:
            seen.add(ch)
            out.append(ch)
            if len(out) == target_len:
                break
    if len(out) != target_len:
        raise ValueError(f"无法从 RAW_ALPHABET 中提取出 {target_len} 个唯一字符，只得到了 {len(out)} 个")
    return ''.join(out)

BASE58_ALPHABET = build_alphabet(RAW_ALPHABET)
# 确认一下：
assert len(BASE58_ALPHABET) == BASE58_BASE
assert len(set(BASE58_ALPHABET)) == BASE58_BASE

# 2. 快速映射表
BASE58_INDEX = {ch: idx for idx, ch in enumerate(BASE58_ALPHABET)}

def encode_base58(data: bytes) -> str:
    if not data:
        return ""
    num = int.from_bytes(data, "big")
    encoded = []
    while num > 0:
        num, rem = divmod(num, BASE58_BASE)
        encoded.append(BASE58_ALPHABET[rem])
    # 前导零字节对应字母表第 0 号字符
    n0 = len(data) - len(data.lstrip(b"\x00"))
    encoded.extend(BASE58_ALPHABET[0] * n0)
    return "".join(reversed(encoded))

def decode_base58(s: str) -> bytes:
    if not s:
        return b""
    zero_char = BASE58_ALPHABET[0]
    # 恢复前导零
    n0 = 0
    for ch in s:
        if ch == zero_char:
            n0 += 1
        else:
            break
    # 计算剩余部分的大整数
    num = 0
    for ch in s[n0:]:
        if ch not in BASE58_INDEX:
            raise ValueError(f"非法 Base58 字符：{ch!r}")
        num = num * BASE58_BASE + BASE58_INDEX[ch]
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return b"\x00" * n0 + body

# —— 测试 ——
if __name__ == "__main__":
    print("使用的字母表：", BASE58_ALPHABET)
    for data in [b"", b"\x00\x00hello", b"ChatGPT", b"\xff\x00\xab\xcd"]:
        e = encode_base58(data)
        d = decode_base58(e)
        print(f"{data!r} → encode: {e} → decode: {d!r}")
