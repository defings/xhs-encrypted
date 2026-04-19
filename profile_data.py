import base64
import json
import random
import time
from typing import List

# === ProfileDataKeys (与你的 Go 一致) ===
ProfileDataKeys: List[int] = [
    187567141, 875696391, 170266120, 876222754, 188089115, 1010309137, 187054378, 957950720,
    758514978, 941162813, 221382708, 990709537, 758848528, 688730163, 890444313, 722272792,
    890962233, 252521496, 890843430, 185009704, 874317360, 119997734, 907612693, 119932961,
    841824786, 120993794, 839716879, 909248796, 439099654, 372901635, 439091750, 1009915397,
]

# 保证 keys 中每个值都落在 32-bit 无符号范围，如果需要（调用者可传入任意 int）。
ProfileDataKeys = [k & 0xffffffff for k in ProfileDataKeys]


def _u32(x: int) -> int:
    """保留 32-bit 无符号值"""
    return x & 0xffffffff


def rightShift3(v: int, c: int) -> int:
    """模拟 Go 中的 unsigned right shift for 32-bit"""
    return (v & 0xffffffff) >> c


def desCryptor(message: bytes, mode: int, encrypt: bool, padding: int, iv: bytes, keys: List[int]) -> bytes:
    """
    message: bytes（函数内部按字节处理）
    mode: int (0 表示 ECB，1 表示 CBC)
    encrypt: True=加密, False=解密
    padding: 0/1/2（与 Go 保持一致）
    iv: bytes 长度至少 8（当 mode==1 时使用）
    keys: list of int (32 entries 表示单/3 DES 的 key table)
    返回: bytes
    """
    # S-box / spfunction arrays（保持与 Go 一致），并转换为 32-bit 无符号数
    spfunction1 = [0x1010400, 0, 0x10000, 0x1010404, 0x1010004, 0x10404, 0x4, 0x10000,
                   0x400, 0x1010400, 0x1010404, 0x400, 0x1000404, 0x1010004, 0x1000000, 0x4,
                   0x404, 0x1000400, 0x1000400, 0x10400, 0x10400, 0x1010000, 0x1010000, 0x1000404,
                   0x10004, 0x1000004, 0x1000004, 0x10004, 0, 0x404, 0x10404, 0x1000000,
                   0x10000, 0x1010404, 0x4, 0x1010000, 0x1010400, 0x1000000, 0x1000000, 0x400,
                   0x1010004, 0x10000, 0x10400, 0x1000004, 0x400, 0x4, 0x1000404, 0x10404,
                   0x1010404, 0x10004, 0x1010000, 0x1000404, 0x1000004, 0x404, 0x10404, 0x1010400,
                   0x404, 0x1000400, 0x1000400, 0, 0x10004, 0x10400, 0, 0x1010004]
    spfunction2 = [-0x7fef7fe0, -0x7fff8000, 0x8000, 0x108020, 0x100000, 0x20, -0x7fefffe0, -0x7fff7fe0,
                   -0x7fffffe0, -0x7fef7fe0, -0x7fef8000, -0x80000000, -0x7fff8000, 0x100000, 0x20, -0x7fefffe0,
                   0x108000, 0x100020, -0x7fff7fe0, 0, -0x80000000, 0x8000, 0x108020, -0x7ff00000,
                   0x100020, -0x7fffffe0, 0, 0x108000, 0x8020, -0x7fef8000, -0x7ff00000, 0x8020,
                   0, 0x108020, -0x7fefffe0, 0x100000, -0x7fff7fe0, -0x7ff00000, -0x7fef8000, 0x8000,
                   -0x7ff00000, -0x7fff8000, 0x20, -0x7fef7fe0, 0x108020, 0x20, 0x8000, -0x80000000,
                   0x8020, -0x7fef8000, 0x100000, -0x7fffffe0, 0x100020, -0x7fff7fe0, -0x7fffffe0, 0x100020,
                   0x108000, 0, -0x7fff8000, 0x8020, -0x80000000, -0x7fefffe0, -0x7fef7fe0, 0x108000]
    spfunction3 = [0x208, 0x8020200, 0, 0x8020008, 0x8000200, 0, 0x20208, 0x8000200,
                   0x20008, 0x8000008, 0x8000008, 0x20000, 0x8020208, 0x20008, 0x8020000, 0x208,
                   0x8000000, 0x8, 0x8020200, 0x200, 0x20200, 0x8020000, 0x8020008, 0x20208,
                   0x8000208, 0x20200, 0x20000, 0x8000208, 0x8, 0x8020208, 0x200, 0x8000000,
                   0x8020200, 0x8000000, 0x20008, 0x208, 0x20000, 0x8020200, 0x8000200, 0, 0x200,
                   0x20008, 0x8020208, 0x8000200, 0x8000008, 0x200, 0, 0x8020008, 0x8000208,
                   0x20000, 0x8000000, 0x8020208, 0x8, 0x20208, 0x20200, 0x8000008, 0x8020000,
                   0x8000208, 0x208, 0x8020000, 0x20208, 0x8, 0x8020008, 0x20200]
    spfunction4 = [0x802001, 0x2081, 0x2081, 0x80, 0x802080, 0x800081, 0x800001, 0x2001,
                   0, 0x802000, 0x802000, 0x802081, 0x81, 0, 0x800080, 0x800001, 0x1, 0x2000,
                   0x800000, 0x802001, 0x80, 0x800000, 0x2001, 0x2080, 0x800081, 0x1, 0x2080,
                   0x800080, 0x2000, 0x802080, 0x802081, 0x81, 0x800080, 0x800001, 0x802000,
                   0x802081, 0x81, 0, 0, 0x802000, 0x2080, 0x800080, 0x800081, 0x1, 0x802001,
                   0x2081, 0x2081, 0x80, 0x802081, 0x81, 0x1, 0x2000, 0x800001, 0x2001, 0x802080,
                   0x800081, 0x2001, 0x2080, 0x800000, 0x802001, 0x80, 0x800000, 0x2000, 0x802080]
    spfunction5 = [0x100, 0x2080100, 0x2080000, 0x42000100, 0x80000, 0x100, 0x40000000, 0x2080000,
                   0x40080100, 0x80000, 0x2000100, 0x40080100, 0x42000100, 0x42080000, 0x80100, 0x40000000,
                   0x2000000, 0x40080000, 0x40080000, 0, 0x40000100, 0x42080100, 0x42080100, 0x2000100,
                   0x42080000, 0x40000100, 0, 0x42000000, 0x2080100, 0x2000000, 0x42000000, 0x80100,
                   0x80000, 0x42000100, 0x100, 0x2000000, 0x40000000, 0x2080000, 0x42000100, 0x40080100,
                   0x2000100, 0x40000000, 0x42080000, 0x2080100, 0x40080100, 0x100, 0x2000000, 0x42080000,
                   0x42080100, 0x80100, 0x42000000, 0x42080100, 0x2080000, 0, 0x40080000, 0x42000000,
                   0x80100, 0x2000100, 0x40000100, 0x80000, 0, 0x40080000, 0x2080100, 0x40000100]
    spfunction6 = [0x20000010, 0x20400000, 0x4000, 0x20404010, 0x20400000, 0x10, 0x20404010, 0x400000,
                   0x20004000, 0x404010, 0x400000, 0x20000010, 0x400010, 0x20004000, 0x20000000, 0x4010,
                   0, 0x400010, 0x20004010, 0x4000, 0x404000, 0x20004010, 0x10, 0x20400010, 0x20400010,
                   0, 0x404010, 0x20404000, 0x4010, 0x404000, 0x20404000, 0x20000000, 0x20004000, 0x10,
                   0x20400010, 0x404000, 0x20404010, 0x400000, 0x4010, 0x20000010, 0x400000, 0x20004000,
                   0x20000000, 0x4010, 0x20000010, 0x20404010, 0x404000, 0x20400000, 0x404010, 0x20404000,
                   0, 0x20400010, 0x10, 0x4000, 0x20400000, 0x404010, 0x4000, 0x400010, 0x20004010, 0,
                   0x20404000, 0x20000000, 0x400010, 0x20004010]
    spfunction7 = [0x200000, 0x4200002, 0x4000802, 0, 0x800, 0x4000802, 0x200802, 0x4200800,
                   0x4200802, 0x200000, 0, 0x4000002, 0x2, 0x4000000, 0x4200002, 0x802,
                   0x4000800, 0x200802, 0x200002, 0x4000800, 0x4000002, 0x4200000, 0x4200800, 0x200002,
                   0x4200000, 0x800, 0x802, 0x4200802, 0x200800, 0x2, 0x4000000, 0x200800, 0x4000000,
                   0x200800, 0x200000, 0x4000802, 0x4000802, 0x4200002, 0x4200002, 0x2, 0x200002, 0x4000000,
                   0x4000800, 0x200000, 0x4200800, 0x802, 0x200802, 0x4200800, 0x802, 0x4000002, 0x4200802,
                   0x4200000, 0x200800, 0, 0x2, 0x4200802, 0, 0x200802, 0x4200000, 0x800, 0x4000002, 0x4000800, 0x800,
                   0x200002]
    spfunction8 = [0x10001040, 0x1000, 0x40000, 0x10041040, 0x10000000, 0x10001040, 0x40, 0x10000000,
                   0x40040, 0x10040000, 0x10041040, 0x41000, 0x10041000, 0x41040, 0x1000, 0x40,
                   0x10040000, 0x10000040, 0x10001000, 0x1040, 0x41000, 0x40040, 0x10040040, 0x10041000,
                   0x1040, 0, 0, 0x10040040, 0x10000040, 0x10001000, 0x41040, 0x40000, 0x41040, 0x40000,
                   0x10041000, 0x1000, 0x40, 0x10040040, 0x1000, 0x41040, 0x10001000, 0x40, 0x10000040,
                   0x10040000, 0x10040040, 0x10000000, 0x40000, 0x10001040, 0, 0x10041040, 0x40040,
                   0x10000040, 0x10040000, 0x10001000, 0x10001040, 0, 0x10041040, 0x41000, 0x41000, 0x1040, 0x1040,
                   0x40040, 0x10000000, 0x10041000]

    # 转为 32-bit 无符号
    spfunction2 = [x & 0xffffffff for x in spfunction2]
    spfunction1 = [x & 0xffffffff for x in spfunction1]
    spfunction3 = [x & 0xffffffff for x in spfunction3]
    spfunction4 = [x & 0xffffffff for x in spfunction4]
    spfunction5 = [x & 0xffffffff for x in spfunction5]
    spfunction6 = [x & 0xffffffff for x in spfunction6]
    spfunction7 = [x & 0xffffffff for x in spfunction7]
    spfunction8 = [x & 0xffffffff for x in spfunction8]

    # 设置 iterations 与 looping
    iterations = 1
    if len(keys) == 32:
        iterations = 3
    else:
        iterations = 9

    if iterations == 3:
        if encrypt:
            looping = [0, 32, 2]
        else:
            looping = [30, -2, -2]
    else:
        if encrypt:
            looping = [0, 32, 2, 62, 30, -2, 64, 96, 2]
        else:
            looping = [94, 62, -2, 32, 64, 2, 30, -2, -2]

    msg = bytearray(message)  # 可变字节数组
    orig_len = len(msg)  # ⚠️ 保存填充前长度，等同于 Go 的 len1

    # 填充（严格按 Go 的逻辑）
    if padding == 2:
        msg += b'    '
    elif padding == 1:
        if encrypt:
            temp = 8 - (orig_len % 8)
            # Go 的实现：如果 temp==8，会把 len1 += 8
            padding_bytes = bytes([temp]) * temp
            msg += padding_bytes
            if temp == 8:
                orig_len += 8
    elif padding == 0:
        msg += b'\x00' * 8

    # CBC 初始化（同之前）
    m = 0
    tempresult = bytearray()
    cbcleft = cbcright = cbcleft2 = cbcright2 = 0
    if mode == 1:
        if not iv or len(iv) < 8:
            raise ValueError("mode==1 (CBC) requires iv of length >= 8")
        ivb = iv if isinstance(iv, (bytes, bytearray)) else iv.encode('latin1')
        cbcleft = ((ivb[0] << 24) | (ivb[1] << 16) | (ivb[2] << 8) | ivb[3]) & 0xffffffff
        cbcright = ((ivb[4] << 24) | (ivb[5] << 16) | (ivb[6] << 8) | ivb[7]) & 0xffffffff

    # 主循环：⚠️ 使用 orig_len （填充前长度）作为边界，与 Go 完全一致
    while m < orig_len:
        # 确保能够安全读取 8 字节（因为我们已经对 msg 做了填充）
        left = ((msg[m] << 24) | (msg[m + 1] << 16) | (msg[m + 2] << 8) | msg[m + 3]) & 0xffffffff
        right = ((msg[m + 4] << 24) | (msg[m + 5] << 16) | (msg[m + 6] << 8) | msg[m + 7]) & 0xffffffff
        m += 8

        # （剩余加密/解密流程与之前实现完全相同）
        # 初始置换
        temp = _u32((rightShift3(left, 4) ^ right) & 0x0f0f0f0f)
        right ^= temp;
        right &= 0xffffffff
        left ^= _u32((temp << 4) & 0xffffffff);
        left &= 0xffffffff

        temp = _u32((rightShift3(left, 16) ^ right) & 0x0000ffff)
        right ^= temp;
        right &= 0xffffffff
        left ^= _u32((temp << 16) & 0xffffffff);
        left &= 0xffffffff

        temp = _u32((rightShift3(right, 2) ^ left) & 0x33333333)
        left ^= temp;
        left &= 0xffffffff
        right ^= _u32((temp << 2) & 0xffffffff);
        right &= 0xffffffff

        temp = _u32((rightShift3(right, 8) ^ left) & 0x00ff00ff)
        left ^= temp;
        left &= 0xffffffff
        right ^= _u32((temp << 8) & 0xffffffff);
        right &= 0xffffffff

        temp = _u32((rightShift3(left, 1) ^ right) & 0x55555555)
        right ^= temp;
        right &= 0xffffffff
        left ^= _u32((temp << 1) & 0xffffffff);
        left &= 0xffffffff

        left = _u32(((left << 1) & 0xffffffff) | rightShift3(left, 31))
        right = _u32(((right << 1) & 0xffffffff) | rightShift3(right, 31))

        # 轮函数（保持原逻辑）
        for j in range(0, iterations, 3):
            endloop = looping[j + 1]
            loopinc = looping[j + 2]
            i = looping[j]
            while i != endloop:
                right1 = _u32(right ^ (keys[i] & 0xffffffff))
                right2 = _u32((rightShift3(right, 4) | ((right << 28) & 0xffffffff)) ^ (keys[i + 1] & 0xffffffff))
                temp_left = left
                left = right

                idx1 = rightShift3(right1, 24) & 0x3f
                idx2 = rightShift3(right1, 16) & 0x3f
                idx3 = rightShift3(right1, 8) & 0x3f
                idx4 = right1 & 0x3f
                idx5 = rightShift3(right2, 24) & 0x3f
                idx6 = rightShift3(right2, 16) & 0x3f
                idx7 = rightShift3(right2, 8) & 0x3f
                idx8 = right2 & 0x3f

                fval = (spfunction2[idx1] | spfunction4[idx2] | spfunction6[idx3] | spfunction8[idx4] |
                        spfunction1[idx5] | spfunction3[idx6] | spfunction5[idx7] | spfunction7[idx8]) & 0xffffffff

                right = _u32(temp_left ^ fval)
                i += loopinc

            temp_left = left
            left = right
            right = temp_left

        # 逆置换
        left = _u32((rightShift3(left, 1) | ((left << 31) & 0xffffffff)))
        right = _u32((rightShift3(right, 1) | ((right << 31) & 0xffffffff)))

        temp = _u32((rightShift3(left, 1) ^ right) & 0x55555555)
        right ^= temp;
        right &= 0xffffffff
        left ^= _u32((temp << 1) & 0xffffffff);
        left &= 0xffffffff

        temp = _u32((rightShift3(right, 8) ^ left) & 0x00ff00ff)
        left ^= temp;
        left &= 0xffffffff
        right ^= _u32((temp << 8) & 0xffffffff);
        right &= 0xffffffff

        temp = _u32((rightShift3(right, 2) ^ left) & 0x33333333)
        left ^= temp;
        left &= 0xffffffff
        right ^= _u32((temp << 2) & 0xffffffff);
        right &= 0xffffffff

        temp = _u32((rightShift3(left, 16) ^ right) & 0x0000ffff)
        right ^= temp;
        right &= 0xffffffff
        left ^= _u32((temp << 16) & 0xffffffff);
        left &= 0xffffffff

        temp = _u32((rightShift3(left, 4) ^ right) & 0x0f0f0f0f)
        right ^= temp;
        right &= 0xffffffff
        left ^= _u32((temp << 4) & 0xffffffff);
        left &= 0xffffffff

        if mode == 1:
            if encrypt:
                cbcleft = left
                cbcright = right
            else:
                left ^= cbcleft2
                right ^= cbcright2
                left &= 0xffffffff
                right &= 0xffffffff

        out8 = bytearray(8)
        out8[0] = rightShift3(left, 24) & 0xff
        out8[1] = rightShift3(left, 16) & 0xff
        out8[2] = rightShift3(left, 8) & 0xff
        out8[3] = left & 0xff
        out8[4] = rightShift3(right, 24) & 0xff
        out8[5] = rightShift3(right, 16) & 0xff
        out8[6] = rightShift3(right, 8) & 0xff
        out8[7] = right & 0xff

        tempresult += out8

    result = bytes(tempresult)

    # 解密时的 PKCS7 去填充（与 Go 一致）
    if (not encrypt) and padding == 1:
        if len(result) > 0:
            padding_chars = result[-1]
            if 1 <= padding_chars <= 8:
                result = result[:len(result) - padding_chars]

    return result


def stringToHex(b: bytes) -> str:
    """把 bytes 转为每字节两位十六进制字符串（小写），与 Go 行为一致"""
    return ''.join('{:02x}'.format(byte) for byte in b)


def EncryptProfileData(s: str) -> str:
    """
    对字符串 s 做：
      base64_encode(s) -> 作为 message 调用 desCryptor(..., encrypt=True, padding=0, mode=0)
      然后把返回的 bytes 转成 hex string（与 Go 的 stringToHex）
    """
    b64 = base64.b64encode(s.encode('utf-8'))  # bytes
    # desCryptor 期望 bytes
    enc = desCryptor(b64, 0, True, 0, b'', ProfileDataKeys)
    return stringToHex(enc)


def GetProfileData(cookie: str, ua: str, location: str) -> str:
    """构造与 Go 相同的 JSON 字段并返回 EncryptProfileData 的结果"""
    x1 = ua
    x44 = str(int(time.time() * 1000))  # ms since epoch, 等价于 Go 的 UnixNano()/1e6
    x57 = cookie
    y = round(random.randint(860, 864) + random.random(), 5)
    right = round(random.randint(290, 292) + random.random(), 5)
    bottom = round(random.randint(881, 883) + random.random(), 5)
    payload = {
        "x1": x1,
        "x2": "false", "x3": "zh-CN", "x4": "32", "x5": "8", "x6": "32",
        "x7": "Google Inc. (Intel),ANGLE (Intel, Intel(R) HD Graphics 4600 (0x00000412) Direct3D11 vs_5_0 ps_5_0, D3D11)",
        "x8": "4", "x9": "1920;1080", "x10": "1920;1040", "x11": "-480", "x12": "Asia/Shanghai", "x13": "true",
        "x14": "true", "x15": "true", "x16": "false", "x17": "false", "x18": "un", "x19": "Win32", "x20": "un",
        "x21": "PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF",
        "x22": "4d48070a3c236ee5469cf56fabc2b34e", "x23": "false", "x24": "false", "x25": "false", "x26": "false",
        "x27": "false", "x28": "0,false,false", "x29": "4,7,8", "x30": "swf object not loaded",
        "x31": "124.04347527516074", "x33": "0", "x34": "0", "x35": "0", "x36": "3",
        "x37": "0|0|0|0|0|0|0|0|0|1|0|0|0|0|0|0|0|0|1|0|0|0|0|0",
        "x38": "0|0|1|0|1|0|0|0|0|0|1|0|1|0|1|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0", "x39": "1310",
        "x40": "0", "x41": "0", "x42": "3.4.5", "x43": "2e2c912c", "x44": x44,
        "x45": "__SEC_CAV__1-1-1-1-1|", "x46": "false", "x47": "0|0|0|0|0|1", "x48": "", "x49": "{list:[],type:}",
        "x50": "", "x51": "", "x52": "", "x54": "11311144241322244122",
        "x55": "700,700,700,800,700,820,660,660,700,640,720,760,840,860", "x53": "bbbfdfa465c9bd61c524ea7740c3d826",
        "x56": "Google Inc. (Intel)|ANGLE (Intel, Intel(R) HD Graphics 4600 (0x00000412) Direct3D11 vs_5_0 ps_5_0, D3D11)|0ebc53d03ea89d69525d81de558e2544|35",
        "x57": x57,
        "x58": "131", "x59": "12", "x60": "63", "x61": "1346", "x62": "2047", "x63": "0", "x64": "0", "x65": "0",
        "x66": {"referer": "",
                "location": location,
                "frame": 0}, "x67": "1|0", "x68": "0", "x69": "un", "x70": ["location"], "x71": "true",
        "x72": "complete", "x73": "896", "x74": "0|0|0", "x75": "Google Inc.", "x76": "true",
        "x77": "1|1|1|1|1|1|1|1|1|1",
        "x78": {"x": 0, "y": y, "left": 0, "right": right, "bottom": bottom, "height": 18,
                "top": y, "width": right,
                "font": "system-ui, \"Apple Color Emoji\", \"Segoe UI Emoji\", \"Segoe UI Symbol\", \"Noto Color Emoji\", -apple-system, \"Segoe UI\", Roboto, Ubuntu, Cantarell, \"Noto Sans\", sans-serif, BlinkMacSystemFont, \"Helvetica Neue\", Arial, \"PingFang SC\", \"PingFang TC\", \"PingFang HK\", \"Microsoft Yahei\", \"Microsoft JhengHei\""},
        "x79": "144|126543802368", "x80": "1|[object FileSystemDirectoryHandle]",
        "x82": "SharedArrayBuffer|__SSR__|getdss|_0x341b|_0x1769|_0x12372b|_BHjFmfUMEtxhI|_dsf|_dsn|_dsl|_AUuXfEG27Xa3x|liveLogger|setImmediate|clearImmediate|__DANMU_DEBUG__"}
    # Android
    # right = round(random.randint(290, 292) + random.random(), 2)
    # y = random.randint(912, 920)
    # payload = {
    #     "x1": x1,
    #     "x2": "false", "x3": "zh-CN", "x4": "32", "x5": "8", "x6": "32",
    #     "x7": "Google Inc. (Intel),ANGLE (Intel, Intel(R) HD Graphics 4600 (0x00000412) Direct3D11 vs_5_0 ps_5_0, D3D11)",
    #     "x8": "4", "x9": "412;915", "x10": "412;915", "x11": "-480", "x12": "Asia/Shanghai", "x13": "true",
    #     "x14": "true", "x15": "true", "x16": "false", "x17": "false", "x18": "un", "x19": "Win32", "x20": "un",
    #     "x21": "PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF",
    #     "x22": "4d48070a3c236ee5469cf56fabc2b34e", "x23": "false", "x24": "false", "x25": "false", "x26": "false",
    #     "x27": "false", "x28": "1,true,true", "x29": "4,7,8", "x30": "swf object not loaded", "x33": "0", "x34": "0",
    #     "x35": "0", "x36": "3", "x31": "124.04347527516074", "x37": "0|0|0|0|0|0|0|0|0|1|0|0|0|0|0|0|0|0|0|0|0|0|0|0",
    #     "x38": "0|0|1|0|1|0|0|0|0|0|1|1|1|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0", "x39": "1324",
    #     "x40": "0", "x41": "0", "x42": "3.4.5", "x43": "2e2c912c", "x44": x44,
    #     "x45": "__SEC_CAV__1-1-1-1-1|", "x46": "false", "x47": "0|0|0|0|0|1", "x48": "", "x49": "{list:[],type:}",
    #     "x50": "", "x51": "", "x52": "", "x54": "11311144241322244122",
    #     "x55": "680,760,1120,700,1060,800,820,700,720,740,1000,660,700,760", "x53": "bbbfdfa465c9bd61c524ea7740c3d826",
    #     "x56": "Google Inc. (Intel)|ANGLE (Intel, Intel(R) HD Graphics 4600 (0x00000412) Direct3D11 vs_5_0 ps_5_0, D3D11)|0ebc53d03ea89d69525d81de558e2544|35",
    #     "x57": x57,
    #     "x58": "234", "x59": "66", "x60": "63", "x61": "1371", "x62": "2047", "x63": "0", "x64": "0", "x65": "0",
    #     "x66": {"referer": "",
    #             "location": location,
    #             "frame": 0}, "x67": "1|0", "x68": "0", "x69": "un", "x70": ["location"], "x71": "true",
    #     "x72": "complete", "x73": "587", "x74": "0|0|0", "x75": "Google Inc.", "x76": "true",
    #     "x77": "1|1|1|1|1|1|1|1|1|1",
    #     "x78": {"x": 0, "y": y, "left": 0, "right": right, "bottom": bottom, "height": 16, "top": y, "width": right,
    #             "font": "-apple-system, \"SF UI Text\", \"PingFang SC\", \"Hiragino Sans GB\", \"Microsoft YaHei\", \"WenQuanYi Micro Hei\", \"Helvetica Neue\", Helvetica, Arial, sans-serif"},
    #     "x79": "144|126543802368", "x80": "1|[object FileSystemDirectoryHandle]",
    #     "x82": "__CUSTOM_IMG_REPORT__|__CUSTOM_IMG_video_note_poster_METRICS__|__CUSTOM_IMG_ELEMENT__|__CUSTOM_FMP_REPORT__|__CUSTOM_FMP_METRICS__|__CUSTOM_FMP_ELEMENT__|ds_pulling|getdss|_0x341b|_0x1769|_0x12372b|_BHjFmfUMEtxhI|_dsf|_dsn|_dsl"}

    b = json.dumps(payload, separators=(',', ':'), ensure_ascii=False)
    return EncryptProfileData(b)


# === 示例（你可以运行来检验） ===
if __name__ == "__main__":
    from utils.req import req_post
    from utils.common import get_ck_s



    ck = "abRequestId=3b24b0f0-4cda-55d0-8c6a-702e96a515b6; ets=1775118631559; a1=19d4d50c2f4iur1y92n0svksyo1umnjwrgn8r84n350000917626; webId=3f9e950a97d6a23dd87a7e7c251f4bc1; gid=yjf4f28fyfFqyjf4f28SJkY4i437FyvjJI8MIIqhTMvlyY2876IVEF888jyWKJK8qJd4YD4i; id_token=VjEAAKWLvqtWYKdEpUU7x36HHATZFdVwBLulfiORtK2gyMwxoMNj8hz7KksmL5gaG5ZZ+akVqRdGwZ7XkNJtpTdI5/fayLldn5e011MRAP6tP+zk4f9CTazsO/F8ttdBLeDGrPiL; web_session=030037aefd7d5cb6ddcb5451b72e4aacec44e6; xsecappid=xhs-pc-web; webBuild=6.3.0; websectiga=984412fef754c018e472127b8effd174be8a5d51061c991aadd200c69a2801d6; sec_poison_id=9426e61a-ee37-4486-b24e-738bfaf2d1e2; loadts=1775200591797; unread={%22ub%22:%2269ba8af3000000002200db58%22%2C%22ue%22:%2269ac49560000000022032c8b%22%2C%22uc%22:28}"
    a1 = get_ck_s(ck)
    lts = int(get_ck_s(ck, "loadts="))
    uri = "http://as.xiaohongshu.com"
    url_text = "/api/sec/v1/shield/webprofile"
    ua_example = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0"
    enc_hex = GetProfileData(ck, ua_example, "")
    enc_hex = "c0588288ff50a429cb4c1650d4ab590ba275ea4b0000000000000000000000004897724f50ea4e1498d4671f09e203460822cd6681aded0e2fd65123bb1f8a424d6f7a696c6c612f352e30202857696e646f7773204e542031302e303b2057696e36343b2078363429204170706c655765624b69742f3533372e333620284b48544d4c2c206c696b65204765636b6f29204368726f6d652f3134362e302e302e302053617a682d434e000000000057696e33320000000000000000080000000400000a00000004380000002000000020417369612f5368616e6768616900000000000000fffffe20646174613a696d6167652f706e673b6261736536342c34383037303537336634343730613536306434323238623361623830476f6f676c6520496e632e2028496e74656c290000000000000000000000414e474c452028496e74656c2c20496e74656c282d32332e3235373837353435303337373836375f32362e3938363730343130333038323730355f31302e3436343139313939373133323030375f4e2f415f302e3030333735363232363135303033363200000005504446205669657765722c4368726f6d6520504446205669657765722c4368726f6d69756d2050444620566965776572000000000008417269616c2c56657264616e612c54696d6573204e657720526f6d616e2c436f7572696572204e65772c47656f72676961000000000f6e756c6c0000000000000000089c000004cf00000251000000c10000000005b9ad3200000000050d39f1000000010000000034670000000000000000000007a3000000570000000014000000a6000000b2523d14f6000002ea00000209523d155a0000008e00000382523d15be00000696000002cb523d1622000005f20000030f523d168600000248000001ac523d16ea000004960000031f523d174e000000e1000002e1523d17b2000004fb00000140523d1816000005a4000003f8523d187a000004f5000001e8523d18de000004c9000000ac523d19420000023d000002fd523d19a60000062d000003d4523d1a0a0000027100000374523d1a6e00000595000002a6523d1ad20000067b000001d5523d1b360000063800000054523d1b9a000001aa000003b1523d1bfe0000075700000379523d1c6200000004000005e8000001f700000000523d14f60000058e0000017e00000000523d18de0000063e0000041200000000523d1cc60000051e000003ba00000000523d20ae0000000b000000000000135a523d14f600000000000007ef523d16ea0000000000000f03523d18de000000000000096f523d1ad20000000000001042523d1cc60000000000000915523d1eba000000000000056f523d20ae0000000000000980523d22a20000000000000883523d24960000000000000933523d268a76697369626c6500000001000006ae0000035d000000000000006e0000019d523d135913cd962fa43b8563e36c97ba0132de705a7726654176d08f812ae1fab5ea6f108d9edbfa4225543c7121b9ef7726cecf04e29a0d96eabc88d344868425488d96dad0618a3e143fc1027a2658ad30c7d8de9d54fdafd8b59336e4f79b8afa2ebfe58132bf10d98a3449b9c5ad2fbad5aa4f0698c81de9f0b298d829672a3d0fbb08751888e66a36716c5fce5e496145a8106f36b13cefacda74fe33d7b1b00cc6674c5ca1cc097b29de46283845a09f4a3cc526cf1d4fcb342ed181207aedd16ae1437147cf4de24bf4b4fc55e6cdff618d5bdfe4e3ac5091001f74fa14d359a3fbd7c5ed0618c100eb5b5cbd8f1f78eb439313fd9ae9936f0191abb7725a0a42611852f50fc9343a8a480f7de7c1b25d9c6df15d8fae6ab0880ac02b77fded92921c94d4523d097ccb9afeeba54adaf4dffe807644a033dab680f48e38b40599bb3fa9bca5cc913efd5bdfa11f9f7cf27374a0e1d490f1a7f7344e5651cd80e02a83b1dbdd0ac5f70d1ca2365302cfb06a5579d44382825a98416fc4733f956132a5086a585d22a663a7a481ec860db0a9c244c33c5f2f6eaf016b1f7641f553960862a0dc8a263b3f7a46628e8a0fa769f6610d4a810c8cac0285a6c5038ffae3feaf25263f7f8814c191e113f13ec9bf349ccec55c9edd5de45509b471f404110ecf39be2856226a5f32def36627f576a3001eed42102a743dbcc896981c4a2f7c0412c987d9bf9c9382c36e44e9ba309e01c7c0ee0acb87343a70252188bfa01c0aa6069b54d330f6f22be632fb63fffed581b4e6ee7fcc6a80610294db7252d7583d90e1bef0c20199b3e1903f56a27ce75d84d401a7c2c18c365ccea34f5c6a7f5718bc66a73ba3e91e8f7bbae2fee4b01b30ea78eb25155a9892cde9d663295f656bc6f8d6e79dfedf5bb1095186fedafedacc026e6426f59ab5bcf4ff020949683d6bc9dfb78b5995cc6ecdc955cc38fa037164efeee64b77ab9ccdee15ec0c7608756cd2e519817467fa0562774f3fd5c5b562f5dc088c60699a0629a1ba99b53af40283dda8c83edbca524520877f59f6ba77d34e8e7f163ddd73a1694b91fb944c3d5ffc3bad82cc12c12aa05c7ec7577b1237c19de71194a015308921108c540c302454bbbe66c7b055cff5fb0bf71e5bb5771e9f2a7fefb716ab6b712ec240ad51797f2a856775ec5ab7de5a4558f30c5cb977ab4d33e634aad0de161ea35865c85d7acf4f6320f027d3ef17a5173faf2af5636757c238ef2ded290eff4dab6da0c3fbe604ab0576ddba84056e1ed46638932bbdd425b0e2b8b3c3597c0f4579bcd124d0a448641f89ae463d85a32596b5d0299a6047e8f01693032661d05d87608889d6c01f58d19c862bdb4f4e40f4bae76256577dd274e30e76cdbe96f1ae287d641eef1694f80331980a37b92c4ea01ffcc3d3d61a32f7995dd24d3fe1e83262bbff2154e09ebb15389a139dd0e12d1412327119f7700928d0f286831577d08d20820c2b44ddbaad5a4a3650da6d793d0a70f4d7825abf290d0082427b02531d092daad8c32d371b2b8b0a9a786e431c47224dc4bf9877e65a7ba65654363e11cdc0dea35afdabd1987a5e3a2efdc504db07335ca0cc2ff5d23f8db4cf28724b0adee33b2295a558f8fbfa9f8e0c301469581a1a1ffa6dc5707d991acaf9bcd76e86f673fcf3cbe7c6938113bf8006dd3f382392ac45365fe0c1b4e81ca5637d0cd693dc36d4970f72315f4ddffd98aaace7b918802823253d98a01a7b17c8b8654a85f36bf4228bb49d8aecfb46a182e22a89fba45c2bd5d53894ad138092c5cac34fc674e3e7b95e06041b0b9e102dace76c4b16b3ddbe194781248a2d0970333181769b4f7e3a0f0c1c841127e3d179280c1636e1d0079b45f9a68fc7713b02c5c0ccc4ad9fdfe708e5080755f6e79c87dbc457d4eac171be04b42e314b3a199ad570bf693f5a8e05527165eccf226212cb5d7db03f42680f0cdf6ea7ad0ddc10b718f36efc46043a61b3004d845d8b1f437f64e69f19c1427f369020d81545982969383f655d0acb5a13c2afed751429c55d79c9304d727a01bdbd93c69381021f4b8718fa6de612e8930ae5db4547dc475c2cb736767adf2e546838776aaa756e5b00a2a8f767958cc2143924b17c77f38406463e9a331876adab323bfe7b9ab4d8fa82630e6b26e5f1db7232c7614896b7b6c2941f96ebeae81721f905fe5bfa94f1f0a9bd715508cc94fdf4bff504609a8d14495dc5bc04ce078e6b3afe0763b475a6d96278829f57d02089f278f8885726d9c84773950dbb3ec920a995153841552c04d00010ae05f0d48eb5e2e425219af7b4042e705e30f45a4f1e603268676dfd92b5cad9d5b17c3df3d93dc8142d12efddc921370d8d82b9e6aad2092103d4bcc70f6cb5b08a4ea64998eea8eefda9df7a94b896eb7ee3d34b551271e8a20e858c8dce65e3a1deba9f6091ca41aa7f64df41600cf0d0e92a612fff43123ee9ad8bcf7eefad286f52956140d3f513e115d646d11ae53331e2ae9e596b373e4e92954214f31bbc0cf6c5f0fa02b0d443bd275308c3860bd57989634ee0139ee0da918b53aef583e9c7861a1793f5700e901fac3648f092208740b8712fb5a824ba445c683a6e8b0ef673d9ad23e13650adb4c5c12578ba164d4a5b4b0bc2860f5bd35eabe64e1f686a80003da92b27cc44868b4bb001344ebbafabdd50b5483174c9d2167213e72517d0243c1caa77c2860a29d4dc304d10e18873d896fb88b0d33dbe897990a212a1ad049159aaec91feeab14e8c70cff10e908b53f8632f49bd72c5b7cf9a448e687480e2753f3530b6d4c5a8ea6c7af49ccb1b5c7bf8ec7a8d069c86dfdecc2de5e3bae740facf9e2d657780c00b3fa369df7de8774fd5fd9450b35b8088dbbbd9c237a7fbd95c78945c844733a984c717400c85ddd99fba860172d47056a69edeef55759be0e0d7a979a31c9fa3ac6ef987c6ce7210b6848c730b60a02e83981d7a892023d425c922f0116fe8282e655c348ac5b8b7a9ffa4b5317fb8cbc3424d7ef55ac80665417f100ee30879d15b3c63842cfee5ad6d5826da29a9a837a671d67c77eaf6e44fd2c4873b7e4a30137112962ea3f815379c4c9a9b70d3c7db9d94c3fa180d475321cb0623ebdd02c34116628826811de0305639deb369b15c4ae3a49842129c25c4167f33252665f062e5ef0c3d2ac5227fa790501852d9855773c6e36011293abe3b4fb808e93a604469e1af5f92ced04a6aa2d80e22f378a3e14fb8e9a16e05961de4099c9d9eb70f2058628cfb3334a5e0428da8d8c9826058748795a5b07ee98f89f5bd4e0c781c6edc2840c452f6a7fba5eb309b9ad811bc9894750499fc85e6c0d71f614ac6d0497df1dbd80da49ade1c76019b88beb02697992e1bfce659e27e8e50b780c839f0cd5e4ce6893fa30e54693b244486e7d6b23da430d9ffd5d2bf0a574e883775e27fae0125fc7d0007783892dcb2887f8eca8c68bba7156988a30928009f7ccda4086f48ab439f49697168ae8b104d9dde8680ad0bdafa5288f7199e2e08cf1a57ac693e168717ce24dbb0681b18abe59621bfc62c9d5bce90e7f8a4c0b75ff061e8846f7aaeafabc0fa95387216f934bda21194adad1594e094e69f35fccb1f6634082c13c615b5ae5a04d20cde44aca204eba0864aa19808ae9a06300534ff61457449f6e132f7aa85b19c19dbe2324ba9d4eaa0a4d2786108dbaf45c4ec9f50dc561fd31626da0d6791cf05b6605557fd61b9493146268d1b02866d42cd8789849144d691400061b7ba0d1430dc4309ee8aa77f6945b4975de0a25e50fa7bdc2daa3c4fc6017904a3bba5307a41fb17b519524154dbb4b64ae9051e8af5d573154143c77cde9dd89145f29df24226b7d47bba167bc956e7ec50378104d5bf798221d674217f1b2dca79aaba145096a88f13b1f2c6c68d9d9c7ed0ab69a28f35ad2b3a1487"
    d = {"platform": "Windows", "sdkVersion": "4.3.3", "svn": "2",
         "profileData": enc_hex}
    resp = req_post(ck, a1, lts, url_text, d, uri)
    print(resp.json())
