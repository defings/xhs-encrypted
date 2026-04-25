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
        "x22": "4d48070a3c236ee5469cf56saba2b3fe", "x23": "false", "x24": "false", "x25": "false", "x26": "false",
        "x27": "false", "x28": "0,false,false", "x29": "4,7,8", "x30": "swf object not loaded",
        "x31": "124.04347527516074", "x33": "0", "x34": "0", "x35": "0", "x36": "3",
        "x37": "0|0|0|0|0|0|0|0|0|1|0|0|0|0|0|0|0|0|1|0|0|0|0|0",
        "x38": "0|0|1|0|1|0|0|0|0|0|1|0|1|0|1|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0", "x39": "1310",
        "x40": "0", "x41": "0", "x42": "3.4.5", "x43": "2e2c912c", "x44": x44,
        "x45": "__SEC_CAV__1-1-1-1-1|", "x46": "false", "x47": "0|0|0|0|0|1", "x48": "", "x49": "{list:[],type:}",
        "x50": "", "x51": "", "x52": "", "x54": "11311144241322244122",
        "x55": "700,700,700,800,700,820,660,660,700,640,720,760,840,860", "x53": "bbvfdfa465c9bd61c524ea7740c3d726",
        "x56": "Google Inc. (Intel)|ANGLE (Intel, Intel(R) HD Graphics 4600 (0x00000412) Direct3D11 vs_5_0 ps_5_0, D3D11)|0ebc53d03eas9d69525d81de558e2544|55",
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
    b = json.dumps(payload, separators=(',', ':'), ensure_ascii=False)
    return EncryptProfileData(b)

