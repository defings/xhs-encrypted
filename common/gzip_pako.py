from __future__ import annotations

import time
import zlib
from typing import Sequence


# =========================
# 基础工具
# =========================

def _u32_le(n: int) -> bytes:
    n &= 0xFFFFFFFF
    return n.to_bytes(4, "little")


def _u32_from_le(b: bytes) -> int:
    if len(b) != 4:
        raise ValueError("need exactly 4 bytes")
    return int.from_bytes(b, "little", signed=False)


def to_int_list(b: bytes) -> list[int]:
    return list(b)


# =========================
# 压缩（对齐 pako）
# =========================

def deflate_raw_pako_like(
    data: bytes,
    level: int = zlib.Z_DEFAULT_COMPRESSION
) -> bytes:
    """
    对齐 pako.Deflate({ raw: true, level: -1 })
    """
    c = zlib.compressobj(
        level=level,
        method=zlib.DEFLATED,
        wbits=-15,  # raw deflate
        memLevel=8,
        strategy=zlib.Z_DEFAULT_STRATEGY,
    )
    return c.compress(data) + c.flush(zlib.Z_FINISH)


def gzip_pako(
    data: bytes,
    *,
    mtime: int = int(time.time()),
    level: int = zlib.Z_DEFAULT_COMPRESSION,
    xfl: int = 0,
    os_byte: int = 3,  # Unix
) -> bytes:
    """
    [gzip header] + [raw deflate] + [crc32] + [isize]
    """
    header = bytes([
        0x1F, 0x8B,  # magic
        0x08,        # deflate
        0x00,        # FLG
    ]) + _u32_le(mtime) + bytes([
        xfl & 0xFF,
        os_byte & 0xFF,
    ])

    body = deflate_raw_pako_like(data, level=level)

    crc32 = zlib.crc32(data) & 0xFFFFFFFF
    isize = len(data) & 0xFFFFFFFF
    trailer = _u32_le(crc32) + _u32_le(isize)

    return header + body + trailer


# =========================
# 解压（对应 gzip_pako）
# =========================

def inflate_raw_pako_like(data: bytes) -> bytes:
    """
    raw deflate 解压（对应 deflate_raw_pako_like）
    """
    d = zlib.decompressobj(wbits=-15)
    out = d.decompress(data)
    out += d.flush()

    if d.unused_data:
        raise ValueError("extra data after raw deflate stream")

    return out


def ungzip_pako(
    gz: bytes | Sequence[int],
    *,
    verify: bool = True,
) -> bytes:
    """
    解析 gzip_pako 生成的数据

    限制：
    - FLG = 0
    - 单 member
    """
    if not isinstance(gz, (bytes, bytearray)):
        gz = bytes(gz)
    else:
        gz = bytes(gz)

    if len(gz) < 18:
        raise ValueError("invalid gzip data")

    # --- header ---
    if gz[0] != 0x1F or gz[1] != 0x8B:
        raise ValueError("bad gzip magic")

    if gz[2] != 0x08:
        raise ValueError("unsupported method")

    flg = gz[3]
    if flg != 0:
        raise NotImplementedError("only FLG=0 supported")

    body_start = 10
    body_end = len(gz) - 8

    body = gz[body_start:body_end]
    crc_expect = _u32_from_le(gz[body_end:body_end + 4])
    isize_expect = _u32_from_le(gz[body_end + 4:body_end + 8])

    # --- 解压 ---
    data = inflate_raw_pako_like(body)

    # --- 校验 ---
    if verify:
        crc_actual = zlib.crc32(data) & 0xFFFFFFFF
        isize_actual = len(data) & 0xFFFFFFFF

        if crc_actual != crc_expect:
            raise ValueError("crc32 mismatch")

        if isize_actual != isize_expect:
            raise ValueError("isize mismatch")

    return data


if __name__ == "__main__":
    l = [3, 232, 0, 0, 1, 157, 169, 229, 73, 21, 3, 233, 156, 236, 115, 196,
         48, 217, 51, 51, 51, 35, 11, 5, 89, 80, 3, 86, 11, 74, 75, 0, 2, 88,
         95, 81, 87, 84, 48, 216, 123, 80, 150, 118, 55, 40, 51, 55, 47, 51,
         55, 46, 51, 55, 45, 51, 55, 44, 51, 55]

    raw = bytes(l)

    # 压缩
    gz = gzip_pako(
        raw,
        mtime=1776671871,
        level=zlib.Z_DEFAULT_COMPRESSION,
    )

    print("gzip bytes:", to_int_list(gz))
    print("len =", len(gz))

    # 解压
    decoded = ungzip_pako(gz)
    print("decoded == raw ?", decoded == raw)