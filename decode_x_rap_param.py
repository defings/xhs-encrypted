from __future__ import annotations

import base64
import datetime
import gzip
import json

import xxhash

from common.aes_128_ecb import AES128CustomSBox
from common.generate_x_rap_param_payload import EBV_DIC, RANDOM_STRING, decode_events

MARK_X_RAP_PARAM = [7, 36, 1, 5]

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  字段类型分类表 —— 根据 EBV_DIC 的 field_id 决定解析方式
#
#  格式说明（每个字段前 2 字节固定是 XOR'd field_id）：
#    TYPE_FLAG_1B   : + 1 字节标志位              (总 3 字节)
#    TYPE_VALUE_4B  : + 4 字节整型值              (总 6 字节)
#    TYPE_TLV_STR   : + 4 字节长度 + N 字节字符串  (总 2+4+N 字节)
#    TYPE_HASH_4B   : + 4 字节哈希值              (总 6 字节)
#    TYPE_FOCUS_BASE: + 2 字节填充 + 6 字节时间戳  (总 10 字节)
#    TYPE_FOCUS_DATA: + 4 字节随机数 + 9 字节事件   (总 15 字节)
#    TYPE_SIGN_COST : + 4 字节随机数 + 4 字节值     (总 10 字节)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TYPE_FLAG_1B = "flag_1b"
TYPE_VALUE_4B = "value_4b"
TYPE_TLV_STR = "tlv_str"
TYPE_HASH_4B = "hash_4b"
TYPE_FOCUS_BASE = "focus_base"
TYPE_FOCUS_DATA = "focus_data"
TYPE_SIGN_COST = "sign_cost"


def _build_field_type_map() -> dict[int, str]:
    """根据 EBV_DIC 构建 field_id → 解析类型 的映射表"""
    m = {}

    # 1-byte 布尔/标志字段
    flag_1b_ids = (
        list(range(1051, 1075))       # PhantomjsV1 ~ mouseEvent
        + list(range(1151, 1157))      # HpIconCloseClick ~ HpCreatorTabClick
    )
    for fid in flag_1b_ids:
        m[fid] = TYPE_FLAG_1B

    # 4-byte 整型值字段
    value_4b_ids = [
        1100,  # FieldAbnormal
        1075,  # MouseBaseX
        1076,  # MouseBaseY
        1079,  # TouchBaseX
        1080,  # TouchBaseY
        1085,  # WheelBaseX
        1086,  # WheelBaseY
    ]
    for fid in value_4b_ids:
        m[fid] = TYPE_VALUE_4B

    # TLV 字符串字段
    m[1002] = TYPE_TLV_STR   # Uuid

    # 4-byte 哈希字段
    m[1003] = TYPE_HASH_4B   # RequestHash

    # BaseTime 类型字段 (2填充 + 6时间戳 = 8字节体)
    base_time_ids = [1077, 1081, 1083, 1087, 1089]
    # MouseBaseTime, TouchBaseTime, KeyboardBaseTime, WheelBaseTime, FocusBaseTime
    for fid in base_time_ids:
        m[fid] = TYPE_FOCUS_BASE

    # Data 类型字段 (4字节随机数 + N×3字节事件, 可变长)
    data_field_ids = [1078, 1082, 1084, 1088, 1090]
    # MouseData, TouchData, KeyboardData, WheelData, FocusData
    for fid in data_field_ids:
        m[fid] = TYPE_FOCUS_DATA

    # 特殊结构字段
    m[1091] = TYPE_SIGN_COST   # SignCostTime

    return m


FIELD_TYPE_MAP = _build_field_type_map()


# ━━━━━━━━━━━━━━━━━━━━━━  基础工具函数  ━━━━━━━━━━━━━━━━━━━━━━━━━

def _from_be(data, length: int = 4) -> int:
    """大端字节 → 整数"""
    val = 0
    for b in data[:length]:
        val = (val << 8) | b
    return val


def _recover_xor_key(xor_hash_bytes: bytes) -> str:
    """暴力枚举 36 个候选字符，找到 xxhash32 匹配的 xor_key"""
    for ch in RANDOM_STRING:
        if xxhash.xxh32(ch).digest() == xor_hash_bytes:
            return ch
    raise ValueError("无法恢复 xor_key，数据可能损坏")


def _xor_list(data, xk: int) -> list[int]:
    return [b ^ xk for b in data]


def _ts_readable(ms: int) -> str:
    return datetime.datetime.fromtimestamp(ms / 1000.0).strftime("%Y-%m-%d %H:%M:%S.%f")


def _field_name(fid: int) -> str:
    return EBV_DIC.get(str(fid), f"Unknown({fid})")


# ━━━━━━━━━━━━━━  外层解码 (base64 → gzip payload)  ━━━━━━━━━━━━━

def decode_outer(b64_str: str) -> dict:
    raw = base64.b64decode(b64_str)
    data = list(raw)

    mark = data[0:4]
    protocol_version = _from_be(data[4:8])
    cbc_iv_en_len = _from_be(data[8:12])
    pt_len = _from_be(data[12:16])
    xxhash_digest = bytes(data[16:20])
    sdk_version = _from_be(data[20:24])
    random_duration = _from_be(data[24:28])

    temp = data[36:]
    temp_bytes = bytes(temp)
    hash_ok = (xxhash.xxh32(temp_bytes).digest() == xxhash_digest)

    # MARK[3] 决定 salt 长度: v5(=5) → 5字节, v6(=6) → 6字节
    mark_sub = mark[3]
    salt_len = mark_sub  # v5→5, v6→6
    salt = bytes(temp[0:salt_len]).decode("utf-8")

    cbc_iv_en = temp[salt_len:salt_len + cbc_iv_en_len]
    encrypted_iv_block = bytes(cbc_iv_en[:16])

    pt_start = salt_len + cbc_iv_en_len
    pt = temp[pt_start:pt_start + pt_len]

    aes = AES128CustomSBox(None, None)
    cbc_iv = aes.decrypt_block(encrypted_iv_block, None)

    original_data_len = _from_be(pt[-4:])
    encrypted_blocks = bytes(pt[:-4])

    decrypted = bytearray()
    for i in range(0, len(encrypted_blocks), 16):
        decrypted.extend(aes.decrypt_block(encrypted_blocks[i:i + 16], None))

    gzip_data = bytearray()
    for i in range(0, len(decrypted), 16):
        chunk = decrypted[i:i + 16]
        gzip_data.extend(b ^ k for b, k in zip(chunk, cbc_iv))
    gzip_data = bytes(gzip_data[:original_data_len])

    payload_bytes = gzip.decompress(gzip_data)

    return {
        "mark": mark,
        "protocol_version": protocol_version,
        "sdk_version": sdk_version,
        "random_duration_ms": random_duration,
        "xxhash_ok": hash_ok,
        "salt": salt,
        "cbc_iv": cbc_iv.decode("utf-8"),
        "original_gzip_len": original_data_len,
        "payload_bytes": list(payload_bytes),
    }


# ━━━━━━━━━━━  内层解码 (payload_bytes → 可读字段)  ━━━━━━━━━━━━━

class PayloadReader:
    """带游标的 payload 读取器"""

    def __init__(self, data: list[int]):
        self.data = data
        self.pos = 0

    def read(self, n: int) -> list[int]:
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read_field_id(self, xk: int) -> int:
        """读取 2 字节 XOR'd field_id 并解码"""
        b = self.read(2)
        return ((b[0] ^ xk) << 8) | (b[1] ^ xk)


def _parse_field(reader: PayloadReader, xk: int) -> dict:
    """
    通用字段解析：读取 2 字节 field_id，根据类型表分派解析。
    返回 {"field_id": int, "field_name": str, "type": str, "value": ...}
    """
    fid = reader.read_field_id(xk)
    fname = _field_name(fid)
    ftype = FIELD_TYPE_MAP.get(fid)

    if ftype is None:
        raise ValueError(f"未知字段 ID={fid} (name={fname})，无法确定解析格式")

    if ftype == TYPE_FLAG_1B:
        val = reader.read(1)[0] ^ xk
        return {"field_id": fid, "field_name": fname, "type": ftype, "value": val}

    if ftype == TYPE_VALUE_4B:
        val = _from_be(_xor_list(reader.read(4), xk))
        return {"field_id": fid, "field_name": fname, "type": ftype, "value": val}

    if ftype == TYPE_TLV_STR:
        str_len = _from_be(_xor_list(reader.read(4), xk))
        raw = _xor_list(reader.read(str_len), xk)
        val = ''.join(chr(c) for c in raw)
        return {"field_id": fid, "field_name": fname, "type": ftype, "value": val}

    if ftype == TYPE_HASH_4B:
        val = bytes(_xor_list(reader.read(4), xk)).hex()
        return {"field_id": fid, "field_name": fname, "type": ftype, "value": val}

    if ftype == TYPE_FOCUS_BASE:
        # 2 字节填充 + 6 字节时间戳
        _xor_list(reader.read(2), xk)  # padding (0,0)
        ts = _from_be(_xor_list(reader.read(6), xk), 6)
        return {"field_id": fid, "field_name": fname, "type": ftype,
                "value": {"时间戳(ms)": ts, "时间戳(可读)": _ts_readable(ts)}}

    if ftype == TYPE_FOCUS_DATA:
        # 4 字节随机数 + N×3 字节事件编码 (事件数量可变)
        rand_val = _from_be(_xor_list(reader.read(4), xk))
        # 前探：逐 3 字节读取事件，直到下一组 2 字节解码出合法 field_id
        event_bytes = []
        while reader.remaining() >= 3:
            # 检查当前位置的 2 字节是否是下一个合法字段 ID
            peek_b0 = reader.data[reader.pos]
            peek_b1 = reader.data[reader.pos + 1]
            peek_fid = ((peek_b0 ^ xk) << 8) | (peek_b1 ^ xk)
            if peek_fid in FIELD_TYPE_MAP:
                break
            # 不是合法 field_id，这 3 字节属于事件数据
            event_bytes.extend(reader.read(3))
        event_raw = _xor_list(event_bytes, xk)
        event_dict = {i: v for i, v in enumerate(event_raw)}
        return {"field_id": fid, "field_name": fname, "type": ftype,
                "value": {"随机值": rand_val, "_event_raw": event_dict}}

    if ftype == TYPE_SIGN_COST:
        # 4 字节随机耗时 + 4 字节固定值
        rand_val = _from_be(_xor_list(reader.read(4), xk))
        fixed_val = _from_be(_xor_list(reader.read(4), xk))
        return {"field_id": fid, "field_name": fname, "type": ftype,
                "value": {"随机耗时值": rand_val, "固定值": fixed_val}}

    raise ValueError(f"未处理的字段类型: {ftype}")


def decode_payload(payload: list[int]) -> dict:
    """
    泛化解析 payload_bytes：
      ① 固定头部 (10字节) + XOR区 (6字节)
      ② 循环读取字段ID → 查 EBV_DIC → 按类型表分派解析
    所有字段均解析为人类可读值，无残留字节数组。
    """
    reader = PayloadReader(payload)
    result = {}
    fields = []  # 按顺序记录所有解析出的字段

    # ────── 段1: 标识头 + 时间戳  (10字节) ──────
    header = reader.read(4)
    ts_bytes = reader.read(6)
    timestamp_ms = _from_be(ts_bytes, 6)
    result["标识头(PAYLOAD_ARRAY_HEADER)"] = header
    result["时间戳(ms)"] = timestamp_ms
    result["时间戳(可读)"] = _ts_readable(timestamp_ms)

    # ────── 段2: XOR标识 + 密钥摘要  (6字节) ──────
    xor_marker = reader.read(2)  # [3, 233]
    xor_hash = bytes(reader.read(4))
    xor_key_char = _recover_xor_key(xor_hash)
    xk = ord(xor_key_char)
    result["XOR标识"] = xor_marker
    result["XOR密钥字符"] = xor_key_char
    result["XOR密钥ASCII(操作码)"] = xk

    # ────── 段3..N: 循环读取所有字段 ──────
    # BaseTime → Data 对应关系: *BaseTime 的时间戳作为对应 *Data 的事件解码基准
    base_time_map = {
        1077: 1078,  # MouseBaseTime → MouseData
        1081: 1082,  # TouchBaseTime → TouchData
        1083: 1084,  # KeyboardBaseTime → KeyboardData
        1087: 1088,  # WheelBaseTime → WheelData
        1089: 1090,  # FocusBaseTime → FocusData
    }
    collected_base_ts = {}  # data_field_id → base_timestamp

    while reader.remaining() > 0:
        field = _parse_field(reader, xk)
        fid = field["field_id"]
        fname = field["field_name"]

        # 记录所有 *BaseTime 时间戳
        if fid in base_time_map:
            data_fid = base_time_map[fid]
            collected_base_ts[data_fid] = field["value"]["时间戳(ms)"]

        # *Data 字段事件解码 (适用于所有 TYPE_FOCUS_DATA 类型)
        if field["type"] == TYPE_FOCUS_DATA and "_event_raw" in field["value"]:
            event_dict = field["value"].pop("_event_raw")
            base_ts = collected_base_ts.get(fid, timestamp_ms)
            if len(event_dict) == 0:
                field["value"] = 0  # 无事件数据，显示为 0
            else:
                events = decode_events(base_ts, event_dict)
                decoded_events = []
                for flag, ts in events:
                    decoded_events.append({
                        "flag": flag,
                        "时间戳(ms)": ts,
                        "时间(可读)": _ts_readable(ts),
                    })
                field["value"]["事件列表"] = decoded_events

        fields.append(field)

    # ────── 按语义分组输出 ──────
    # 分组规则：基于字段ID范围
    group_auto_env = {}     # 自动化环境检测 (1051-1070)
    group_stealth = {}      # 隐身检测 (1071-1074)
    group_interaction = {}  # 交互数据 (1075-1091)
    group_hp_click = {}     # 页面点击 (1151-1156)
    group_other = {}        # 其他 (Uuid, RequestHash, FieldAbnormal 等)

    for f in fields:
        fid = f["field_id"]
        key = f"{f['field_name']}(ID={fid})"
        val = f["value"]

        if 1051 <= fid <= 1070:
            group_auto_env[key] = val
        elif 1071 <= fid <= 1074:
            group_stealth[key] = val
        elif 1075 <= fid <= 1091:
            group_interaction[key] = val
        elif 1151 <= fid <= 1156:
            group_hp_click[key] = val
        else:
            result[f"字段-{key}"] = val

    if group_auto_env:
        result["环境监测点-自动化检测"] = group_auto_env
    if group_stealth:
        result["环境监测点-隐身检测"] = group_stealth
    if group_interaction:
        result["交互数据"] = group_interaction
    if group_hp_click:
        result["交互事件-页面点击"] = group_hp_click

    if reader.remaining() > 0:
        result["剩余未解析字节"] = payload[reader.pos:]

    return result


def decode_payload_raw(payload: list[int]) -> list[dict]:
    """
    按段逐条解析 payload_bytes，返回与分割文件对应的段列表。
    每段输出: {"segment": 段序号, "raw_bytes": {...}, "decoded": {...}}
    """
    reader = PayloadReader(payload)
    segments = []

    # ── 段1: 标识头 + 时间戳 (10字节) ──
    raw = reader.read(10)
    header = raw[:4]
    ts_ms = _from_be(raw[4:], 6)
    segments.append({
        "segment": 1,
        "description": "标识头 + 时间戳",
        "raw_bytes": {i: v for i, v in enumerate(raw)},
        "decoded": {
            "标识头": header,
            "时间戳(ms)": ts_ms,
            "时间戳(可读)": _ts_readable(ts_ms),
        }
    })

    # ── 段2: XOR标识 + 密钥摘要 (6字节) ──
    raw = reader.read(6)
    xor_key_char = _recover_xor_key(bytes(raw[2:6]))
    xk = ord(xor_key_char)
    segments.append({
        "segment": 2,
        "description": "XOR标识 + 密钥摘要",
        "raw_bytes": {i: v for i, v in enumerate(raw)},
        "decoded": {
            "标识": list(raw[:2]),
            "XOR密钥字符": xor_key_char,
            "操作码": xk,
        }
    })

    # ── 段3..N: 逐字段解析 ──
    seg_idx = 3
    base_time_map = {
        1077: 1078, 1081: 1082, 1083: 1084, 1087: 1088, 1089: 1090,
    }
    collected_base_ts = {}

    while reader.remaining() > 0:
        start_pos = reader.pos
        field = _parse_field(reader, xk)
        end_pos = reader.pos
        fid = field["field_id"]

        raw_slice = payload[start_pos:end_pos]

        # 记录所有 *BaseTime 时间戳
        if fid in base_time_map:
            collected_base_ts[base_time_map[fid]] = field["value"]["时间戳(ms)"]

        # *Data 字段事件解码
        if field["type"] == TYPE_FOCUS_DATA and "_event_raw" in field["value"]:
            event_dict = field["value"].pop("_event_raw")
            base_ts = collected_base_ts.get(fid, ts_ms)
            if len(event_dict) == 0:
                field["value"] = 0
            else:
                events = decode_events(base_ts, event_dict)
                decoded_events = []
                for flag, ts in events:
                    decoded_events.append({
                        "flag": flag,
                        "时间戳(ms)": ts,
                        "时间(可读)": _ts_readable(ts),
                    })
                field["value"]["事件列表"] = decoded_events

        segments.append({
            "segment": seg_idx,
            "description": f"{field['field_name']}(ID={fid})",
            "raw_bytes": {i: v for i, v in enumerate(raw_slice)},
            "decoded": field["value"],
        })
        seg_idx += 1

    return segments


# ━━━━━━━━━━━━━━━━━━━━  完整解码入口  ━━━━━━━━━━━━━━━━━━━━━━━━━━━

def decode_x_rap_param(b64_str: str) -> dict:
    outer = decode_outer(b64_str)
    payload = outer.pop("payload_bytes")
    inner = decode_payload(payload)

    return {
        "=== 外层结构 (creat_x_rap_param) ===": {
            "标识头(MARK)": outer["mark"],
            "协议版本": outer["protocol_version"],
            "SDK版本": outer["sdk_version"],
            "随机延时(ms)": outer["random_duration_ms"],
            "XXHASH校验": "通过" if outer["xxhash_ok"] else "失败",
            "盐值(随机串)": outer["salt"],
            "CBC-IV(16字符随机串)": outer["cbc_iv"],
            "原始GZIP数据长度": outer["original_gzip_len"],
        },
        "=== 内层负载 (creat_x_rap_param_payload) ===": inner,
    }


if __name__ == "__main__":
    s = input("->")
    res = decode_x_rap_param(s)
    print(json.dumps(res, ensure_ascii=False))