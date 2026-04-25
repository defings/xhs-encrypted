import random
import time
import xxhash

PAYLOAD_ARRAY_HEADER = [3, 232, 0, 0]

RANDOM_STRING = "0123456789abcdefghijklmnopqrstuvwxyz"
EBV_DIC = {"1000": "Timestamp", "1001": "Xorkeyverifyvalue", "1002": "Uuid", "1003": "RequestHash",
           "1051": "PhantomjsV1",
           "1052": "PhantomjsV2", "1053": "ChromedriverV1", "1054": "ChromedriverV2", "1055": "ChromedriverV3",
           "1056": "ChromedriverV4", "1057": "CDPV1", "1058": "UndetectedChromeDriverV1", "1059": "PlayWrightV1",
           "1060": "PlayWrightV2", "1061": "PlayWrightV3", "1062": "CrawleeV1", "1063": "CefBrowserV1",
           "1064": "PuppteerV1",
           "1065": "SeleniumV1", "1066": "DrissionRunV1", "1067": "AnonymousReadyStateV1",
           "1068": "DrissionAutomationV1",
           "1069": "DrissionAutomationV2", "1070": "BrowserUseV1", "1071": "isStealthV1", "1072": "isCodeBeautify",
           "1073": "stealthJs", "1074": "mouseEvent", "1075": "MouseBaseX", "1076": "MouseBaseY",
           "1077": "MouseBaseTime",
           "1078": "MouseData", "1079": "TouchBaseX", "1080": "TouchBaseY", "1081": "TouchBaseTime",
           "1082": "TouchData",
           "1083": "KeyboardBaseTime", "1084": "KeyboardData", "1085": "WheelBaseX", "1086": "WheelBaseY",
           "1087": "WheelBaseTime", "1088": "WheelData", "1089": "FocusBaseTime", "1090": "FocusData",
           "1091": "SignCostTime",
           "1100": "FieldAbnormal", "1151": "HpIconCloseClick", "1152": "HpIconSearchClick", "1153": "HpIconInputClick",
           "1154": "HpChannelClick", "1155": "HpFilterClick", "1156": "HpCreatorTabClick", "Timestamp": 1000,
           "Xorkeyverifyvalue": 1001, "Uuid": 1002, "RequestHash": 1003, "PhantomjsV1": 1051, "PhantomjsV2": 1052,
           "ChromedriverV1": 1053, "ChromedriverV2": 1054, "ChromedriverV3": 1055, "ChromedriverV4": 1056,
           "CDPV1": 1057,
           "UndetectedChromeDriverV1": 1058, "PlayWrightV1": 1059, "PlayWrightV2": 1060, "PlayWrightV3": 1061,
           "CrawleeV1": 1062,
           "CefBrowserV1": 1063, "PuppteerV1": 1064, "SeleniumV1": 1065, "DrissionRunV1": 1066,
           "AnonymousReadyStateV1": 1067,
           "DrissionAutomationV1": 1068, "DrissionAutomationV2": 1069, "BrowserUseV1": 1070, "isStealthV1": 1071,
           "isCodeBeautify": 1072, "stealthJs": 1073, "mouseEvent": 1074, "MouseBaseX": 1075, "MouseBaseY": 1076,
           "MouseBaseTime": 1077, "MouseData": 1078, "TouchBaseX": 1079, "TouchBaseY": 1080, "TouchBaseTime": 1081,
           "TouchData": 1082, "KeyboardBaseTime": 1083, "KeyboardData": 1084, "WheelBaseX": 1085, "WheelBaseY": 1086,
           "WheelBaseTime": 1087, "WheelData": 1088, "FocusBaseTime": 1089, "FocusData": 1090, "SignCostTime": 1091,
           "HpIconCloseClick": 1151, "HpIconSearchClick": 1152, "HpIconInputClick": 1153, "HpChannelClick": 1154,
           "HpFilterClick": 1155, "HpCreatorTabClick": 1156, "FieldAbnormal": 1100}


def encode_events(events):
    """
    events: List[[flag:int, timestamp:int]]

    return:
        {
            "baseTime": int,
            "data": {index: byte}
        }
    """
    if not events:
        return {"baseTime": 0, "data": {}}

    base_time = events[0][1]

    buf = []

    for flag, ts in events:
        delta = ts - base_time

        # 限制在 uint16
        delta = max(0, min(delta, 0xFFFF))

        buf.append(flag & 0xFF)  # uint8
        buf.append((delta >> 8) & 0xFF)  # 高字节（大端）
        buf.append(delta & 0xFF)  # 低字节

    data_obj = {i: b for i, b in enumerate(buf)}

    return {
        "baseTime": base_time,
        "data": data_obj
    }


def decode_events(base_time, data_obj):
    """
    base_time: int
    data_obj: {index: byte}

    return:
        List[[flag, timestamp]]
    """
    # 按顺序恢复 byte 数组
    buf = [data_obj[i] for i in sorted(data_obj.keys(), key=int)]

    events = []

    for i in range(0, len(buf), 3):
        flag = buf[i]
        delta = (buf[i + 1] << 8) | buf[i + 2]  # 大端 uint16
        ts = base_time + delta

        events.append([flag, ts])

    return events


def creat_x_rap_param_payload(req_info: str) -> list[int]:
    """
    创建x-arp-param原始数组
    :param req_info: 请求信息，请求路径+body，例如//edith.xiaohongshu.com/api/sns/web/v1/homefeed{"cursor_score":"","num":18,"refresh_type":1,"note_index":35,"unread_begin_note_id":"","unread_end_note_id":"","unread_note_count":0,"category":"homefeed_recommend","search_key":"","need_num":8,"image_formats":["jpg","webp","avif"],"need_filter_image":false}
    :return:
    """
    # 大端表示
    to_be = lambda n, r=4: [(n >> (i * 8)) & 0xff for i in range(r)][::-1]
    # 生成随机iv
    random_string = lambda length: ''.join([random.choice(RANDOM_STRING) for i in range(length)])
    aes_iv = random_string(16)

    # 生成负载
    payload_array = []
    # step1: 添加标识头
    payload_array.extend(PAYLOAD_ARRAY_HEADER)
    # step2: 添加时间戳
    now = int(time.time() * 1000)
    payload_array.extend(to_be(now, 6))
    # step3: 添加异或标识摘要
    xor_key = random_string(1)
    xor_key_ascii = ord(xor_key)
    xor_key_xxhash = xxhash.xxh32(xor_key)
    temp_array = []
    temp_array.extend([3, 233])
    temp_array.extend(list(xor_key_xxhash.digest()))
    payload_array.extend(temp_array)
    temp_array = []
    # step4: 携带随机iv
    temp_array = [i ^ xor_key_ascii for i in to_be(EBV_DIC["Uuid"], 2)]
    temp_array.extend([i ^ xor_key_ascii for i in to_be(len(aes_iv), 4)])
    temp_array.extend([ord(c) ^ xor_key_ascii for c in aes_iv])
    payload_array.extend(temp_array)
    temp_array = []
    # step5: req_info的xxhash32摘要
    req_info_xxhash = xxhash.xxh32(req_info.encode("utf8"))
    temp_array = [i ^ xor_key_ascii for i in to_be(EBV_DIC["RequestHash"], 2)]
    temp_array.extend([i ^ xor_key_ascii for i in req_info_xxhash.digest()])
    payload_array.extend(temp_array)
    temp_array = []
    # step5: 环境监测点填充
    env_list = ["PhantomjsV1", "PhantomjsV2", "ChromedriverV1", "ChromedriverV2", "ChromedriverV3", "ChromedriverV4",
                "CDPV1", "UndetectedChromeDriverV1", "PlayWrightV1", "PlayWrightV2", "PlayWrightV3", "CrawleeV1",
                "CefBrowserV1", "PuppteerV1", "SeleniumV1", "BrowserUseV1", "DrissionRunV1", "AnonymousReadyStateV1",
                "DrissionAutomationV1", "DrissionAutomationV2"]
    for env in env_list:
        env_array = [i ^ xor_key_ascii for i in to_be(EBV_DIC[env], 2)]
        env_array.append(xor_key_ascii)
        temp_array.extend(env_array)
    payload_array.extend(temp_array)
    temp_array = []

    temp_array.extend([i ^ xor_key_ascii for i in to_be(EBV_DIC["FieldAbnormal"], 2)])
    temp_array.extend([xor_key_ascii for _ in range(4)])
    payload_array.extend(temp_array)
    temp_array = []

    env_list = ["isStealthV1", "isCodeBeautify", "stealthJs"]
    for env in env_list:
        env_array = [i ^ xor_key_ascii for i in to_be(EBV_DIC[env], 2)]
        env_array.append(xor_key_ascii)
        temp_array.extend(env_array)
    payload_array.extend(temp_array)
    temp_array = []

    env_list = ["MouseData", "TouchData", "KeyboardData", "WheelData"]
    for env in env_list:
        env_array = [i ^ xor_key_ascii for i in to_be(EBV_DIC[env], 2)]
        env_array.extend([xor_key_ascii for _ in range(4)])
        temp_array.extend(env_array)
    payload_array.extend(temp_array)
    temp_array = []

    now = int(time.time() * 1000)
    temp_array.extend([i ^ xor_key_ascii for i in to_be(EBV_DIC["FocusBaseTime"], 2)])
    temp_array.append(xor_key_ascii)
    temp_array.append(xor_key_ascii)
    temp_array.extend([i ^ xor_key_ascii for i in to_be(now, 6)])
    payload_array.extend(temp_array)
    temp_array = []

    temp_array.extend([i ^ xor_key_ascii for i in to_be(EBV_DIC["FocusData"], 2)])
    temp_array.extend([i ^ xor_key_ascii for i in to_be(random.randint(1, 100), 4)])
    time_locus = [[1, now], [0, now + random.randint(100, 999)], [1, now + random.randint(100, 999)]]
    time_locus_encode_dic = encode_events(time_locus)
    temp_array.extend([i ^ xor_key_ascii for i in time_locus_encode_dic["data"].values()])
    payload_array.extend(temp_array)
    temp_array = []

    temp_array.extend([i ^ xor_key_ascii for i in to_be(EBV_DIC["SignCostTime"], 2)])
    temp_array.extend([i ^ xor_key_ascii for i in to_be(random.randint(1, 100), 4)])
    temp_array.extend([i ^ xor_key_ascii for i in to_be(65535, 4)])
    payload_array.extend(temp_array)
    temp_array = []

    env_list = ["HpIconCloseClick", "HpIconSearchClick", "HpIconInputClick", "HpChannelClick", "HpFilterClick",
                "HpCreatorTabClick"]
    for env in env_list:
        env_array = [i ^ xor_key_ascii for i in to_be(EBV_DIC[env], 2)]
        env_array.append(xor_key_ascii)
        temp_array.extend(env_array)
    payload_array.extend(temp_array)

    return payload_array
