import base64
import random
import time
import zlib

import xxhash

from common.aes_128_ecb import AES128CustomSBox
from common.generate_x_rap_param_payload import creat_x_rap_param_payload
from common.gzip_pako import gzip_pako

MARK_X_RAP_PARAM = [7, 36, 1, 5]
SDK_VERSION_X_RAP_PARAM = 10100
PROTOCOL_VERSION = 1
RANDOM_STRING = "0123456789abcdefghijklmnopqrstuvwxyz"


def creat_x_rap_param(req_info: str) -> str:
    """
    创建x-arp-param原始数组
    :param req_info: 请求信息，请求路径+body，例如//edith.xiaohongshu.com/api/sns/web/v1/homefeed{"cursor_score":"","num":18,"refresh_type":1,"note_index":35,"unread_begin_note_id":"","unread_end_note_id":"","unread_note_count":0,"category":"homefeed_recommend","search_key":"","need_num":8,"image_formats":["jpg","webp","avif"],"need_filter_image":false}
    :return:
    """
    # 生成原始负载
    payload_array = creat_x_rap_param_payload(req_info)
    #TODO 压缩，注意在底层Python zlib由C实现，而pako则是由js实现，所以输出有差异,除非版本、内部实现完全一致(现实基本不可能)
    decoded_data = gz = gzip_pako(
        bytes(payload_array),
        level=zlib.Z_DEFAULT_COMPRESSION,
        xfl=0,
        os_byte=3,
    )
    decoded_data_len = len(decoded_data)

    # aes-cbc模式中iv异或
    random_string = lambda length: ''.join([random.choice(RANDOM_STRING) for i in range(length)])
    cbc_iv = random_string(16).encode("utf-8")
    cbc_text = b''.join(
        bytes(b ^ k for b, k in zip(decoded_data[i:i + 16], cbc_iv))
        for i in range(0, len(decoded_data), 16)
    )
    cbc_text = list(cbc_text)

    # 进行aes-ebc模式
    aes = AES128CustomSBox(None, None)
    if len(cbc_text) % 16 != 0:
        padding = 16 - len(cbc_text) % 16
        cbc_text.extend([0 for _ in range(padding)])
    pt = []
    for i in range(0, len(cbc_text), 16):
        block = cbc_text[i:i + 16]
        pt.extend(list(aes.encrypt_block(bytes(block), None)))
    to_be = lambda n, r=4: [(n >> (i * 8)) & 0xff for i in range(r)][::-1]
    pt.extend(to_be(decoded_data_len))

    # 给负载加盐
    temp = []
    temp.extend(list(random_string(5).encode("utf-8")))
    cbc_iv_en = list(aes.encrypt_block(cbc_iv, None))
    cbc_iv_en.extend(to_be(len(cbc_iv_en)))
    temp.extend(cbc_iv_en)
    temp.extend(pt)

    # 生成负载摘要
    payload_xxhash = xxhash.xxh32(bytes(temp)).digest()

    res_arr = []
    res_arr.extend(MARK_X_RAP_PARAM)
    res_arr.extend(to_be(PROTOCOL_VERSION))
    res_arr.extend(to_be(len(cbc_iv_en)))
    res_arr.extend(to_be(len(pt)))
    res_arr.extend(payload_xxhash)
    res_arr.extend(to_be(SDK_VERSION_X_RAP_PARAM))
    res_arr.extend(to_be(random.randint(800, 1500)))
    while len(res_arr) != 36:
        res_arr.append(0)
    res_arr.extend(temp)

    return base64.b64encode(bytes(res_arr)).decode("utf-8")


if __name__ == '__main__':
    print(creat_x_rap_param('//edith.xiaohongshu.com/api/sns/web/v1/homefeed{"cursor_score":"","num":18,"refresh_type":1,"note_index":35,"unread_begin_note_id":"","unread_end_note_id":"","unread_note_count":0,"category":"homefeed_recommend","search_key":"","need_num":8,"image_formats":["jpg","webp","avif"],"need_filter_image":false}'))
