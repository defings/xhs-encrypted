# 小红书加密参数工具集

本项目是小红书(xiaohongshu.com)相关加密参数的解密/加密实现集合，包含了平台常见的X-s, X-S-common, X-Rap-Param,
ProfileData等多种加密参数的解析和生成算法。

## 功能列表

### X-s 加密算法实现

| 文件名            | 功能描述              |
|----------------|-------------------|
| **mns0101.py** | mns0101自定义加密/解密算法 |
| **mns0201.py** | mns0201自定义加密/解密算法 |
| **mns0301.py** | mns0301自定义加密/解密算法 |

### 工具函数

| 文件名          | 功能描述                                    |
|--------------|-----------------------------------------|
| **other.py** | 各类ID生成工具：trace_id、request_id、search_id等 |
| **a1.py**    | cookie中的a1参数生成                          |

## 目录结构

```
├── common/                 # 通用加密工具库
│   ├── aes_128_ecb.py      # AES-128-ECB自定义S盒实现
│   ├── arx_custom.py       # 自定义ARX加密算法
│   ├── base58_xs.py        # xs参数专用Base58编解码
│   ├── base64_x3.py        # x3参数专用Base64编解码
│   ├── base64_xsc.py       # x-s-common参数专用Base64编解码
│   ├── crc32_xsc.py        # x-s-common参数专用CRC32计算
│   ├── generate_bit_arr.py # x-s payload生成
│   ├── generate_x_rap_param_payload.py # X-Rap-Param payload生成
│   ├── gzip_pako.py        # Gzip压缩/解压缩工具
│   ├── xs_xxtea.py         # XXTEA加密算法实现
│   └── __init__.py
├── js/                  
│   └── crc.js              # CRC算法JS实现
├── a1.py
├── base58.py
├── decode_x_rap_param.py
├── mns0101.py
├── mns0201.py
├── mns0301.py
├── other.py
├── profile_data.py
├── x_rap_param.py
└── xs解码.py
```

## 快速开始

```python


import json
import uuid

from common.generate_bit_arr import generate_xs_bit_arr
from mns0101 import mns0101_encrypt
from mns0201 import mns0201_encrypt
from mns0301 import mns0301_encrypt
from common.base64_xsc import custom_b64_encode
from common.crc32_xsc import xs_common_crc32
from other import *
from profile_data import GetProfileData
import requests

HEADER = {
    "accept": "application/json, text/plain, */*",
    "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    "cache-control": "no-cache",
    "origin": "https://www.xiaohongshu.com",
    "pragma": "no-cache",
    "priority": "u=1, i",
    "referer": "https://www.xiaohongshu.com/",
    "sec-ch-ua": '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-site",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    "xy-direction": "83",
    "content-type": "application/json;charset=UTF-8",
    "Connection": "keep-alive"
}

B1 = 'I38rHdgsxxxxxxxxxxxxxxxxxxx'
WEB_BUILD = "6.3.0"
SDK_VERSION = "4.3.3"


def req_get(c: str, a: str, load_ts: int, url_text: str, uri: str, x1: str = "xhs-pc-web") -> requests.Response:
    """
    get请求
    :param x1:
    :param c: 请求ck
    :param a: ck中的a1参数
    :param load_ts: ck中的loadts
    :param url_text: 请求路径
    :param uri: 请求地址前缀
    :param proxy_name: 请求代理
    :return:
    """
    xs_arr = generate_xs_bit_arr(url_text, "", load_ts, a)
    xs_x3 = mns0301_encrypt(xs_arr)
    xs_body = {
        "x0": SDK_VERSION,
        "x1": x1,
        "x2": "Windows",
        "x3": xs_x3,
        "x4": "object"
    }
    xs = "XYS_" + custom_b64_encode(json.dumps(xs_body).replace(" ", "").encode("utf8"))
    xs_common_body = {
        "s0": 5,
        "s1": "",
        "x0": "1",
        "x1": SDK_VERSION,
        "x2": "Windows",
        "x3": x1,
        "x4": WEB_BUILD,
        "x5": a,
        "x6": "",
        "x7": "",
        "x8": B1,
        "x9": xs_common_crc32()(B1),
        "x10": 0,
        "x11": "normal",
        "x12": f"dsllt={int(time.time() * 1000)}"
    }
    xs_common = custom_b64_encode(json.dumps(xs_common_body).replace(" ", "").encode("utf8"))

    HEADER["x-b3-traceid"] = generate_trace_id()
    HEADER["x-s"] = xs
    HEADER["x-s-common"] = xs_common
    HEADER["x-t"] = str(int(time.time() * 1000))
    HEADER["x-xray-traceid"] = generate_trace_id()

    HEADER["cookie"] = c

    resp = requests.get(uri + url_text, headers=HEADER, allow_redirects=False)
    return resp


def req_post(c: str, a: str, load_ts: int, url_text: str, data_body: dict, uri: str,
             x1: str = "xhs-pc-web") -> requests.Response:
    """
    post请求
    :param x1:
    :param c: 请求ck
    :param a: ck中的a1参数
    :param load_ts: ck中的loadts
    :param url_text: 请求路径
    :param data_body: 请求体
    :param uri: 请求地址前缀
    :param proxy_name: 请求代理
    :return:
    """
    xs_arr = generate_xs_bit_arr(url_text, json.dumps(data_body).replace(" ", ""), load_ts, a)
    xs_x3 = mns0301_encrypt(xs_arr)
    xs_body = {
        "x0": SDK_VERSION,
        "x1": x1,
        "x2": "Windows",
        "x3": xs_x3,
        "x4": "object"
    }
    xs = "XYS_" + custom_b64_encode(json.dumps(xs_body).replace(" ", "").encode("utf8"))
    xs_common_body = {
        "s0": 5,
        "s1": "",
        "x0": "1",
        "x1": SDK_VERSION,
        "x2": "Windows",
        "x3": x1,
        "x4": WEB_BUILD,
        "x5": a,
        "x6": "",
        "x7": "",
        "x8": B1,
        "x9": xs_common_crc32()(B1),
        "x10": 0,
        "x11": "normal"
    }
    xs_common = custom_b64_encode(json.dumps(xs_common_body).replace(" ", "").encode("utf8"))
    HEADER["x-b3-traceid"] = generate_trace_id()
    HEADER["x-s"] = xs
    HEADER["x-s-common"] = xs_common
    HEADER["x-t"] = str(int(time.time() * 1000))
    HEADER["x-xray-traceid"] = generate_trace_id()

    HEADER["cookie"] = c

    resp = requests.post(uri + url_text, headers=HEADER, data=json.dumps(data_body).replace(" ", ""),
                         allow_redirects=False)
    return resp

```

## 注意事项

1. 本项目仅用于学习和研究目的，请勿用于非法用途
2. 小红书平台加密算法可能随时更新，本项目不保证长期可用性
3. 使用本项目产生的任何后果由使用者自行承担

## 关注公众号，解锁纯算手扣详细教程

![](./image/扫码_搜索联合传播样式-白色版.png)
