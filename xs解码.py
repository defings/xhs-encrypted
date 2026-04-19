import json

from common.base64_xsc import custom_b64_decode
from mns0301 import mns0301_decryption
from common.generate_bit_arr import reverse_xs_bit_arr
if __name__ == '__main__':
    xs = input("输入:")
    xs_decode = json.loads(custom_b64_decode(xs).decode('utf-8'))
    print(f"xs_decode ==> {xs_decode}")
    x3 = xs_decode["x3"]
    x3_decode = mns0301_decryption(x3)
    print(f"x3_decode ==> {x3_decode}")
    reverse_xs_bit_arr(x3_decode)