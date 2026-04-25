from __future__ import annotations
from typing import List

CUSTOM_SBOX = [122, 1, 88, 224, 80, 78, 2, 121, 29, 75, 83, 218, 107, 72, 212, 82, 237, 119, 18, 33, 20, 21, 236,
               16, 24, 229, 185, 241, 12, 8, 252, 125, 249, 205, 181, 200, 230, 55, 38, 135, 86, 186, 184, 43, 173,
               240, 104, 247, 139, 141, 211, 94, 54, 77, 46, 146, 49, 130, 242, 41, 112, 61, 45, 215, 182, 64, 178,
               67, 68, 128, 120, 210, 13, 73, 74, 9, 99, 108, 7, 58, 158, 213, 6, 198, 225, 98, 244, 52, 36, 89,
               169, 87, 42, 0, 62, 23, 44, 10, 26, 66, 250, 147, 190, 220, 245, 179, 106, 19, 232, 3, 199, 151, 187,
               115, 118, 134, 227, 70, 114, 71, 208, 5, 76, 56, 124, 31, 129, 171, 117, 81, 235, 243, 50, 116, 17,
               143, 132, 137, 156, 113, 34, 126, 157, 207, 63, 145, 105, 101, 60, 109, 150, 162, 152, 153, 51, 57,
               154, 202, 195, 159, 160, 188, 228, 163, 164, 84, 127, 167, 168, 4, 111, 93, 172, 183, 39, 175, 176,
               40, 65, 174, 180, 110, 11, 27, 223, 142, 48, 177, 254, 144, 97, 96, 192, 203, 92, 14, 239, 22, 131,
               234, 32, 233, 201, 85, 196, 69, 133, 204, 30, 170, 103, 138, 123, 53, 214, 25, 216, 217, 194, 219,
               148, 221, 28, 222, 166, 255, 248, 191, 91, 90, 15, 231, 193, 189, 209, 102, 197, 37, 238, 140, 226,
               95, 136, 161, 59, 165, 246, 206, 149, 47, 100, 35, 251, 253, 79, 155]

KEY = b"kqI1DTcwKX90ZtAy"


class AES128CustomSBox:
    """
    zero-padding，自定义sbox
    """

    def __init__(self, sbox: List[int] | None, inv_sbox: List[int] | None):
        if sbox is None:
            sbox = CUSTOM_SBOX
        if inv_sbox is None:
            inv_sbox = generate_inverse_sbox(sbox)

        if len(sbox) != 256 or len(inv_sbox) != 256:
            raise ValueError("sbox and inv_sbox must have length 256")

        self.sbox = sbox
        self.inv_sbox = inv_sbox

        self.rcon = [
            0x01, 0x02, 0x04, 0x08, 0x10,
            0x20, 0x40, 0x80, 0x1B, 0x36
        ]

    @staticmethod
    def _xtime(x: int) -> int:
        x <<= 1
        if x & 0x100:
            x ^= 0x11B
        return x & 0xFF

    def _mul(self, x: int, y: int) -> int:
        """GF(2^8) 乘法"""
        res = 0
        for i in range(8):
            if y & 1:
                res ^= x
            high = x & 0x80
            x = (x << 1) & 0xFF
            if high:
                x ^= 0x1B
            y >>= 1
        return res

    def _sub_word(self, word: List[int]) -> List[int]:
        return [self.sbox[b] for b in word]

    @staticmethod
    def _rot_word(word: List[int]) -> List[int]:
        return word[1:] + word[:1]

    @staticmethod
    def _flatten_words(words: List[List[int]]) -> bytes:
        out = []
        for w in words:
            out.extend(w)
        return bytes(out)

    def _key_expansion(self, key: bytes) -> List[bytes]:
        w: List[List[int]] = [list(key[i:i + 4]) for i in range(0, 16, 4)]

        for i in range(4, 44):
            temp = w[i - 1].copy()
            if i % 4 == 0:
                temp = self._sub_word(self._rot_word(temp))
                temp[0] ^= self.rcon[(i // 4) - 1]
            w.append([w[i - 4][j] ^ temp[j] for j in range(4)])

        return [self._flatten_words(w[i:i + 4]) for i in range(0, 44, 4)]

    @staticmethod
    def _add_round_key(state: List[int], round_key: bytes) -> None:
        for i in range(16):
            state[i] ^= round_key[i]

    def _sub_bytes(self, state: List[int]) -> None:
        for i in range(16):
            state[i] = self.sbox[state[i]]

    def _inv_sub_bytes(self, state: List[int]) -> None:
        for i in range(16):
            state[i] = self.inv_sbox[state[i]]

    @staticmethod
    def _shift_rows(state: List[int]) -> None:
        s = state.copy()
        state[1], state[5], state[9], state[13] = s[5], s[9], s[13], s[1]
        state[2], state[6], state[10], state[14] = s[10], s[14], s[2], s[6]
        state[3], state[7], state[11], state[15] = s[15], s[3], s[7], s[11]

    @staticmethod
    def _inv_shift_rows(state: List[int]) -> None:
        s = state.copy()
        state[1], state[5], state[9], state[13] = s[13], s[1], s[5], s[9]
        state[2], state[6], state[10], state[14] = s[10], s[14], s[2], s[6]
        state[3], state[7], state[11], state[15] = s[7], s[11], s[15], s[3]

    def _mix_columns(self, state: List[int]) -> None:
        for c in range(4):
            i = c * 4
            a = state[i:i + 4]

            state[i] = self._mul(a[0], 2) ^ self._mul(a[1], 3) ^ a[2] ^ a[3]
            state[i + 1] = a[0] ^ self._mul(a[1], 2) ^ self._mul(a[2], 3) ^ a[3]
            state[i + 2] = a[0] ^ a[1] ^ self._mul(a[2], 2) ^ self._mul(a[3], 3)
            state[i + 3] = self._mul(a[0], 3) ^ a[1] ^ a[2] ^ self._mul(a[3], 2)

    def _inv_mix_columns(self, state: List[int]) -> None:
        for c in range(4):
            i = c * 4
            a = state[i:i + 4]

            state[i] = self._mul(a[0], 14) ^ self._mul(a[1], 11) ^ self._mul(a[2], 13) ^ self._mul(a[3], 9)
            state[i + 1] = self._mul(a[0], 9) ^ self._mul(a[1], 14) ^ self._mul(a[2], 11) ^ self._mul(a[3], 13)
            state[i + 2] = self._mul(a[0], 13) ^ self._mul(a[1], 9) ^ self._mul(a[2], 14) ^ self._mul(a[3], 11)
            state[i + 3] = self._mul(a[0], 11) ^ self._mul(a[1], 13) ^ self._mul(a[2], 9) ^ self._mul(a[3], 14)

    # ---------------- 加密 ----------------
    def encrypt_block(self, pt: bytes, key: bytes | None) -> bytes:
        if key is None:
            key = KEY
        round_keys = self._key_expansion(key)
        state = list(pt)

        self._add_round_key(state, round_keys[0])

        for r in range(1, 10):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, round_keys[r])

        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, round_keys[10])

        return bytes(state)

    # ---------------- 解密 ----------------
    def decrypt_block(self, ct: bytes, key: bytes | None) -> bytes:
        if key is None:
            key = KEY
        round_keys = self._key_expansion(key)
        state = list(ct)

        # 逆初始轮
        self._add_round_key(state, round_keys[10])

        for r in range(9, 0, -1):
            self._inv_shift_rows(state)
            self._inv_sub_bytes(state)
            self._add_round_key(state, round_keys[r])
            self._inv_mix_columns(state)

        # 最后一轮
        self._inv_shift_rows(state)
        self._inv_sub_bytes(state)
        self._add_round_key(state, round_keys[0])

        return bytes(state)


def generate_inverse_sbox(sbox):
    # 初始化一个长度为 256 的空表
    inv_sbox = [0] * 256
    for i, val in enumerate(sbox):
        inv_sbox[val] = i

    return inv_sbox


