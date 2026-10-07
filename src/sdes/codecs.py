"""Strict user-input conversions; ciphertext always remains lossless bytes."""

import re


def parse_bits(text: str, width: int) -> int:
    value = text.strip()
    if len(value) != width or any(char not in "01" for char in value):
        raise ValueError(f"请输入恰好 {width} 位的二进制数据，仅允许 0 和 1")
    return int(value, 2)


def parse_hex(text: str) -> bytes:
    value = text.strip()
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}\s*)*", value):
        raise ValueError("Hex 必须由完整字节组成，例如 00 7F FF；每字节为两个十六进制数字")
    return bytes.fromhex(value)


def ascii_bytes(text: str) -> bytes:
    try:
        return text.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError(f"第 {error.start + 1} 个字符不是 ASCII 字符") from error


def preview_bytes(data: bytes) -> str:
    return "".join(
        chr(byte) if 32 <= byte < 127 and byte != 92 else f"\\x{byte:02x}" for byte in data
    )
