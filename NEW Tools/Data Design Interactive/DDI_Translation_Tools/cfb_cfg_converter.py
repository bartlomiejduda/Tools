"""
Copyright © 2026  Bartłomiej Duda
License: GPL-3.0 License
"""

import struct
import sys
from dataclasses import dataclass
from pathlib import Path

MAX_CONFIG_DEPTH: int = 100


@dataclass(frozen=True)
class ConfigRecord:
    name: str
    name_hash: int | None
    value: str
    depth: int


def _next_stream_offset_after_string(payload_start: int, length: int) -> int:
    """
    Returns the next offset used by the game's padded string stream
    """
    after_extra_byte = payload_start + length + 1
    if after_extra_byte % 4 == 0:
        return after_extra_byte + 4
    return ((after_extra_byte + 3) // 4) * 4


def _read_stream_string(data: bytes, offset: int) -> tuple[str, int]:
    """
    Returns string and offset
    """
    if offset + 4 > len(data):
        raise ValueError("Unexpected EOF")
    length: int = struct.unpack_from('<I', data, offset)[0]
    start = offset + 4
    if length < 1 or length > len(data) - start:
        raise ValueError("Wrong text length")
    raw = data[start:start + length]
    if not raw.endswith(b'\0'):
        raise ValueError("Text is not NULL terminated")
    if b'\0' in raw[:-1]:
        raise ValueError("Text contains internal NULL value")
    return raw[:-1].decode('latin-1'), _next_stream_offset_after_string(start, length)


def parse_cfb_file(path: Path) -> list[ConfigRecord]:
    """
    Parses CFB file
    """
    cfb_file_data: bytes = path.read_bytes()
    config_records_list: list[ConfigRecord] = []
    offset: int = 0
    while offset < len(cfb_file_data):
        name, offset = _read_stream_string(cfb_file_data, offset)
        if offset + 4 > len(cfb_file_data):
            raise ValueError("Unexpected EOF")
        name_hash = struct.unpack_from('<I', cfb_file_data, offset)[0]
        offset += 4
        value, offset = _read_stream_string(cfb_file_data, offset)
        if offset + 4 > len(cfb_file_data):
            raise ValueError("Unexpected EOF")
        depth = struct.unpack_from('<I', cfb_file_data, offset)[0]
        offset += 4
        config_records_list.append(ConfigRecord(name, name_hash, value, depth))
    return config_records_list


def _decode_text(path: Path) -> str:
    data = path.read_bytes()
    return data.decode('latin-1')


def _tokenize_cfg(text: str) -> list[str]:
    """
    Tokenizer matching engine's CFG syntax.
    """
    tokens: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch == ';':
            end = text.find('\n', i)
            i = n if end < 0 else end + 1
            continue
        if ch == '"':
            i += 1
            buf: list[str] = []
            while i < n and text[i] != '"':
                if text[i] == ';':
                    raise ValueError("Comma inside string is not supported by the game's engine")
                buf.append(text[i])
                i += 1
            if i >= n:
                raise ValueError("Unclosed quote in text")
            tokens.append(''.join(buf))
            i += 1
            continue
        start = i
        while i < n and not text[i].isspace() and text[i] != ';' and text[i] != '"':
            i += 1
        if i == start:
            raise ValueError(f"Can't read token on position {i}.")
        tokens.append(text[start:i])
    return tokens


def parse_cfg_text(text: str) -> list[ConfigRecord]:
    tokens: list[str] = _tokenize_cfg(text)
    records: list[ConfigRecord] = []
    depth: int = 0
    i: int = 0
    while i < len(tokens):
        token = tokens[i]
        if token == '}':
            depth -= 1
            if depth < 0:
                raise ValueError("Too many closing brackets } in CFG file")
            i += 1
            continue
        if token == '{':
            raise ValueError("Opening bracket { in the wrong place")
        if i + 1 >= len(tokens):
            raise ValueError("Missing value for token")
        value = tokens[i + 1]
        if value == '}':
            raise ValueError("Missing value for token")
        records.append(ConfigRecord(token, None, value, depth))
        if value == '{':
            depth += 1
            if depth > MAX_CONFIG_DEPTH:
                raise ValueError(f"Max depth = {MAX_CONFIG_DEPTH} has been exceeded")
        i += 2
    if depth != 0:
        raise ValueError(f"Missing {depth} closing brackets in CFG")
    return records


def _format_token(value: str) -> str:
    """
    Formats token
    """
    if any(ch in value for ch in ('\n', '\r', '"', ';')):
        raise ValueError("Value contains invalid character")
    if value == '' or any(ch.isspace() for ch in value):
        return '"' + value + '"'
    return value


def write_cfg(records: list[ConfigRecord], output_path: Path) -> None:
    """
    Write CFG text in the engine's token-based syntax
    """
    lines: list[str] = []
    opened: list[int] = []
    for record in records:
        while len(opened) > record.depth:
            indent = opened.pop()
            lines.append('\t' * indent + '}')
        if len(opened) != record.depth:
            raise ValueError("Wrong CFB structure")
        name_text = _format_token(record.name)
        value_text = record.value
        if value_text == '}':
            raise ValueError("Invalid value")
        if value_text == '{':
            lines.append('\t' * record.depth + name_text)
            lines.append('\t' * record.depth + '{')
            opened.append(record.depth)
        else:
            lines.append('\t' * record.depth + name_text + '\t' + _format_token(value_text))
    while opened:
        indent = opened.pop()
        lines.append('\t' * indent + '}')
    lines.append('')
    output_path.write_bytes(('\r\n'.join(lines)).encode('latin-1'))


def generate_cfb_hash(name: str, ignore_blanks: bool = True, ignore_case: bool = True) -> int:
    """
    Hash function used in CFB files
    """
    if '\0' in name:
        raise ValueError("Name can't contain NULLs!")
    try:
        raw: bytes = name.encode('latin-1')
    except UnicodeEncodeError:
        raise ValueError(f"Name can't be encoded as latin-1!")

    result_hash: int = 0
    multiple: int = 6293815
    index: int = 1
    c_whitespace: set[int] = {9, 10, 11, 12, 13, 32}
    for char in raw:
        if ignore_blanks and char in c_whitespace:
            continue
        if ignore_case and 0x61 <= char <= 0x7A:
            char -= 0x20
        result_hash = (result_hash + multiple * index * char) & 0xFFFFFFFF
        multiple = (multiple * 6293815) & 0xFFFFFFFF
        index += 1
    return result_hash


def build_cfb(records: list[ConfigRecord]) -> bytes:
    """
    Serialize records, calculating each item-name hash from its name
    """
    out = bytearray()
    for record in records:
        name_hash = generate_cfb_hash(record.name, ignore_blanks=True, ignore_case=True)
        _write_stream_string(out, record.name)
        out.extend(struct.pack('<I', name_hash))
        _write_stream_string(out, record.value)
        out.extend(struct.pack('<I', record.depth))
    return bytes(out)


def _write_stream_string(out: bytearray, value: str) -> None:
    if '\0' in value:
        raise ValueError("Value can't contain NULL")
    raw = value.encode('latin-1') + b'\0'
    out.extend(struct.pack('<I', len(raw)))
    out.extend(raw)
    out.append(0)
    target = (len(out) // 4 + 1) * 4
    out.extend(b'\0' * (target - len(out)))


def convert_cfb_to_cfg(input_path: Path, output_path: Path) -> int:
    records = parse_cfb_file(input_path)
    write_cfg(records, output_path)
    return len(records)


def convert_cfg_to_cfb(input_path: Path, output_path: Path) -> int:
    text = _decode_text(input_path)
    records = parse_cfg_text(text)
    raw = build_cfb(records)
    output_path.write_bytes(raw)
    return len(records)


def main():
    pass  # TODO


if __name__ == '__main__':

    # TODO - handle it as debug feature
    sys.argv = [
        "cfb_cfg_converter.py",
        "TEMP\\aaaa",
    ]

    main()
