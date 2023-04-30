tail_concerto_character_mapping: dict = {
    b"\xAF": b"\x5A",  # Ż -> Z
    b"\xD3": b"\x4F",  # Ó -> O
    b"\xA3": b"\x4C",  # Ł -> L
    b"\xC6": b"\x43",  # Ć -> C
    b"\xCA": b"\x45",  # Ę -> E
    b"\x8C": b"\x53",  # Ś -> S
    b"\xA5": b"\x41",  # Ą -> A
    b"\x8F": b"\x5A",  # Ź -> Z
    b"\xD1": b"\x4E",  # Ń -> N

    b"\xBF": b"\x7A",  # ż -> z
    b"\xF3": b"\x6F",  # ó -> o
    b"\xB3": b"\x6C",  # ł -> l
    b"\xE6": b"\x63",  # ć -> c
    b"\xEA": b"\x65",  # ę -> e
    b"\x9C": b"\x73",  # ś -> s
    b"\xB9": b"\x61",  # ą -> a
    b"\x9F": b"\x7A",  # ź -> z
    b"\xF1": b"\x6E",  # ń -> n
}


def tail_concerto_import_transform(input_bytes: bytes) -> bytes:
    for key, value in tail_concerto_character_mapping.items():
        input_bytes = input_bytes.replace(key, value)
    return input_bytes
