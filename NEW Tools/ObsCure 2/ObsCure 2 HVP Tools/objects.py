from dataclasses import dataclass


@dataclass
class HashEntryObject:
    crc: int
    path_length: int
    file_path: str


@dataclass
class HashDumpObject:
    crc: str
    path_length: int
    file_path: str

