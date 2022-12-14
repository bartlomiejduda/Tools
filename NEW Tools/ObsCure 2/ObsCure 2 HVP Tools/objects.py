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


@dataclass
class DirectoryEntryObject:
    entry_hash: str
    entry_name: str
    entry_type: int
    value1: int  # CRC / zero
    value2: int  # file uncomp size / zero
    value3: int  # file offset / number of files in directory
    value4: int  # file comp size / start index


@dataclass
class RepackInfoObject:
    entry_hash: str
    entry_name: str
    entry_val1: str
    entry_type: int
