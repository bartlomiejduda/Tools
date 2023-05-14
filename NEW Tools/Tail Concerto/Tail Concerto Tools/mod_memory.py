from typing import List

from reversebox.io_files.mod_handler import ModEntry

mod_memory: List[ModEntry] = [
    ModEntry(file_offset=0x04, file_size=3360, file_relative_path="fonts\\font1.tim"),  # 1
    ModEntry(file_offset=0x23CD0, file_size=8128, file_relative_path="game\\police.tim"),  # 63
    ModEntry(file_offset=0x66034, file_size=115232, file_relative_path="menu\\ps1_gamepad.tim"),  # 70
    ModEntry(file_offset=0x9FE40, file_size=3104, file_relative_path="menu\\exit_button.tim"),  # 87
    ModEntry(file_offset=0x49F958, file_size=229396, file_relative_path="game\\fin.tim"),  # 109
    ModEntry(file_offset=0x505004, file_size=21024, file_relative_path="menu\\menu_buttons.tim"),  # 115
    ModEntry(file_offset=0x50A228, file_size=3104, file_relative_path="menu\\default_button.tim"),  # 116
    ModEntry(file_offset=0x50AE4C, file_size=3104, file_relative_path="menu\\exit_button.tim"),  # 117
    ModEntry(file_offset=0x50BA70, file_size=75536, file_relative_path="menu\\ps1_gamepad_02.tim"),  # 118
    ModEntry(file_offset=0x51E804, file_size=8864, file_relative_path="menu\\sound_volume.tim"),  # 119
    ModEntry(file_offset=0x520AA8, file_size=8864, file_relative_path="menu\\mode.tim"),  # 120
    ModEntry(file_offset=0x524FF0, file_size=6944, file_relative_path="menu\\sound_configuration.tim"),  # 122
    ModEntry(file_offset=0x526B14, file_size=8864, file_relative_path="menu\\max.tim"),  # 123
    ModEntry(file_offset=0x528DB8, file_size=2784, file_relative_path="menu\\stereo.tim"),  # 124
    ModEntry(file_offset=0x52989C, file_size=2784, file_relative_path="menu\\mono.tim"),  # 125
    ModEntry(file_offset=0x52A380, file_size=2784, file_relative_path="menu\\stereo2.tim"),  # 126
    ModEntry(file_offset=0x52AE64, file_size=2784, file_relative_path="menu\\mono2.tim"),  # 127
    ModEntry(file_offset=0x52BD0C, file_size=3104, file_relative_path="menu\\exit.tim"),  # 129
    ModEntry(file_offset=0x52C930, file_size=8864, file_relative_path="menu\\sfx_volume.tim"),  # 130
    ModEntry(file_offset=0x5311A4, file_size=15424, file_relative_path="game\\locations.tim"),  # 131
    ModEntry(file_offset=0x575298, file_size=7456, file_relative_path="map\\archeonis.tim"),  # 136
    ModEntry(file_offset=0x576FBC, file_size=8608, file_relative_path="map\\factory.tim"),  # 137
    ModEntry(file_offset=0x579160, file_size=9056, file_relative_path="map\\fortress.tim"),  # 138
    ModEntry(file_offset=0x70DE08, file_size=2112, file_relative_path="buildings\\219_seamus_estate.tim"),  # 329
    ModEntry(file_offset=0x70E64C, file_size=2112, file_relative_path="buildings\\view_ocean_mine_company.tim"),  # 330
    ModEntry(file_offset=0x12090EC, file_size=1984, file_relative_path="game\\target_start.tim"),  # 1203
    ModEntry(file_offset=0x12098B0, file_size=2368, file_relative_path="game\\target.tim"),  # 1204
    ModEntry(file_offset=0x1D95048, file_size=2112, file_relative_path="game\\book.tim"),  # 1907
]