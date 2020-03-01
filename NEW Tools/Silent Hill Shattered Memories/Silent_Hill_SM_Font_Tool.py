# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Silent Hill: Shattered Memories (PSP)

# Ver    Date        Author
# v0.1   01.03.2020  Bartlomiej Duda
# v0.2   01.03.2020  Bartlomiej Duda

VERSION_NUM = "v0.2"

import os
import sys
import struct
import zlib

def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    
def read_font(in_font_file_path, out_file_path):
    bd_logger("Starting read font")
    
    compressed_data = open(in_font_file_path, 'rb').read()
    decompressed_data = zlib.decompress(compressed_data)
    
    out_file = open(out_file_path, 'wb+')
    out_file.write(decompressed_data)
    out_file.close()
    
    
    bd_logger("Ending read font")
    
    
def write_font(in_decompressed_font_path, out_compressed_font_path):
    bd_logger("Starting write font")
    
    decompressed_data = open(in_decompressed_font_path, 'rb').read()
    compressed_data = zlib.compress(decompressed_data, 9)
    
    out_file = open(out_compressed_font_path, 'wb+')
    out_file.write(compressed_data)
    out_file.close()    
    
    bd_logger("Ending write font")


#read font
#p_in_font_file_path = "C:\\Users\\Arek\\Desktop\\Font_EBOOT\\font_eboot_temp"
#p_out_file_path = "C:\\Users\\Arek\\Desktop\\Font_EBOOT\\font_eboot_OUT"
#read_font(p_in_font_file_path, p_out_file_path)


#write font
p_in_decompressed_font_path = "C:\\Users\\Arek\\Desktop\\Font_EBOOT\\font_eboot_OUT_PL"
p_out_file_path = "C:\\Users\\Arek\\Desktop\\Font_EBOOT\\font_eboot_PACKED"
write_font(p_in_decompressed_font_path, p_out_file_path)