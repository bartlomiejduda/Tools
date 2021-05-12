# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Jack Orlando

# Ver    Date        Author               Comment
# v0.1   11.05.2021  Bartlomiej Duda      -
# v0.2   12.05.2021  Bartlomiej Duda      Added RLE decoding

import os
import sys
import struct
import datetime
from PIL import Image


class BMP_IMG:
    class BMP_HEADER:
        def __init__(self, in_size, in_offset):
            self.bmp_magic = b'BM'
            self.bmp_size = in_size
            self.reserved = 0
            self.offset_im_data = in_offset 
            
        def get_binary(self):
            return ( struct.pack("2s", self.bmp_magic) +
                     struct.pack("<L", self.bmp_size) +
                     struct.pack("<L", self.reserved) +  
                     struct.pack("<L", self.offset_im_data) 
                    )
        
    class BMP_INFO_HEADER:
        def __init__(self, in_width, in_height, in_bpp):
            self.info_header_size = 40
            self.num_of_planes = 1
            self.comp_type = 0  # "0" - no compression
                                # "1" - BI_RLE8, 8bit RLE encoding
                                # "2" - BI_RLE4, 4bit RLE encoding
            self.comp_im_size = 0
            self.pref_hor_res = 0
            self.pref_vert_res = 0
            self.num_of_used_colors = 128
            self.num_of_imp_colors = 0   # 0 means all colors are important
            
            self.im_width = in_width
            self.im_height = in_height 
            self.bpp = in_bpp 
            
        def get_binary(self):
            return ( struct.pack("<L", self.info_header_size) +
                     struct.pack("<L", self.im_width) +
                     struct.pack("<L", self.im_height) +
                     struct.pack("<H", self.num_of_planes) +
                     struct.pack("<H", self.bpp) +
                     struct.pack("<L", self.comp_type) +
                     struct.pack("<L", self.comp_im_size) +
                     struct.pack("<L", self.pref_hor_res) +
                     struct.pack("<L", self.pref_vert_res) +
                     struct.pack("<L", self.num_of_used_colors) +
                     struct.pack("<L", self.num_of_imp_colors)
                     )
        
    def __init__(self, in_width, in_height, in_bpp, in_image_data, in_palette_data):
        self.bmp_width = in_width
        self.bmp_height = in_height
        self.bmp_bpp = in_bpp
        self.bmp_data = in_image_data
        self.bmp_palette = in_palette_data
        
        self.data_size = len(self.bmp_data)
        self.palette_size = len(self.bmp_palette)
        self.bmp_size = 14 + 40 + self.palette_size + self.data_size
        self.data_offset = 14 + 40 + self.palette_size
        
        
        self.header = self.BMP_HEADER(self.data_size, self.data_offset)
        self.header_data = self.header.get_binary()
        
        self.info_header = self.BMP_INFO_HEADER(self.bmp_width, self.bmp_height, self.bmp_bpp)
        self.info_header_data = self.info_header.get_binary()
        
    def get_bmp_file_data(self):
        return ( self.header_data +
                 self.info_header_data + 
                 self.bmp_palette +
                 self.bmp_data
                )
        

def bd_logger(in_str):
    '''
    Function for logging debug messages
    '''   
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    

def byte_to_bits(in_byte):
    byte_int = struct.unpack("B", in_byte)[0]
    bytes_str = bin(byte_int)[2:].rjust(8, '0')
    return bytes_str

def bits_to_byte(in_bits):
    out_byte = int(in_bits, 2).to_bytes(1, 'little')
    return out_byte


def convert_data(in_file_path, out_file_path):
    '''
    Function for converting PBM images to BMP images
    '''    
    bd_logger("Starting convert_data...")    
    
    pbm_file = open(in_file_path, 'rb')
    
    im_width = struct.unpack("<H", pbm_file.read(2))[0]
    im_height = struct.unpack("<H", pbm_file.read(2))[0]
    im_bpp = 8
    palette_data = pbm_file.read(256)
    
    pbm_size = os.path.getsize(in_file_path)
    
    
    
    # RLE decoding
    bmp_data = b''
    while 1:
        curr_pos = pbm_file.tell()
        if curr_pos >= pbm_size:
            break
            
        color = struct.unpack("B", pbm_file.read(1))[0]
        repeat = 1

        if color & 1:
            repeat = struct.unpack("B", pbm_file.read(1))[0]
            
        color = color >> 1
        
        for j in range(repeat):
            p_byte = (palette_data[color]).to_bytes(1, byteorder='little')
            bmp_data += p_byte
    
    
    
    
    out_bmp_data_size = len(bmp_data)
    out_palette_data_size = len(palette_data)
    print("data_size: " + str(out_bmp_data_size) + " pal_size: " + str(out_palette_data_size))
    
    
    ##convert 8-bit palette to 32-bit
    #new_pal_data = b''
    #for p_byte in palette_data:
        #pb_byte = p_byte.to_bytes(1, 'little')   
    
        #out_bits = byte_to_bits(pb_byte)
        ##print(out_bits)
        
        #r_value = (out_bits[0] + out_bits[1] + out_bits[2]).rjust(8, '0')
        #r_byte = bits_to_byte(r_value)
        
        #g_value = (out_bits[3] + out_bits[4] + out_bits[5]).rjust(8, '0')
        #g_byte = bits_to_byte(g_value)
        
        #b_value = (out_bits[6] + out_bits[7]).rjust(8, '0')
        #b_byte = bits_to_byte(b_value)  
        
        ##rgba_value = r_byte + g_byte + b_byte + b'\x00'
        #rgba_value = b_byte + g_byte + r_byte + b'\x00'
        
        #new_pal_data += rgba_value
    
    
    #bmp_file_data = b''
    #bmp_file_data += bmp_data
    #bmp_file_data += palette_data

    
    ## convert 16-bit palette to 32-bit
    #new_pal_data = b''
    #pal_list1 = []
    #pal_list2 = []
    #count = 0
    #for p_byte in palette_data:
        #count += 1
        #pb_byte = p_byte.to_bytes(1, 'little') 
        
        #if count % 2 == 0:
            #pal_list1.append(pb_byte)
        #else:
            #pal_list2.append(pb_byte)
            
    #for i in range(128):
        #rgba_value = pal_list1[i] + pal_list2[i] + b'\x00\x00'
        #new_pal_data += rgba_value
        
    
    #temporary workaround for palette data...
    for i in range(128):
        palette_data += b'\x00\x00'
        
    


    # sve BMP file
    bmp_object = BMP_IMG(im_width, im_height, im_bpp, bmp_data, palette_data)
    bmp_file_data = bmp_object.get_bmp_file_data()
    out_file = open(out_file_path, "wb+")  
    out_file.write(bmp_file_data)
    out_file.close()  
    
    
    # flip BMP image
    img = Image.open(out_file_path).transpose(Image.FLIP_TOP_BOTTOM)  
    img.save(out_file_path)
    img.close()

    

    pbm_file.close()
    bd_logger("Ending convert_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - convert PBM image to BMP image 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\AUTOJAC.PBM"
        p_out_file_path = "C:\\Users\\Arek\\Desktop\\out.bmp"
        convert_data(p_in_file_path, p_out_file_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()