# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Teenage Mutant Ninja Turtles 2003 (PC)

# Ver    Date        Author               Comment
# v0.1   09.03.2021  Bartlomiej Duda      -
# v0.2   09.03.2021  Bartlomiej Duda      -

import os
import sys
import struct
import datetime
from PIL import Image


def bd_logger(in_str):
    '''
    Function for logging debug messages
    '''   
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    

def get_string(in_file, max_str_len):
    '''
    Function for reading null terminated string from binary file
    '''  
    out_name = ""
    b_out_name = b''
    file_size = os.path.getsize(in_file.name)
    curr_str_len = 0
    while 1:  
        curr_offset = in_file.tell() 
        if curr_offset == file_size:  # EOF reached, aborting
            break
        
        ch = struct.unpack("c", in_file.read(1))[0]
        
        if ord(ch) != 0:
            b_out_name += ch  
            curr_str_len += 1
            if curr_str_len == max_str_len:
                break
            
        else:
            break
        
    back_offset = in_file.tell() - 1  # fix for wrong offset after reading null at the end
    in_file.seek(back_offset)
        
    out_name = b_out_name.decode("utf8")
    return out_name     


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
            self.comp_type = 0
            self.comp_im_size = 0
            self.pref_hor_res = 0
            self.pref_vert_res = 0
            self.num_of_used_colors = 0
            self.num_of_imp_colors = 0
            
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
        




def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from TXD files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    txd_file = open(in_file_path, 'rb')
    
    HEADER_SIZE = 16
    CHUNK_HEADER_SIZE = 12
    
    chunk_type = struct.unpack("<L", txd_file.read(4))[0]
    if chunk_type != 35:
        bd_logger("It is not valid TXD file from TMNT 2003 game! Aborting!")
        return
    
    txd_file.read(4) # chunk size
    txd_file.read(4) # RW version ID
    num_of_entries = struct.unpack("<L", txd_file.read(4))[0]
    
    for i in range(num_of_entries):
        str_start_offset = txd_file.tell()
        texture_name = get_string(txd_file, 16)
        str_end_offset = txd_file.tell()
        padding_len = 16 - (str_end_offset - str_start_offset)
        txd_file.read(padding_len)
        out_file_path = out_folder_path + texture_name + "_tex" + str(i+1) + ".bmp"      
        
        txd_file.read(56) # unknown
        
        chunk_type = struct.unpack("<L", txd_file.read(4))[0]
        if chunk_type != 24:
            bd_logger("Chunk_type_offset: " + str(txd_file.tell() - 4))
            bd_logger("It is not valid Image chunk! Aborting!")
            return 
        
        chunk_size = struct.unpack("<L", txd_file.read(4))[0]
        txd_file.read(4) # RW version ID
        
        
        
        chunk_type = struct.unpack("<L", txd_file.read(4))[0]
        if chunk_type != 1:
            bd_logger("Chunk_type_offset: " + str(txd_file.tell() - 4))
            bd_logger("It is not valid Struct chunk! Aborting!")
            return 
        txd_file.read(4) # chunk size
        txd_file.read(4) # RW version ID
        
        image_width = struct.unpack("<L", txd_file.read(4))[0]
        image_height = struct.unpack("<L", txd_file.read(4))[0]
        bpp = struct.unpack("<L", txd_file.read(4))[0]
        image_stride = struct.unpack("<L", txd_file.read(4))[0]
        
        
        num_bytes = image_width * image_height  # values for checking correct image data size 
        num_bytes_stride = image_height * image_stride
        
        if bpp == 8:
            PALETTE_SIZE = 1024
        elif bpp == 4:
            PALETTE_SIZE = 64
        elif bpp == 32:
            PALETTE_SIZE = 0
            num_bytes *= 4
        
        
        image_size = chunk_size - PALETTE_SIZE - HEADER_SIZE - CHUNK_HEADER_SIZE
        
        if (num_bytes != image_size and num_bytes_stride != image_size):
            log_msg = "Image size and image dimensions don't match for texture \"" + str(texture_name) + "\"! Aborting!"
            bd_logger(log_msg)
            raise Exception(log_msg)
        
        image_data = txd_file.read(image_size)
        
        
        # read palette
        palette_data = b''
        for i in range( int(PALETTE_SIZE / 4) ):
            pal_entry1 = txd_file.read(1)
            pal_entry2 = txd_file.read(1)
            pal_entry3 = txd_file.read(1)
            pal_entry4 = txd_file.read(1)
            palette_data += pal_entry3 + pal_entry2 + pal_entry1 + pal_entry4 # RGBA swap        

        #print(out_file_path)
        
        out_file = open(out_file_path, "wb+")
        bmp_object = BMP_IMG(image_width, image_height, bpp, image_data, palette_data)
        bmp_file_data = bmp_object.get_bmp_file_data()  
        out_file.write(bmp_file_data)
        
        out_file.close()
        
        try:
            img = Image.open(out_file_path).transpose(Image.FLIP_TOP_BOTTOM)  
            img.save(out_file_path)
            img.close()
        except:
            bd_logger("Can't flip image " + texture_name + "...")        
    
    
    
   
    
    txd_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 2
    # 1 - data export, one TXD file
    # 2 - data export, all TXD files to separate directories
    # 3 - data export, all TXD files to one directory
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\key_keyconf.txd"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\key_keyconf.txd_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    elif main_switch == 2:
        p_in_txd_directory = "C:\\Users\\Arek\\Desktop\\TXD_OUT\\"
        
        for root, dirs, files in os.walk(p_in_txd_directory):
            for file in files:
                if file.endswith('.txd'):
                    file_path = str(os.path.join(root, file))
                    out_path = file_path + "_OUT\\"
                    print("Processing " + file_path)
                    export_data(file_path, out_path)
                    
    elif main_switch == 3:
        p_in_txd_directory = "C:\\Users\\Arek\\Desktop\\TXD_OUT\\"
        out_directory = "C:\\Users\\Arek\\Desktop\\TXD_OUT\\BMP_OUT\\"
        
        if not os.path.exists(out_directory):
            os.makedirs(out_directory)            
        
        for root, dirs, files in os.walk(p_in_txd_directory):
            for file in files:
                if file.endswith('.txd'):
                    file_path = str(os.path.join(root, file))
                    print(file_path)
                    export_data(file_path, out_directory)        
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()