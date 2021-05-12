# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''

# Program tested on Python 3.7.0

# Ver    Date        Author               Comment
# v0.1   27.01.2021  Bartlomiej Duda      -
# v0.2   13.02.2021  Bartlomiej Duda      Added padding calculation functions
# v0.3   12.05.2021  Bartlomiej Duda      BMP enhancements + bytes/bits conversions functions






def bd_logger(in_str):
    '''
    Function for logging debug messages
    '''   
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    


from itertools import cycle
def xore(data, key):
    '''
    Function for XORing data
    '''  
    return bytes(a ^ b for a, b in zip(data, cycle(key)))



def byte_to_bits(in_byte):
    byte_int = struct.unpack("B", in_byte)[0]
    bytes_str = bin(byte_int)[2:].rjust(8, '0')
    return bytes_str

def bits_to_byte(in_bits):
    out_byte = int(in_bits, 2).to_bytes(1, 'little')
    return out_byte






##################################################
##################################################
##                                              ##
##  Padding Functions                           ##
##                                              ##
##################################################
##################################################

def calculate_padding_len(in_len):
    padding_val = (8 - (in_len % 8)) % 8
    return padding_val

def calculate_padding_len_v2(in_len):
    mod_res = int(in_len % 4)
    if mod_res == 0:
        return mod_res
    else:
        res = 4 - mod_res
        return res  
 
def calculate_padding_len_v3(in_len):
    padding_val = (4 - (in_len % 4)) % 4
    return padding_val   

def calculate_padding_len_v4(in_len):
    div = 4
    padding_val = (div - (in_len % div)) % div
    return padding_val  









##################################################
##################################################
##                                              ##
##  String Functions                            ##
##                                              ##
##################################################
##################################################

def read_nulls(in_file):
    while 1:
        back_offset = in_file.tell()
        ch = struct.unpack('c', in_file.read(1))[0].decode("windows-1252")
        if ord(ch) != 0:
            in_file.seek(back_offset)
            return


def get_string2(in_file):
    '''
    Function for reading null terminated string from binary file
    '''  
    out_name = ""
    while 1:
        ch = struct.unpack("c", in_file.read(1))[0]
        
        if ord(ch) != 0:
            try:
                out_name += ch.decode("utf8")
            except:
                temp_hex = hex(ord(ch))  # workaround for invalid characters...
                temp_str = "<" + str(temp_hex) + ">"
                out_name += temp_str
                
        else:
            break
    return out_name


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
    
    
    







##################################################
##################################################
##                                              ##
##  PNG Functions                               ##
##                                              ##
##################################################
##################################################
 
import zlib # needed for CRC calculation
            # and for image data compression
            
class PNG_CHUNK:
    def __init__(self, in_name, in_data):
        self.data_size = len(in_data)
        self.name = in_name
        self.data = in_data
        self.CRC = zlib.crc32(self.name.encode("utf8") + in_data)
        
    def print_chunk_info(self):
        print("Chunk name: " + str(self.name))
        print("Chunk data size: " + str(self.data_size))
        print("Chunk CRC (dec): " + str(self.CRC))
        print("Chunk CRC (hex): " + str(hex(self.CRC)))
        
    def get_binary(self):
        return ( struct.pack(">L", self.data_size) +
                 struct.pack("4s", self.name.encode("utf8")) + 
                 self.data +
                 struct.pack(">L", self.CRC)
                 )
    

class PNG_IMG:
    def __init__(self, in_width, in_height, in_image_data, in_palette_data):
        
        self.magic = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'
        
        self.png_width = in_width-1
        self.png_height = in_height 
        self.png_depth = 8
        self.png_color_type = 0
        self.png_comp_method = 0
        self.png_filther_method = 0
        self.png_interlace_method = 0
        
        self.png_image_data = in_image_data
        self.png_palette_data = in_palette_data

    
    
    def get_IHDR_data(self):
        return ( struct.pack(">L", self.png_width) +
                 struct.pack(">L", self.png_height) +
                 struct.pack(">B", self.png_depth) +
                 struct.pack(">B", self.png_color_type) +
                 struct.pack(">B", self.png_comp_method) +
                 struct.pack(">B", self.png_filther_method) +
                 struct.pack(">B", self.png_interlace_method)
                 )

    def get_PLTE_data(self):
        return self.png_palette_data
    
    def get_IDAT_data(self):
        return zlib.compress(self.png_image_data)
    
    def get_IEND_data(self):
        return b''    

    def get_PNG_data(self):
        IHDR_data = self.get_IHDR_data()
        IHDR_chunk = PNG_CHUNK("IHDR", IHDR_data)
        
        #PLTE_data = self.get_PLTE_data()
        #PLTE_chunk = PNG_CHUNK("PLTE", PLTE_data)

        IDAT_data = self.get_IDAT_data()
        IDAT_chunk = PNG_CHUNK("IDAT", IDAT_data)
        
        IEND_data = self.get_IEND_data()
        IEND_chunk = PNG_CHUNK("IEND", IEND_data)
        
        
        return ( self.magic +
                 IHDR_chunk.get_binary() +
                 #PLTE_chunk.get_binary() +
                 IDAT_chunk.get_binary() +
                 IEND_chunk.get_binary()
                 )
    
    def print_PNG_info(self):
        print("PNG width: " + str(self.png_width))
        print("PNG height: " + str(self.png_height))
        print("PNG depth: " + str(self.png_depth))
        print("PNG color type: " + str(self.png_color_type))  
        

out_PNG = PNG_IMG(im_width, im_height, im_data, im_palette_data)
png_data = out_PNG.get_PNG_data()
out_PNG.print_PNG_info()














##################################################
##################################################
##                                              ##
##  BMP Functions                               ##
##                                              ##
##################################################
##################################################



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
            self.comp_type = 0   # "0" - no compression
                                 # "1" - BI_RLE8, 8bit RLE encoding
                                 # "2" - BI_RLE4, 4bit RLE encoding
            self.comp_im_size = 0
            self.pref_hor_res = 0
            self.pref_vert_res = 0
            self.num_of_used_colors = 0   # "0" for default 2^n
            self.num_of_imp_colors = 0    # "0" means that all colors are important
            
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
        




# writing bmp
bmp_object = BMP_IMG(im_width, im_height, im_bpp, bmp_data, palette_data)
bmp_file_data = bmp_object.get_bmp_file_data()
out_file_path = out_folder_path + file_name.replace(">", "0") + "_" + str(f_count+1) + ".bmp"
out_file = open(out_file_path, "wb+")  
out_file.write(bmp_file_data)
out_file.close()
        
        

#BMP FLIP TOP BOTTOM FIX
try:
    img = Image.open(out_file_path).transpose(Image.FLIP_TOP_BOTTOM)  
    img.save(out_file_path)
    img.close()
except:
    bd_logger("Can't flip image " + file_name + "...")



#reading palette 
ssh_file.seek(pal_data_offset)
pal_header_data = ssh_file.read(15) # palette header
palette_data = b''
for i in range(256):
    pal_entry1 = ssh_file.read(1)
    pal_entry2 = ssh_file.read(1)
    pal_entry3 = ssh_file.read(1)
    pal_entry4 = ssh_file.read(1)
    palette_data += pal_entry4 + pal_entry3 + pal_entry2 + pal_entry1 # RGBA swap



# SKEW FIX
bmp_data = b'' 
temp_row = b''
skew_val = im_width % 4      
for i in range(im_height):
    temp_row = b''
    for j in range(im_width):
        pixel = ssh_file.read(1)
        temp_row += pixel
    if skew_val == 1:
        temp_row += b'\x00\x00'
    elif skew_val == 2:
        temp_row += b'x\00'
        
    row_len = len(temp_row)
    bmp_data += temp_row

diff = block_size - im_size_calc
bmp_data += ssh_file.read(diff)




# RLE decoding (RLEB, flag type) for Jack Orlando
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










