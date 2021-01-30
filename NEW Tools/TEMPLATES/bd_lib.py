# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''

# Program tested on Python 3.7.0

# Ver    Date        Author               Comment
# v0.1   27.01.2021  Bartlomiej Duda      -






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









##################################################
##################################################
##                                              ##
##  String Functions                            ##
##                                              ##
##################################################
##################################################

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


def get_string(in_file):
    '''
    Function for reading null terminated string from binary file
    '''  
    out_name = ""
    b_out_name = b''
    file_size = os.path.getsize(in_file.name)
    while 1:  
        curr_offset = in_file.tell() 
        if curr_offset == file_size:  # EOF reached, aborting
            break
        
        ch = struct.unpack("c", in_file.read(1))[0]
        
        if ord(ch) != 0:
            b_out_name += ch  
        else:
            break
        
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



# TODO 























