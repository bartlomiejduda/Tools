# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with NHL 2002 (PS2)

# Ver    Date        Author               Comment
# v0.1   23.01.2021  Bartlomiej Duda      -
# v0.2   28.01.2021  Bartlomiej Duda      -
# v0.3   30.01.2021  Bartlomiej Duda      -
# v0.4   31.01.2021  Bartlomiej Duda      -

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


def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from SSH files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    ssh_file = open(in_file_path, 'rb')
    
    try:
        magic = struct.unpack("4s", ssh_file.read(4))[0].decode("utf8")
    except:
        bd_logger("Can't read magic! Aborting!")
        
    if magic not in ("SHPS", "SHPP"):
        bd_logger("It is not supported EA graphics file! Aborting!")
        return
    
    ssh_file.read(4) # total file size
    num_of_files = struct.unpack("<L", ssh_file.read(4))[0]
    ssh_file.read(4) # directory ID
    
    
    for i in range(num_of_files):
        file_name = struct.unpack("4s", ssh_file.read(4))[0].decode("utf8")
        file_offset = struct.unpack("<L", ssh_file.read(4))[0]

        back_offset = ssh_file.tell()
        ssh_file.seek(file_offset)
        
        #reading image header
        image_type = struct.unpack("<B", ssh_file.read(1))[0]
        block_size = struct.unpack("<L", ssh_file.read(3) + b'\x00')[0] - 16 
        if block_size < 0:
            block_size = 0
        im_width = struct.unpack("<H", ssh_file.read(2))[0] 
        im_height = struct.unpack("<H", ssh_file.read(2))[0]
        #im_width = int(im_size / im_height)
        im_size_calc = im_width * im_height
        temp = ssh_file.read(8)
        
        im_data_offset = ssh_file.tell()
        pal_data_offset = im_data_offset + block_size
        
        
        if block_size == im_size_calc + 12:
            im_size = im_size_calc
        else:
            im_size = block_size
            #im_width -= 0
            #im_height += 150
            #im_size = (im_width * im_height) 
            #im_size = block_size - 12
            #im_size = block_size
            
            #print("file_name: " + str(file_name) + 
                  #" block_size: " + str(block_size) +
                  #" im_size_calc: " + str(im_size_calc) +
                  #" im_size: " + str(im_size) +
                  #" im_width: " + str(im_width) + 
                  #" im_height: " + str(im_height) + 
                  #" diff: " + str(block_size - im_size_calc)
                  #)
        
        
        print("file_name: " + str(file_name) +
              " image_type: " + str(image_type)
              )
                 
        
        # reading image data + pixel data swap
        ssh_file.seek(im_data_offset)
        
        

        
        bmp_data = b'' # SKEW FIX
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
        if diff > 0:
            bmp_data += ssh_file.read(diff)
        

 
        
        
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
            

        
        
        # BMP START
        bmp_width = im_width
        bmp_height = im_height
        bmp_bpp = 8
        bmp_pal = palette_data
        #bmp_data = im_data
        
        
        # create BMP header
        first_header_size = 14
        h_magic = struct.pack("2s", b"BM")
        h_size = struct.pack("<L", 111)   # !
        h_reserv = struct.pack("<L", 0)   
        h_offset = struct.pack("<L", 111) # !
        
        # create DIB header 
        dib_header_size = 40
        d_size = struct.pack("<L", dib_header_size)
        d_width = struct.pack("<L", bmp_width)
        d_height = struct.pack("<L", bmp_height)
        d_planes = struct.pack("<H", 1)
        d_bpp = struct.pack("<H", bmp_bpp)  
        d_comp = struct.pack("<L", 0)
        d_size_image = struct.pack("<L", 0)   # ?!
        d_hor_res = struct.pack("<L", 0)
        d_vert_res = struct.pack("<L", 0)
        d_num_pal_col = struct.pack("<L", 0)
        d_imp_colors = struct.pack("<L", 0)
 
        
        # corrections 
        h_size_calc = first_header_size + dib_header_size +len(bmp_pal) + len(bmp_data)
        h_size = struct.pack("<L",   h_size_calc)
        h_offset = struct.pack("<L", first_header_size + dib_header_size + len(bmp_pal) )
        

        
        # WRITING BMP
        out_file_path = out_folder_path + file_name.replace(">", "0") + ".bmp"
        #print(out_file_path)
        out_file = open(out_file_path, "wb+")
        
        
        # write header
        out_file.write(h_magic)
        out_file.write(h_size)
        out_file.write(h_reserv)
        out_file.write(h_offset)
        
        # write DIB header 
        out_file.write(d_size)
        out_file.write(d_width)
        out_file.write(d_height)
        out_file.write(d_planes)
        out_file.write(d_bpp)
        out_file.write(d_comp)
        out_file.write(d_size_image)
        out_file.write(d_hor_res)
        out_file.write(d_vert_res)
        out_file.write(d_num_pal_col)
        out_file.write(d_imp_colors)

        
        # write palette and data
        out_file.write(bmp_pal)
        out_file.write(bmp_data)        
        out_file.close()
        
        
        
        #BMP FLIP TOP BOTTOM FIX
        try:
            img = Image.open(out_file_path).transpose(Image.FLIP_TOP_BOTTOM)  
            img.save(out_file_path)
            img.close()
        except:
            bd_logger("Can't flip image " + file_name + "...")

        ssh_file.seek(back_offset)
    

    ssh_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\NBA Live 97 PS1\\ZFONT3.PSH"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\NBA Live 97 PS1\\ZFONT3.PSH_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()