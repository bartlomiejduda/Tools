# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Actua Soccer

# Ver    Date        Author               Comment
# v0.1   04.01.2021  Bartlomiej Duda      -

import os
import sys
import struct
import datetime


def bd_logger(in_str):
    '''
    Function for logging debug messages
    '''   
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    

def convert_data(pal_file_path, bm_file_path, out_folder_path):
    '''
    Function for coverting data from BM/PAL files to BMP files
    '''    
    bd_logger("Starting convert_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    pal_file = open(pal_file_path, 'rb')
    bm_file = open(bm_file_path, 'rb')
    
    image_width = 640
    image_height = 480
    image_bpp = 8
    
    
    # create header
    h_magic = struct.pack("2s", b"BM")
    h_size = struct.pack("<L", 111)   # !
    h_reserv = struct.pack("<L", 0)   
    h_offset = struct.pack("<L", 111) # !
    
    # create DIB header 
    d_size = struct.pack("<L", 40)
    d_width = struct.pack("<L", image_width)
    d_height = struct.pack("<L", image_height)
    d_planes = struct.pack("<H", 1)
    d_bpp = struct.pack("<H", image_bpp)
    d_comp_type = struct.pack("<H", 0)
    d_comp_size = struct.pack("<H", 0)
    d_hor_res = struct.pack("<L", 222)
    d_vert_res = struct.pack("<L", 222)
    d_pal_col_num = struct.pack("<L", 256)
    d_imp_colors = struct.pack("<L", 0)
    
    # read palette and data
    bmp_pal = pal_file.read()
    bmp_data = bm_file.read()
    
    
    # corrections 
    h_size = struct.pack("<L", 14 + 40 + len(bmp_pal) + len(bmp_data) )
    h_offset = struct.pack("<L", 14 + 40 + len(bmp_pal) )
    
    
    data_arr = []
    bm_file.seek(0)
    for i in range(image_height):
        data_row = bm_file.read(image_width)
        data_arr.append(data_row)
        
    data_arr.reverse()
    
    temp_data = b''
    for i in range(image_height):
        temp_data += data_arr[i]
        
    bmp_data = temp_data
    
    
    
    
    out_file_path = out_folder_path + "out.bmp"
    print(out_file_path)
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
    out_file.write(d_comp_type)
    out_file.write(d_comp_size)
    out_file.write(d_hor_res)
    out_file.write(d_vert_res)
    out_file.write(d_pal_col_num)
    out_file.write(d_imp_colors)
    
    # write palette and data
    out_file.write(bmp_pal)
    out_file.write(bmp_data)
    
   
    out_file.close()
    pal_file.close()
    bm_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_pal_file_path = "C:\\Users\\Arek\\Desktop\\BM_PAL_Tool\\ROLLING.PAL"
        p_bm_file_path = "C:\\Users\\Arek\\Desktop\\BM_PAL_Tool\\ROLLING.BM"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\BM_PAL_Tool\\"
        convert_data(p_pal_file_path, p_bm_file_path, p_out_folder_path)
        
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()