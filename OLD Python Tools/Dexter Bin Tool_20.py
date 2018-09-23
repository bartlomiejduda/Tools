# -*- coding: utf-8 -*-


#This tool was made by Ikskoks for Xentax community.
#Please don't copy this tool to other forums and sites.

#If you like my tool, please consider visit my fanpage https://www.facebook.com/ikskoks/ and site http://ikskoks.pl/



import argparse
import os
import sys
import time
import struct
import binascii
import re
import io
import glob
import codecs
from tempfile import mkstemp
from shutil import move
from os import remove, close



def unpack_dexter( path_to_bin_file ):
       BIN_file = open(path_to_bin_file, 'rb')
       (BIN_path, BIN_name) = os.path.split(path_to_bin_file)
       (BIN_short_name, extension) = os.path.splitext(BIN_name) 
       number_of_files = struct.unpack('i', BIN_file.read(4))[0]
       tab_filename = []
       tab_size = []
       tab_id = [] 
       tab_offset = []
       for i in range(number_of_files):
              file_name = BIN_file.read(16).split('\x00', 1)[0] 
              file_size = struct.unpack('i', BIN_file.read(4))[0]
              file_id = struct.unpack('i', BIN_file.read(4))[0]
              file_offset = file_id * 2048
              tab_filename.append(file_name)
              tab_size.append(file_size)
              tab_id.append(file_id)
              tab_offset.append(file_offset)
       BIN_file.read(2544)
       BIN_file.read(2044)
       output_folder = BIN_path + '\\' + BIN_short_name
       if not os.path.exists(output_folder):
              os.makedirs(output_folder)       
       for i in range(number_of_files):
              BIN_file.seek(tab_offset[i])
              out_data = BIN_file.read(tab_size[i])
              out_file_path = output_folder + '\\' + tab_filename[i]
              with open(out_file_path,'wb') as f:
                     f.write(out_data)              
       print 'Files extracted successfully.'
       


 
def unpack_cut_files( path_to_data_folder, out_script, out_info_path ): 
       out_script_file = open(out_script_path, 'wt')
       out_info_file = open(out_info_path, 'wt+')
       path = path_to_data_folder + '\\' + "*.cut"
       copy_line = ""
       for fname in glob.glob(path):
              print(fname)
              with open(fname,'r' )as f:
                     while True:
                            line = f.readline()
                            #print line
                            copy_line = line
                            if 'DIALOGUE ENGLISH' in line or 'DIALOGUE FRENCH' in line or 'DIALOGUE GERMAN' in line:
                                   
                                   line = line.split('=')[1].split('\"')[1]
                                   print line
                                   out_script_file.write(line + '\n')
                                   out_info_file.write(fname + '\n')
                            if not copy_line: 
                                   break
       #out_script_file.write('#########' + '\n')
       path_to_instr_file = path_to_data_folder.split('CUT')[0] + 'INSTR.TXT'
       print path_to_instr_file
       
       instr_file = codecs.open(path_to_instr_file,'r', encoding='mbcs')
       while True:
              line = instr_file.readline()
              if 'ENGLISH' in line:
                     line = line.split('=')[1].split('\"')[1]
                     #print line
                     out_script_file.write(line + '\n')
                     out_info_file.write(path_to_instr_file + '\n')
              if not line: break     
       path_to_credits_file = path_to_data_folder.split('CUT')[0] + 'CREDITS.TXT'
       print path_to_credits_file
       credits_file = codecs.open(path_to_credits_file,'r', encoding='mbcs')
       while True:
              line = credits_file.readline()
              if len(line.strip()) > 0:
                     line = line.split('\r')[0]
                     out_script_file.write(line + '\n')
                     out_info_file.write(path_to_credits_file + '\n')
              if not line: break  
              
       print 'Dialogues extracted successfully.'



def replace(file_path, pattern, subst):
       fh, abs_path = mkstemp()
       with open(abs_path, 'w') as new_file:
              with open(file_path) as old_file:
                     for line in old_file:
                            new_file.write(line.replace(pattern, subst))
       close(fh)
       remove(file_path)
       move(abs_path, file_path)       




def pack_cut_files( path_to_data_folder, out_script, out_info_path, out_new_path ): 
       num_lines = sum(1 for line in open(out_info_path))
       out_script_file = open(out_script_path, 'rt')
       out_info_file = open(out_info_path, 'rt')  
       out_new_file = open(out_new_path, 'rt')
       for i in range(num_lines):
              file_path = out_info_file.readline().split('\n')[0]
              pattern = out_script_file.readline().split('\n')[0]
              subst = out_new_file.readline().split('\n')[0].replace('Ż', '\xC4').replace('Ł', '\xC2').replace('Ę', '\xCB').replace('Ć', '\xC7').replace('Ś', '\xDA').replace('Ą', '\xC0').replace('Ź', '\xC1').replace('Ń', '\xD1').replace('ż', '\xC4').replace('ł', '\xC2').replace('ę', '\xCB').replace('ć', '\xC7').replace('ś', '\xDA').replace('ą', '\xC0').replace('ź', '\xC1').replace('ń', '\xD1').replace('Ó', '\xD3').replace('ó', '\xF3')
              replace(file_path, pattern, subst)            
       print "Packed successfully!"




def unpack_tex( path_to_tex ): 
       tex_file = open(path_to_tex, 'rb')
       magic = struct.unpack('i', tex_file.read(4))[0]
       width = struct.unpack('h', tex_file.read(2))[0]
       height = struct.unpack('h', tex_file.read(2))[0]
       tex_size = os.path.getsize(path_to_tex)
       (bmp_path, bmp_name) = os.path.split(path_to_tex)
       (bmp_short_name, temp2) = os.path.splitext(bmp_name) 
       temp_path = bmp_path + '\\'  + bmp_short_name  + 'aa222.data'
       bmp_path = bmp_path + '\\' + bmp_short_name + '.bmp'
       print bmp_path
       bmp_file = open(bmp_path, 'wb+')
       header = '\x42\x4d' + '\x3a\x00\x00\x00' + '\x00\x00\x00\x00' + '\x36\x00\x00\x00' + '\x28\x00\x00\x00'
       bmp_file.write(header)

       bmp_file.write(struct.Struct("<l").pack(width))
       bmp_file.write(struct.Struct("<l").pack(height))
       header2 = '\x01\x00' + '\x10\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\xc4\x0e\x00\x00' '\xf1\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00'
       bmp_file.write(header2)
       
       data_arr = []
       temp_file = open(temp_path, 'wb+')
       for i in range(height):
              data_row = tex_file.read(width*2)
              data_arr.append(data_row)
       data_arr.reverse()
       
       for i in range(height):
              temp_file.write(data_arr[i])
       
       
       temp_file.close()
       temp_size = os.stat(temp_path).st_size
       img = open(temp_path, 'rb')
       bmp_file.close()
       out = open(bmp_path, 'ab')

       for i in range(temp_size / 2):
              bytess = struct.unpack('H', img.read(2))[0]
              strr = bin(bytess)[2:].zfill(16)
              str0 = strr[0]
              str1 = strr[1:6]
              str2 = strr[6:11]
              str3 = strr[11:16]
              str4 = str0 + str3 + str2 + str1
              bytess = int(str4, base=2) 
              conv = struct.Struct("H").pack(bytess)
              out.write(conv)
       print temp_size
       img.close()   
       out.close()
       bmp_file.close()
       os.remove(temp_path)
       


      
def unpack_multiple_tex( path_to_tex_folder ): 
       tex_files =  os.listdir(path_to_tex_folder)    
       for file in tex_files:
              file_path = path_to_tex_folder + '\\' + file
              unpack_tex( file_path )
  
  
  
def pack_tex( path_to_bmp ): 
       (bmp_path, bmp_name) = os.path.split(path_to_bmp)
       (bmp_short_name, temp2) = os.path.splitext(bmp_name) 
       temp_path = bmp_path + '\\'  + bmp_short_name  + 'bb333.data'  
       tex_path = bmp_path + '\\'  + bmp_short_name  + 'bb444.data' 
       bmp_file = open(path_to_bmp, 'rb')
       bmp_file.seek(18)
       width = struct.unpack('l', bmp_file.read(4))[0]
       height = struct.unpack('l', bmp_file.read(4))[0]
       print width, height
       
       data_arr = []
       temp_file = open(temp_path, 'wb+')
       tex_file = open(tex_path, 'wb+')
       for i in range(height):
              data_row = bmp_file.read(width*2)
              data_arr.append(data_row)
       data_arr.reverse()
       
       for i in range(height):
              temp_file.write(data_arr[i])       

       tex_file.write(struct.Struct("<l").pack(2))
       tex_file.write(struct.Struct("<h").pack(width))
       tex_file.write(struct.Struct("<h").pack(height))
       temp_file.seek(0)
       temp_size = os.stat(temp_path).st_size
       for i in range(temp_size / 2):
              bytess = struct.unpack('H', temp_file.read(2))[0]
              strr = bin(bytess)[2:].zfill(16)
              str0 = strr[0]
              str1 = strr[1:6]
              str2 = strr[6:11]
              str3 = strr[11:16]
              str4 = str0 + str3 + str2 + str1
              bytess = int(str4, base=2) 
              conv = struct.Struct("H").pack(bytess)
              tex_file.write(conv)       



def tex_to_dds( path_to_tex ): 
       tex_file = open(path_to_tex, 'rb')
       magic = struct.unpack('i', tex_file.read(4))[0]
       width = struct.unpack('h', tex_file.read(2))[0]
       height = struct.unpack('h', tex_file.read(2))[0]
       tex_size = os.path.getsize(path_to_tex)
       (dds_path, dds_name) = os.path.split(path_to_tex)
       (dds_short_name, temp2) = os.path.splitext(dds_name) 
       dds_path = dds_path + '\\' + dds_short_name + '.dds'
       
       print dds_path
       dds_file = open(dds_path, 'wb+')
       header1 = '\x44\x44\x53\x20' + '\x7c\x00\x00\x00' + '\x0f\x10\x00\x00' 
       dds_file.write(header1)
       dds_file.write(struct.Struct("<l").pack(height))
       dds_file.write(struct.Struct("<l").pack(width))
       header2 = '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x01\x00\x00\x00'
       reserved = '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00'
       
       header3 = '\x20\x00\x00\x00' + '\x40\x00\x00\x00' + '\x00\x00\x00\x00'
       bits_per_pixel = '\x10\x00\x00\x00'
       rgba_bitmasks =  '\x00\x7C\x00\x00' + '\xE0\x03\x00\x00' + '\x1F\x00\x00\x00' + '\x00\x00\x00\x00'
       header4 = '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00'
       
       dds_file.write(header2)
       dds_file.write(reserved)
       dds_file.write(header3)
       dds_file.write(bits_per_pixel)
       dds_file.write(rgba_bitmasks)
       dds_file.write(header4)
       

       data_size = os.stat(path_to_tex).st_size - 8
       for i in range(data_size / 2):
              bytess = struct.unpack('H', tex_file.read(2))[0]
              out_data = rgb_bgr_conversion ( bytess )
              dds_file.write(out_data)
              
       dds_file.close()



def tim_to_dds( path_to_tim ): 
       tim_file = open(path_to_tim, 'rb')
       tim_file.read(8)
       data_size = struct.unpack('i', tim_file.read(4))[0]
       tim_file.read(4)
       width = struct.unpack('h', tim_file.read(2))[0]
       height = struct.unpack('h', tim_file.read(2))[0]

       (dds_path, dds_name) = os.path.split(path_to_tim)
       (dds_short_name, temp2) = os.path.splitext(dds_name) 
       dds_path = dds_path + '\\' + dds_short_name + '.dds'
       print dds_path
       
       dds_file = open(dds_path, 'wb+')
       header1 = '\x44\x44\x53\x20' + '\x7c\x00\x00\x00' + '\x0f\x10\x00\x00' #tu1
       dds_file.write(header1)
       dds_file.write(struct.Struct("<l").pack(height))
       dds_file.write(struct.Struct("<l").pack(width))
       header2 = '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x01\x00\x00\x00'
       reserved = '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00'
       
       header3 = '\x20\x00\x00\x00' + '\x40\x00\x00\x00' + '\x00\x00\x00\x00'
       bits_per_pixel = '\x10\x00\x00\x00' 
       rgba_bitmasks =  '\x00\x7C\x00\x00' + '\xE0\x03\x00\x00' + '\x1F\x00\x00\x00' + '\x00\x00\x00\x00'
       header4 = '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00'
       
       dds_file.write(header2)
       dds_file.write(reserved)
       dds_file.write(header3)
       dds_file.write(bits_per_pixel)
       dds_file.write(rgba_bitmasks)
       dds_file.write(header4)
       data_size -= 12
       
       for i in range(data_size / 2):
              bytess = struct.unpack('H', tim_file.read(2))[0]
              out_data = rgb_bgr_conversion ( bytess )
              dds_file.write(out_data)
              
       dds_file.close()




def rgb_bgr_conversion ( bytess ):
       strr = bin(bytess)[2:].zfill(16)
       str0 = strr[0]
       str1 = strr[1:6]
       str2 = strr[6:11]
       str3 = strr[11:16]
       str4 = str0 + str3 + str2 + str1
       bytess = int(str4, base=2) 
       conv = struct.Struct("H").pack(bytess)    
       return conv



 
def dds_to_tex( path_to_dds ): 
       (dds_path, dds_name) = os.path.split(path_to_dds)
       (dds_short_name, temp2) = os.path.splitext(dds_name) 
       tex_path = dds_path + '\\'  + dds_short_name  + '222.TEX'       
       dds_file = open(path_to_dds, 'rb')
       dds_file.seek(12)
       height = struct.unpack('l', dds_file.read(4))[0]     
       width = struct.unpack('l', dds_file.read(4))[0]
       dds_file.seek(128)  
       
       tex_file = open(tex_path, 'wb+')
       tex_file.write(struct.Struct("<l").pack(2))
       tex_file.write(struct.Struct("<h").pack(width))
       tex_file.write(struct.Struct("<h").pack(height))
       
       data_size = os.stat(path_to_dds).st_size - 128
       for i in range(data_size / 2):
              bytess = struct.unpack('H', dds_file.read(2))[0]
              out_data = rgb_bgr_conversion ( bytess )
              tex_file.write(out_data)       
       
       tex_file.close()
       dds_file.close()





def dds_to_tim( path_to_dds ): 
       (dds_path, dds_name) = os.path.split(path_to_dds)
       (dds_short_name, temp2) = os.path.splitext(dds_name) 
       tim_path = dds_path + '\\'  + dds_short_name  + '222.TIM'       
       dds_file = open(path_to_dds, 'rb')
       dds_file.seek(12)
       height = struct.unpack('l', dds_file.read(4))[0]     
       width = struct.unpack('l', dds_file.read(4))[0]
       dds_file.seek(128)  
       
       tim_file = open(tim_path, 'wb+')
       tim_file.write(struct.Struct("<l").pack(16))
       tim_file.write(struct.Struct("<l").pack(2))
       
       data_size = os.stat(path_to_dds).st_size - 128
       data_size2 = os.stat(path_to_dds).st_size - 128 + 12
       tim_file.write(struct.Struct("<l").pack(data_size2))
       tim_file.write(struct.Struct("<l").pack(0))
       
       tim_file.write(struct.Struct("<h").pack(width))
       tim_file.write(struct.Struct("<h").pack(height))
       
       
       for i in range(data_size / 2):
              bytess = struct.unpack('H', dds_file.read(2))[0]
              out_data = rgb_bgr_conversion ( bytess )
              tim_file.write(out_data)       
       
       tim_file.close()
       dds_file.close()



def gec_to_dds( path_to_gec ): 
       (gec_path, gec_name) = os.path.split(path_to_gec)
       (gec_short_name, temp2) = os.path.splitext(gec_name)        
       gec_file = open(path_to_gec, 'rb')
       gec_file.read(24)    
       offset_of_info_array = struct.unpack('l', gec_file.read(4))[0] 
       image_data_offset = struct.unpack('l', gec_file.read(4))[0] 
       number_of_textures = struct.unpack('H', gec_file.read(2))[0]
       gec_file.seek(offset_of_info_array)
       
       tab_names = []
       tab_widths = []
       tab_heights = []
       tab_size_vals = []
       tab_sizes = []
       tab_offsets = []
       tab_offsets_append = []
       offset = 6352
       for i in range(number_of_textures):
              tex_name = gec_file.read(8)
              gec_file.read(4)
              width = struct.unpack('H', gec_file.read(2))[0]
              height = struct.unpack('H', gec_file.read(2))[0]
              gec_file.read(8)
              tex_size_val = struct.unpack('l', gec_file.read(4))[0]
              gec_file.read(4)
              
              tab_names.append(tex_name.split('\x00')[0])
              tab_widths.append(width)
              tab_heights.append(height)
              tab_size_vals.append(tex_size_val)
              
              offset += (tex_size_val - tab_size_vals[i-1]) * 2
              tab_offsets.append(offset)              

       for i in range(number_of_textures-1):
              tab_sizes.append(tab_offsets[i+1] - tab_offsets[i])
              
       last_offset = tab_offsets[-1]
       last_size = os.stat(path_to_gec).st_size - last_offset
       tab_sizes.append(last_size)
       
       for i in range(number_of_textures):
              print i+1, tab_names[i], tab_widths[i], tab_heights[i], tab_size_vals[i], tab_offsets[i], tab_sizes[i]


       out_dir_path = gec_path + '\\' + gec_short_name + '_OUT'
       print out_dir_path
       if not os.path.exists(out_dir_path):
              os.makedirs(out_dir_path)       

       for i in range(number_of_textures):
              out_dds_path = out_dir_path + '\\' + tab_names[i] + '.dds'
              print out_dds_path

              dds_file = open(out_dds_path, 'wb+')

              
              header1 = '\x44\x44\x53\x20' + '\x7c\x00\x00\x00' + '\x0f\x10\x00\x00' 
              dds_file.write(header1)
              temp_height = tab_sizes[i]  / tab_widths[i]
              #print temp_height
              dds_file.write(struct.Struct("<l").pack(temp_height))
              dds_file.write(struct.Struct("<l").pack(tab_widths[i]))
              header2 = '\x80\x02\x00\x00' + '\x00\x00\x00\x00' + '\x01\x00\x00\x00'
              reserved = '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00'
              
              header3 = '\x20\x00\x00\x00' + '\x40\x00\x00\x00' + '\x00\x00\x00\x00'
              bits_per_pixel = '\x08\x00\x00\x00' 
              
              
              rgba_bitmasks =  '\xE0\x00\x00\x00' + '\x1C\x00\x00\x00' + '\x03\x00\x00\x00' + '\x00\x00\x00\x00'
             
             
             
              header4 = '\x00\x10\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00'
              
              dds_file.write(header2)
              dds_file.write(reserved)
              dds_file.write(header3)
              dds_file.write(bits_per_pixel)
              dds_file.write(rgba_bitmasks)
              dds_file.write(header4)      
              
              gec_file.seek(tab_offsets[i])
              data = gec_file.read(tab_sizes[i])
              dds_file.write(data)
              
              dds_file.close()


              
############################################################################
## BIN FILE

#path_to_bin_file = 'C:\\Users\\MY_USER\\Desktop\\DATA.BIN'
#unpack_dexter( path_to_bin_file )

#path_to_bin_folder = 'C:\\Users\\MY_USER\\Desktop\\DATA'    
#path_to_info_file = 'C:\\Users\\MY_USER\\Desktop\\DATA_info.txt'   
#pack_dexter( path_to_bin_folder, path_to_info_file ) 



##############################################################################################
##CUT FILES

#path_to_data_folder = 'C:\\Users\\MY_USER\\Desktop\\DATA_TEST\\'
#out_script_path = 'C:\\Users\\MY_USER\\Desktop\\out_script.txt'
#out_info_path = 'C:\\Users\\MY_USER\\Desktop\\out_info.txt'
#unpack_cut_files (path_to_data_folder, out_script_path, out_info_path)



#path_to_data_folder = 'C:\\Users\\MY_USER\\Desktop\\DATA_TEST\\'
#out_script_path = 'C:\\Users\\MY_USER\\Desktop\\out_script.txt'
#out_info_path = 'C:\\Users\\MY_USER\\Desktop\\out_info.txt'
#out_new_path = 'C:\\Users\\MY_USER\\Desktop\\out_script_new.txt'       
#pack_cut_files (path_to_data_folder, out_script_path, out_info_path, out_new_path)

##############################################################################################
## TEX FILES
#path_to_tex = 'C:\\Users\\MY_USER\\Desktop\\BUGDEX_E.TEX'       
#unpack_tex( path_to_tex )

#path_to_tex_folder = 'C:\\Users\\MY_USER\\Desktop\TEX' 
#unpack_multiple_tex( path_to_tex_folder )

#path_to_bmp = 'C:\\Users\\MY_USER\\Desktop\\INTR_SBD.bmp'  
#pack_tex( path_to_bmp )




#path_to_tex = 'C:\\Users\\MY_USER\\Desktop\\CFONT.TEX'  
#tex_to_dds( path_to_tex )

#path_to_dds = 'C:\\Users\\MY_USER\\Desktop\\CFONT.dds' 
#dds_to_tex( path_to_dds )


##################################
## TIM FILES

#path_to_tim = 'C:\\Users\\MY_USER\\Desktop\\DISCLAIN.TIM'  
#tim_to_dds( path_to_tim )

path_to_dds = 'C:\\Users\\MY_USER\\Desktop\\DISCLAIN.dds' 
dds_to_tim( path_to_dds )

###################################
## GEC FILES

#path_to_gec = 'C:\\Users\\MY_USER\\Desktop\\UNA.GEC'
#gec_to_dds( path_to_gec )







