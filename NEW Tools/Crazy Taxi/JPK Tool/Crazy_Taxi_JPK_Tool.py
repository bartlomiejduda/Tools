# -*- coding: utf-8 -*-


#This tool was made by Bartlomiej Duda (Ikskoks) for Xentax community.
#Please don't copy this tool to other forums and sites.

#If you like my tool, please consider visit my fanpage https://www.facebook.com/ikskoks/ and site http://ikskoks.pl/
#Please use Python 2.7 to run this tool


import struct
import os



def adjust_counter(counter):
    strr = ""
    if counter < 10 and counter >= 0:
        strr = '0' + str(counter)
    else:
        strr = str(counter)
    return strr
        

def unpack_JPK(JPK_file_path, output_folder, repack_data_file_path):
    
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)    
    
    JPK_file = open(JPK_file_path, 'rb')
    repack_data_file = open(repack_data_file_path, 'wb+')
    i = 0
    extension = ""
    while True:
        i += 1
        magic = JPK_file.read(4) #magic (Jdds or Jpng)
        try:
            magic[0]
        except:
            break
        if magic == 'Jdds':
            extension = '.dds'
        elif magic == 'Jpng':
            extension = '.png'
        else:
            extension = '.dat'
        texture_size = struct.unpack('<I', JPK_file.read(4))[0]
        unknown1 = JPK_file.read(4) #zeroes
        width = JPK_file.read(4) #width
        height = JPK_file.read(4) #height
        unknown2 = JPK_file.read(4) #zeroes
        texture_data = JPK_file.read(texture_size)

        out_path = output_folder + '\\' + 'texture' + adjust_counter(i) + extension
        DDS_out_file = open(out_path, 'wb+')
        DDS_out_file.write(texture_data)
        DDS_out_file.close()
        print "File saved to " + out_path
        repack_data_file.write(magic + ';' + unknown1 + ';' + width + ';' + height + ';' + unknown2 + '\x0D\x0A') #repack data save
              
    JPK_file.close()
    repack_data_file.close()
    print "Unpacking finished successfully!"

        
#def repack_JPK(new_JPK_file_path, input_folder, repack_data_file_path):     <------TODO
    #new_JPK_file = open(JPK_file_path, 'wb+')
    #repack_data_file = open(repack_data_file_path, 'rb')    
    #for file in input_folder:
        #texture_file = open(file, 'rb')
        #texture_data = texture_file.read()
        #texture_file.close()
        #new_JPK_file.write(magic)
        #new_JPK_file.write( struct.Struct("<l").pack( len(texture_data) ) )
 
 
        
#JPK UNPACK        
JPK_file_path = 'C:\\CRAZY TAXI\\eng.jpk'
output_folder = 'C:\\CRAZY TAXI\\eng'
repack_data_file_path = 'C:\\CRAZY TAXI\\eng.jpk_repack.dat'
unpack_JPK(JPK_file_path, output_folder, repack_data_file_path)