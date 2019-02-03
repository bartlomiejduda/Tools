# -*- coding: utf-8 -*-


#This tool was made by Bartlomiej Duda (Ikskoks) for Xentax community.
#Please don't copy this tool to other forums and sites.

#If you like my tool, please consider visit my fanpage https://www.facebook.com/ikskoks/ and site http://ikskoks.pl/
#Please use Python 2.7 to run this tool


import struct

def int_to_hex_string(input_int):
    hex_out = hex(input_int)
    return hex_out
        
def byte_to_int(byte):
    res_byte = struct.unpack('<B', byte)[0]
    return res_byte

def four_bytes_to_int(bytes4):
    res_bytes = struct.unpack('<L', bytes4)[0]
    #print 'bytes4: ' + int_to_hex_string(res_bytes)
    return res_bytes

def split_every(n, s):
    return [ s[i:i+n] for i in xrange(0, len(s), n) ]

def format_checksum(input_checksum_str):
    checksum_splitted = split_every(2, input_checksum_str)
    checksum_rev = []
    checksum_out = ""
    for hh in checksum_splitted:
        checksum_rev.insert(0, hh)
        
    for cc in checksum_rev:
        checksum_out += cc + ' '
        
    return checksum_out

        
def generate_checksum(save_file_path, checksum_offset, overlay_exe_path, overlay_alphabet_base_offset, overlay_key_base_offset): #implementation of checksum generation algorithm
    
    if checksum_offset == 0:
        return 0
    else:
        Save_file = open(save_file_path, 'rb')
        Overlay_exe = open(overlay_exe_path, 'rb')
        
        counter = checksum_offset
        calculation_val = 0 #result of the calculation algorithm
        mask = 2 ** 32 - 1 #for fixed size shift
        
        while True: 
            save_file_val = byte_to_int(Save_file.read(1)) #from save file
            seek_val = overlay_alphabet_base_offset + save_file_val
            Overlay_exe.seek(seek_val)
            alphabet_val = byte_to_int(Overlay_exe.read(1)) #from alphabet
            seek_val = overlay_key_base_offset + (alphabet_val ^ ((calculation_val >> 24)&mask))*4 
            Overlay_exe.seek(seek_val)
            key_val = four_bytes_to_int(Overlay_exe.read(4))
            calculation_val = ((calculation_val << 8)&mask) ^ key_val
            counter -= 1
            if counter <= 0:
                break
            
        Save_file.close()
        Overlay_exe.close()
        checksum_fin = int_to_hex_string(calculation_val).upper().split('0X')[1].rstrip('L')
        checksum_fin_formatted = format_checksum(checksum_fin)
        print "Formatted checksum: " + checksum_fin_formatted
        return checksum_fin_formatted
  

def fix_checksum(input_checksum, checksum_offset, save_file_path): #fix checksum in ".SAV" save file after it was earlier generated in generate_checksum function
    Save_file = open(save_file_path, 'r+b')
    Save_file.seek(checksum_offset)
    filename = save_file_path.split('\\')[-1]
    
    checksum_arr = input_checksum.split(' ')[0:-1]
    
    for checks in checksum_arr:
        checks_int = int(checks, 16)
        Save_file.write(struct.Struct("<B").pack(checks_int))
    
    Save_file.close()
    print 'Checksum fixed for file "' + filename + '".'
 
    
        
#GENERATE CHECKSUM / FIX CHECKSUM      
checksum_offset = 18428 #47FCh
overlay_alphabet_base_offset = 3165676
overlay_key_base_offset = 3151704
save_file_path = 'c:\Program Files (x86)\Steam\steamapps\common\CT Special Forces\Savegame\BLOCK1.sav'
overlay_exe_path = 'c:\Program Files (x86)\Steam\steamapps\common\CT Special Forces\OVERLAY.EXE'

checksum_res = generate_checksum(save_file_path, checksum_offset, overlay_exe_path, overlay_alphabet_base_offset, overlay_key_base_offset)
fix_checksum(checksum_res, checksum_offset, save_file_path)