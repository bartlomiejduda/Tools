# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Silent Hill: Orphan (Java)

# Ver    Date        Author
# v0.1   17.04.2020  Bartlomiej Duda




VERSION_NUM = "v0.1"

import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def export_lan(in_LAN_filepath, out_INI_path):
    '''
    Function for exporting text from LAN files
    '''    
    bd_logger("Starting export_lan...")    
    
    lan_file = open(in_LAN_filepath, 'rb')
    out_file = open(out_INI_path, 'wt+')
    num_of_lines = struct.unpack('>h', lan_file.read(2))[0]
    print("num_of_lines: " + str(num_of_lines) )
    
    line_arr = []
    for i in range(num_of_lines):
        line_length = struct.unpack('>h', lan_file.read(2))[0]
        line = lan_file.read(line_length).decode("utf8")
        #print(str(i+1) + ") Line: " + line)
        line_arr.append(line)
        
    for line in line_arr:
        line = "BD_TRANSLATE_TEXT=" + line + "\n"
        out_file.write(line)
    
    
    lan_file.close()
    out_file.close()
    bd_logger("Ending export_lan...")    
    
    
    
def export_properties(in_PROP_filepath, out_INI_path):
    '''
    Function for exporting text from properties files
    '''    
    bd_logger("Starting export_prop...")    
    
    prop_file = open(in_PROP_filepath, 'rt', newline='\x0A')
    out_file = open(out_INI_path, 'wt+')
    
    line_arr = []
    for line in prop_file:
        line = "BD_TRANSLATE_TEXT=" + line.replace("\x0A", "") + "\n"
        out_file.write(line)
    
    
    prop_file.close()
    out_file.close()
    bd_logger("Ending export_prop...")       
    
    
    
def main():
    
    main_switch = 1
    # 1 - text export 
    
    
    if main_switch == 1:
        in_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_Orphan_SPOL\\en.lan"
        out_ini_path = "C:\\Users\\Arek\\Desktop\\Silent_Hill_Orphan_SPOL\\en.lan_out.ini"
        export_lan(in_filepath, out_ini_path)
        
        in_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_Orphan_SPOL\\en.properties"
        out_ini_path = "C:\\Users\\Arek\\Desktop\\Silent_Hill_Orphan_SPOL\\en.properties_out.ini"
        export_properties(in_filepath, out_ini_path)        
    
    
    bd_logger("End of main...")    
    
    
    
main()