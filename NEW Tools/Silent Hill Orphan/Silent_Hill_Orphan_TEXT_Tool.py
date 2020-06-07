# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Silent Hill: Orphan (Java)

# Ver    Date        Author
# v0.1   17.04.2020  Bartlomiej Duda
# v0.2   07.06.2020  Bartlomiej Duda



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
    
    
    
def import_lan(in_INI_path, out_LAN_path):
    '''
    Function for importing text to LAN files
    '''    
    bd_logger("Starting import_lan...") 
    
    ini_file = open(in_INI_path, 'rt')
    out_file = open(out_LAN_path, 'wb+')    
    
    count_lines = 0
    for line in ini_file:
        count_lines += 1   #count lines in INI file
        
    ini_file.seek(0)
    print("Num of lines: " + str(count_lines))
    
    line_arr = []
    i = 0
    for line in ini_file:
        i += 1
        line = line.split("BD_TRANSLATE_TEXT=")[-1]   #read lines from INI
        #print(str(i) + ") " + line)
        line_arr.append(line)
    
    #writing data    
    B_count_lines = struct.Struct(">h").pack(count_lines)   
    out_file.write(B_count_lines)
    
    for line in line_arr:
        B_s_len = struct.Struct(">h").pack( len(line)-1 )
        B_str = line.rstrip("\n").encode("utf8")
        
        out_file.write(B_s_len)
        out_file.write(B_str)


    
    ini_file.close()
    out_file.close()
    bd_logger("Ending import_lan...") 
    
    
    
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
    
    
def import_properties(in_INI_path, out_PROP_path):
    '''
    Function for importing text to properties files
    '''    
    bd_logger("Starting import_prop...")  
    
    INI_file = open(in_INI_path, 'rt')
    PROP_file = open(out_PROP_path, 'wt+', newline='\x0A')
    
    for line in INI_file:
        line = line.split("BD_TRANSLATE_TEXT=")[-1]
        PROP_file.write(line)
    
    
    INI_file.close()
    PROP_file.close()
    bd_logger("Ending import_prop...")      
    
    
    
def main():
    
    main_switch = 2
    # 1 - text export 
    # 2 - text import 
    
    
    if main_switch == 1:
        in_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_Orphan_SPOL\\en.lan"
        out_ini_path = "C:\\Users\\Arek\\Desktop\\Silent_Hill_Orphan_SPOL\\en.lan_out.ini"
        export_lan(in_filepath, out_ini_path)
        
        in_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_Orphan_SPOL\\en.properties"
        out_ini_path = "C:\\Users\\Arek\\Desktop\\Silent_Hill_Orphan_SPOL\\en.properties_out.ini"
        export_properties(in_filepath, out_ini_path)   
        
    elif main_switch == 2:
        in_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_Orphan_SPOL\\en.lan_out.ini"
        out_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_Orphan_SPOL\\en.lan_NEW"
        import_lan(in_filepath, out_filepath)    
        
        in_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_Orphan_SPOL\\en.properties_out.ini"
        out_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_Orphan_SPOL\\en.properties_NEW"  
        import_properties(in_filepath, out_filepath) 
        
    else:
        print("Wrong option selected!")
    
    
    bd_logger("End of main...")    
    
    
    
main()