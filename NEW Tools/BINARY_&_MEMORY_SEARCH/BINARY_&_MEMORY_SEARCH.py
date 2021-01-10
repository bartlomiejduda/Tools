# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''

# Tested on Python 3.7.0

# Ver    Date        Author             Comment
# v0.1   03.08.2020  Bartlomiej Duda    -
# v0.2   09.08.2020  Bartlomiej Duda    -
# v0.3   10.08.2020  Bartlomiej Duda    -
# v0.4   10.08.2020  Bartlomiej Duda    -
# v0.5   04.12.2020  Bartlomiej Duda    Minor changes
# v0.6   07.01.2021  Bartlomiej Duda    Added exception handling for nmap error in binary_search




import os
import sys
import struct
from bitstring import ConstBitStream   #need to install it ("pip install bitstring")
import ctypes
import datetime


def bd_logger(in_str):
    '''
    Function for logging debug messages
    '''      
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def binary_search(pattern_file_path, search_file_path, match_flag, match_file_path):
    '''
    Function for searching through binary files 
    '''    
    #bd_logger("Starting binary search...")    
    
    pattern_file = open(pattern_file_path, 'rb')
    search_file = open(search_file_path, 'rb')
    
    pattern_data = pattern_file.read()
    
    search_file_size = os.path.getsize(search_file_path)
    
    try:
        s = ConstBitStream(search_file)
    except:
        bd_logger("Couldn't nmap an empty file! --> " + search_file_path)
        return
    occurances = s.findall(pattern_file, bytealigned=True)
    occurances = list(occurances)
    totalOccurances = len(occurances)  
    match_arr = []
    
    for i in range(0, len(occurances)):
        occuranceOffset_dec = int(occurances[i]/8)
        occuranceOffset_hex = hex(int(occurances[i]/8) )
        print(str(i+1) + ') ' + 'Offset_hex: ' + str(occuranceOffset_hex) + '  Offset_dec: ' + str(occuranceOffset_dec) +  " File_name: " + str( search_file_path.split("\\")[-1] ) 
              + " File_size: " + str(hex(search_file_size) ) + " \\ " + str(search_file_size)  )
        
        if match_flag == 1:
            match_arr.append(occuranceOffset_dec)
                               
    pattern_file.close()
    search_file.close()
    
    if match_flag == 1:
        
        match_file = open(match_file_path, "rt")
        
        for match_entry in match_arr:
            
            print("\n### " + "match_entry: " + str(match_entry) + " ###")
            match_file.seek(0)
            
            i = 0
            for line in match_file:
                #print(line)
                i += 1
                i_mem_address = int(line.split(" file_offset=")[0].split("mem_address=")[-1])
                i_file_offset = int(line.split(" file_offset=")[-1])
                i_match_entry = int(match_entry)
                
                if i_file_offset > i_match_entry:
                    #print("F_OFF: " + str(i_file_offset) )
                    break
                
            j = 0  
            match_file.seek(0)
            for line in match_file:
                j += 1
                
                if j == i-1:
                    print("MATCHED LINE: " + line.rstrip("\n"))
                    i_mem_address = int(line.split(" file_offset=")[0].split("mem_address=")[-1])
                    i_file_offset = int(line.split(" file_offset=")[-1])
                    i_match_entry = int(match_entry)
                    i_off_diff = int(i_match_entry - i_file_offset)
                    i_real_mem_address = int(i_mem_address + i_off_diff)
                    
                    print("REAL_MEM_ADRESS_dec=" + str(i_real_mem_address) + "  REAL_MEM_ADRESS_hex=" + str(hex(i_real_mem_address)) 
                          + "  page_address_dec=" + str(i_mem_address) + "  page_address_hex=" + str(hex(i_mem_address)) 
                          )
                    

            
    
    #bd_logger("Ending binary search...")   
    
  
def memory_search(pid, pattern_file_path, temp_file_path, start_addr, buffer_size, MAX_ADDRESS):

    if os.path.exists(temp_file_path):
        os.remove(temp_file_path)        

    
    processHandle = ctypes.windll.kernel32.OpenProcess(0x10, False, pid)
    buffer = (ctypes.c_byte * buffer_size)()
    bytesRead = ctypes.c_ulonglong(0)
    i = start_addr
    j = 0
    
    
    while(1):
    
        j += 1
        result = ctypes.windll.kernel32.ReadProcessMemory(processHandle, ctypes.c_void_p(start_addr), buffer, len(buffer), ctypes.byref(bytesRead))
        e = ctypes.windll.kernel32.GetLastError()
        
        print(str(j) + ") " + 'result: ' + str(result) + ', err code: ' + str(e) + " i=" + str(hex(i)) + " i_dec=" + str(i) )
        out_data = bytearray(buffer)
        
        temp_file = open(temp_file_path, "ab+")
        temp_file.write(out_data)
        temp_file.close()
        
        binary_search(pattern_file_path, temp_file_path)
        i+= buffer_size

        if i > MAX_ADDRESS:
            break


    ctypes.windll.kernel32.CloseHandle(processHandle)
            
        
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''       
    bd_logger("Starting main...") 
    
    main_switch = 4
    # 1 - binary search
    # 2 - binary search in multiple files
    # 3 - memory search (experimental)
    # 4 - binary search + match row from TotalDump output (experimental)

    
    
    # HOW TO USE THIS PROGRAM - general notes 
    # -You need to adjust main function for your needs
    # e.g. adjust paths and variables 
    # -Change main_switch value to the option you want to use
    
    # OPTIONS 1 & 2 INSTRUCTIONS:
    # It's regular binary search, just adjust paths and execute function.
    
    # OPTION 3 INSTRUCTIONS:
    # It's memory search. Define\change all required variables and execute function.
    
    # OPTION 4 INSTRUCTIONS:
    # 1. Run TotalDump.exe to generate output. You need special version of TotalDump which is also able to generate TXT file as well.
    # 2. Define paths to files outputted by TotalDump and execute the function.
    
    
    
    p_pattern_file_path = "C:\\Users\\Arek\\Desktop\\BINARY_&_MEMORY_SEARCH\\dump3.bin"
    
    if main_switch == 1:
        p_search_file_path = "C:\\Users\\Arek\\Desktop\\CSA\\p_00000000.csa"
        binary_search(p_pattern_file_path, p_search_file_path, 0, "")


    elif main_switch == 2:
        p_search_folder = "C:\\Users\\Arek\\Desktop\\CSA\\p_009_out\\"
        i = 0
        for root, dirs, files in os.walk(p_search_folder):
            for name in files:
                i += 1
                p_search_file_path = os.path.join(root, name)
                #print(str(i) + ") " + "Searching in " + str(p_search_file_path) )  
                binary_search(p_pattern_file_path, p_search_file_path, 0, "")
                
    
    elif main_switch == 3:
        p_pid = 3344 
        p_temp_file_path = "C:\\Users\\Arek\\Desktop\\temp1.bin"
        p_start_addr = 0x400000  
        p_buffer_size = 0x1000 
        p_MAX_ADDRESS = 0x80000000        
        memory_search(p_pid, p_pattern_file_path, p_temp_file_path, p_start_addr, p_buffer_size, p_MAX_ADDRESS)
        
    
    elif main_switch == 4:
        p_search_file_path = "C:\\Users\\Arek\\Desktop\\pdump_5940.bin"
        p_match_file_path = "C:\\Users\\Arek\\Desktop\\pdump_5940.txt"
        binary_search(p_pattern_file_path, p_search_file_path, 1, p_match_file_path)        
        
        
    else:
        print("Wrong option selected!")
    
    
    bd_logger("End of main...")    
    
    
 
 
 
 
    
main()