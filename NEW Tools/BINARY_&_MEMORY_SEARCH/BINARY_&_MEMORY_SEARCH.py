# -*- coding: utf-8 -*-

# Tested on Python 3.8.0

# Ver    Date        Author
# v0.1   03.08.2020  Bartlomiej Duda
# v0.2   09.08.2020  Bartlomiej Duda
# v0.3   10.08.2020  Bartlomiej Duda




import os
import sys
import struct
from bitstring import ConstBitStream   #need to install it
import ctypes



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def binary_search(pattern_file_path, search_file_path):
    '''
    Function for searching through binary files 
    '''    
    #bd_logger("Starting binary search...")    
    
    pattern_file = open(pattern_file_path, 'rb')
    search_file = open(search_file_path, 'rb')
    
    pattern_data = pattern_file.read()
    
    search_file_size = os.path.getsize(search_file_path)
    
    
    s = ConstBitStream(search_file)
    occurances = s.findall(pattern_file, bytealigned=True)
    occurances = list(occurances)
    totalOccurances = len(occurances)    
    
    for i in range(0, len(occurances)):
        occuranceOffset_dec = int(occurances[i]/8)
        occuranceOffset_hex = hex(int(occurances[i]/8) )
        print(str(i+1) + ') ' + 'Offset_hex: ' + str(occuranceOffset_hex) + '  Offset_dec: ' + str(occuranceOffset_dec) +  " File_name: " + str( search_file_path.split("\\")[-1] ) 
              + " File_size: " + str(hex(search_file_size) ) + " \\ " + str(search_file_size)
              
              )
                               
    
    
    
    pattern_file.close()
    search_file.close()
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
    
    bd_logger("Starting main...") 
    
    main_switch = 3
    # 1 - binary search
    # 2 - binary search in multiple files
    # 3 - memory search (experimental)
    
    
    p_pattern_file_path = "C:\\Users\\Arek\\Desktop\\MeMory Dump IKS\\Tex_0019.dds.bin"
    
    if main_switch == 1:
        #p_search_file_path = "C:\\Users\\Arek\\Desktop\\MeMory Dump IKS\\pdump_7548.bin"
        p_search_file_path = "C:\\Users\\Arek\\Desktop\\Dumped.exe"
        binary_search(p_pattern_file_path, p_search_file_path)


    elif main_switch == 2:
        p_search_folder = "C:\\Users\\Arek\\Desktop\\TEMP1\\"
        i = 0
        for root, dirs, files in os.walk(p_search_folder):
            for name in files:
                i += 1
                p_search_file_path = os.path.join(root, name)
                #print(str(i) + ") " + "Searching in " + str(p_search_file_path) )  
                binary_search(p_pattern_file_path, p_search_file_path)
                
    elif main_switch == 3:
        
        p_pid = 3344 
        p_temp_file_path = "C:\\Users\\Arek\\Desktop\\temp1.bin"
        p_start_addr = 0x400000  
        p_buffer_size = 0x1000 
        p_MAX_ADDRESS = 0x80000000        
        memory_search(p_pid, p_pattern_file_path, p_temp_file_path, p_start_addr, p_buffer_size, p_MAX_ADDRESS)
        
        
    else:
        print("Wrong option selected!")
    
    
    bd_logger("End of main...")    
    
    
 
 
 
 
    
main()