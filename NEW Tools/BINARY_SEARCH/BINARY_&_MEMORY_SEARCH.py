# -*- coding: utf-8 -*-

# Tested on Python 3.8.0

# Ver    Date        Author
# v0.1   03.08.2020  Bartlomiej Duda
# v0.2   09.08.2020  Bartlomiej Duda




import os
import sys
import struct
from bitstring import ConstBitStream   #need to install it



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
        
        
        import ctypes, struct

        pid = 7876  
        processHandle = ctypes.windll.kernel32.OpenProcess(0x10, False, pid)
        
        base_addr = 0x400000  
        buffer = (ctypes.c_byte * 4096)()
        bytesRead = ctypes.c_ulonglong(0)
        result = ctypes.windll.kernel32.ReadProcessMemory(processHandle, ctypes.c_void_p(base_addr), buffer, len(buffer), ctypes.byref(bytesRead))
        e = ctypes.windll.kernel32.GetLastError()
        
        print('result: ' + str(result) + ', err code: ' + str(e))
        #print('data: ' + str(struct.unpack('Q', buffer)[0]))
        #print("bd_buffer: " + str(bytearray(buffer))    )
        
        out_data = bytearray(buffer)
        
        
        temp_file_path = "C:\\Users\\Arek\\Desktop\\temp1.bin"
        temp_file = open(temp_file_path, "wb+")
        temp_file.write(out_data)
        temp_file.close()
        
        
        
        
        ctypes.windll.kernel32.CloseHandle(processHandle)
                
        
        
        
    else:
        print("Wrong option selected!")
    
    
    bd_logger("End of main...")    
    
    
 
 
 
 
    
main()