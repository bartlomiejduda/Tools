# -*- coding: utf-8 -*-

# Tested on Python 3.8.0

# Ver    Date        Author
# v0.1   03.08.2020  Bartlomiej Duda




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
    bd_logger("Starting binary search...")    
    
    pattern_file = open(pattern_file_path, 'rb')
    search_file = open(search_file_path, 'rb')
    
    pattern_data = pattern_file.read()
    
    
    s = ConstBitStream(search_file)
    occurances = s.findall(pattern_file, bytealigned=True)
    occurances = list(occurances)
    totalOccurances = len(occurances)    
    
    for i in range(0, len(occurances)):
        occuranceOffset_dec = int(occurances[i]/8)
        occuranceOffset_hex = hex(int(occurances[i]/8) )
        print(str(i+1) + ') ' + 'Offset_hex: ' + str(occuranceOffset_hex) + '  Offset_dec: ' + str(occuranceOffset_dec) )
                               
    
    
    
    pattern_file.close()
    search_file.close()
    bd_logger("Ending binary search...")    
    
    
    
    
    
def main():
    
    main_switch = 1
    # 1 - binary search
    
    
    if main_switch == 1:
        p_pattern_file_path = "C:\\Users\\Arek\\Desktop\\MeMory Dump IKS\\Pattern1.bin"
        p_search_file_path = "C:\\Users\\Arek\\Desktop\\MeMory Dump IKS\\Search1.bin"
        binary_search(p_pattern_file_path, p_search_file_path)

        
    else:
        print("Wrong option selected!")
    
    
    bd_logger("End of main...")    
    
    
    
main()