# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''

# Program tested on Python 3.7.0

# Ver    Date        Author               Comment
# v0.1   27.01.2021  Bartlomiej Duda      -






def bd_logger(in_str):
    '''
    Function for logging debug messages
    '''   
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    


from itertools import cycle
def xore(data, key):
    '''
    Function for XORing data
    '''  
    return bytes(a ^ b for a, b in zip(data, cycle(key)))


def get_string2(in_file):
    '''
    Function for reading null terminated string from binary file
    '''  
    out_name = ""
    while 1:
        ch = struct.unpack("c", in_file.read(1))[0]
        
        if ord(ch) != 0:
            try:
                out_name += ch.decode("utf8")
            except:
                temp_hex = hex(ord(ch))  # workaround for invalid characters...
                temp_str = "<" + str(temp_hex) + ">"
                out_name += temp_str
                
        else:
            break
    return out_name


def get_string(in_file):
    '''
    Function for reading null terminated string from binary file
    '''  
    out_name = ""
    b_out_name = b''
    file_size = os.path.getsize(in_file.name)
    while 1:  
        curr_offset = in_file.tell() 
        if curr_offset == file_size:  # EOF reached, aborting
            break
        
        ch = struct.unpack("c", in_file.read(1))[0]
        
        if ord(ch) != 0:
            b_out_name += ch  
        else:
            break
        
    out_name = b_out_name.decode("utf8")
    return out_name        
    
    
    
 
 
 
 
 
 
 