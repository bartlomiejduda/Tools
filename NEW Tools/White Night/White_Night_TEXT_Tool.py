# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with White Night

# Ver    Date        Author
# v0.1   12.07.2020  Bartlomiej Duda




import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def debug_search(i, in_file_path):
    '''
    Function for debug search in text files
    '''    
    #bd_logger("Starting debug_search...")    
    
    in_file = open(in_file_path, 'rb')
    
    x1 = struct.unpack("<l", in_file.read(4) )[0]
    x2 = struct.unpack("<l", in_file.read(4) )[0]
    x3 = struct.unpack("<l", in_file.read(4) )[0]
    x4 = struct.unpack("<l", in_file.read(4) )[0]
    x5 = struct.unpack("<l", in_file.read(4) )[0]
    
    print(  "%7s" % (str(i) + ") " ) +    "x1=" + str(x1) + " x2=" + str(x2) + " x3=" + str(x3) + " x4=" + str(x4) + " x5=" + str(x5)     +    "%50s" %  ( " NAME: " + str(os.path.basename(in_file.name)))  )
    
    in_file.close()
    
    
    #bd_logger("Ending debug_search...")    
    


def extract_text(in_file_path, out_file_path):
    '''
    Function for extracting text
    '''    
    bd_logger("Starting extract_text...")    
    
    in_file = open(in_file_path, 'rb')  
    out_file = open(out_file_path, 'wt+')  
    
    
    #header read
    unk = in_file.read(12)
    num_of_lines = struct.unpack("<l", in_file.read(4) )[0]
    num_of_lines2 = in_file.read(4)
    
    
    #text read 
    for i in range(num_of_lines):
        line_len = struct.unpack("<l", in_file.read(4) )[0]
        b_str = in_file.read(line_len)
        s_str = b_str.decode("utf8")
        
        #print( str(i+1) + ") " + s_str)
        
        out_file.write( s_str + "\n")
        
    
    in_file.close()
    out_file.close()
    
    bd_logger("Ending extract_text...") 
    
    
def main():
    
    main_switch = 2
    # 1 - debug search
    # 2 - extract text 
    
    
    if main_switch == 1:
        #p_in_file_path = "C:\\Users\\Arek\\Desktop\\Textes\\01-Exterior~SUB.xls.LocalText.gen.EN"
        p_i = 1
        
        p_in_folder = "C:\\Users\\Arek\\Desktop\\Textes\\"
        
        p_i = 0
        for filename in os.listdir(p_in_folder):
            #print(os.path.join(p_in_folder, filename))
            p_i += 1
            p_in_file_path = os.path.join(p_in_folder, filename)
            debug_search(p_i, p_in_file_path)
      
      
    elif main_switch == 2:  
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\Textes\\01-Exterior~SUB.xls.LocalText.gen.EN"
        p_out_file_path = "C:\\Users\\Arek\\Desktop\\Textes\\01-Exterior~SUB.xls.LocalText.gen.EN.ini"
        extract_text(p_in_file_path, p_out_file_path)
        
 
   
        
    else:
        print("Wrong option selected!")
    
    
    bd_logger("End of main...")    
    
    
    
main()