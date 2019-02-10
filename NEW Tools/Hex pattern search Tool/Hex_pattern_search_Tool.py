# -*- coding: utf-8 -*-


#This tool was made by Bartlomiej Duda (Ikskoks) for Xentax community.
#Please don't copy this tool to other forums and sites.

#If you like my tool, please consider visit my fanpage https://www.facebook.com/ikskoks/ and site http://ikskoks.pl/
#Please use Python 2.7 to run this tool


import struct
import os
import binascii
import fnmatch


class Errorlog:
    def __init__(self, fkt):
            self.fkt = fkt    

def split_every(n, s):
    err.fkt = 'FUN010'
    return [ s[i:i+n] for i in xrange(0, len(s), n) ]

def format_hex(input_int, val_length):
    err.fkt = 'FUN020'
    cnt = 0
    if val_length == 4:
        hex_temp = struct.Struct("<L").pack(input_int)
    elif val_length == 2:
        hex_temp = struct.Struct("<H").pack(input_int)
    elif val_length == 1:
        hex_temp = struct.Struct("<B").pack(input_int)
    else:
        print 'Invalid value length!' + ' Fkt: ' + err.fkt
        return -1
    
    err.fkt = 'FUN021'
    hex_temp2 = binascii.hexlify(hex_temp).upper()
    
    hh_temp = ''
    hex_out = ''
    err.fkt = 'FUN022'
    for hh in hex_temp2:
        cnt += 1
        hh_temp += hh
        if cnt % 2 == 0:
            hex_out += hh_temp + ' '
            hh_temp = ''
    return hex_out

def one_byte_to_int_LE(byte1):
    err.fkt = 'FUN030'
    res_bytes = struct.unpack('<B', byte1)[0]
    return res_bytes

def one_byte_to_int_BE(byte1):
    err.fkt = 'FUN040'
    res_bytes = struct.unpack('>B', byte1)[0]
    return res_bytes

def two_bytes_to_int_LE(bytes2):
    err.fkt = 'FUN050'
    res_bytes = struct.unpack('<H', bytes2)[0]
    return res_bytes

def two_bytes_to_int_BE(bytes2):
    err.fkt = 'FUN060'
    res_bytes = struct.unpack('>H', bytes2)[0]
    return res_bytes


def four_bytes_to_int_LE(bytes4):
    err.fkt = 'FUN070'
    res_bytes = struct.unpack('<L', bytes4)[0]
    return res_bytes

def four_bytes_to_int_BE(bytes4):
    err.fkt = 'FUN080'
    res_bytes = struct.unpack('>L', bytes4)[0]
    return res_bytes

def hex_to_ascii(input_hex):
    err.fkt = 'FUN100'
    hex_splitted = input_hex.split(' ')
    ascii_out = ''
    
    err.fkt = 'FUN101'
    for hh in hex_splitted:
        if hh == hex_splitted[-1]:
            continue
        
        err.fkt = 'FUN102'
        hh_ascii = hh.decode("hex")
        err.fkt = 'FUN103'
        if binascii.unhexlify(hh) <= binascii.unhexlify('1F') or binascii.unhexlify(hh) >= binascii.unhexlify('7F'):
            hh_ascii = '.'
        err.fkt = 'FUN104'    
        ascii_out += hh_ascii
    return ascii_out

def adjust_counter(input_counter):
    err.fkt = 'FUN110'
    counter_str = ''
    if input_counter < 10:
        counter_str = '0' + str(input_counter)
    else:
        counter_str = str(input_counter)
    return counter_str

def get_file_size(input_file_path):
    err.fkt = 'FUN120'
    if os.path.isfile(input_file_path):
        file_info = os.stat(input_file_path)
        return file_info.st_size
    
def do_calculation(input_val, input_val2, operator):
    result = 0
    input_val_int = int(input_val)
    input_val2_int = int(input_val2)
    err.fkt = 'FUN130'
    if operator == '+':
        result = input_val_int + input_val2_int
    elif operator == '-':
        result = input_val_int - input_val2_int
    elif operator == '*':
        result = input_val_int * input_val2_int
    elif operator == '/':
        result = input_val_int / input_val2_int    
    elif operator == '%':
        result = input_val_int % input_val2_int   
    elif operator == '^':
        result = input_val_int ^ input_val2_int  
    elif operator == '>>':
        result = input_val_int >> input_val2_int 
    elif operator == '<<':
        result = input_val_int << input_val2_int  
    else:
        err.fkt = 'FUN131'
        print ' Invalid operator! ' + 'Fkt: ' + err.fkt
        return -1
    return result
        
        
def search_pattern(input_folder, mode, offset, val_length, show_filenames, show_paths, endianess, arr_extensions, 
                   show_extensions, all_extensions, show_file_size, enable_calc, calc_offset, operator, enable_regex, regex_filename_filter): 
    
    stop_arr = []
    counter = 0
    for dirname, dirnames, filenames in os.walk(input_folder):
        for filename in filenames:
            
            err.fkt = 'PST010'
            good_ext = 'FALSE'
            for ext in arr_extensions:
                if all_extensions == 1:
                    good_ext = 'TRUE'
                    break
                if filename.upper().endswith(ext.upper()):
                    good_ext = 'TRUE'
                    
            if good_ext != 'TRUE':
                continue        
            
            err.fkt = 'PST020'
            if enable_regex == 1:
                if  filename not in fnmatch.filter(filenames, regex_filename_filter):
                    continue
            
            
            
            err.fkt = 'PST030'
            file_path = os.path.join(dirname, filename)
            file_name = file_path.split('\\')[-1]
            file_ext = '.' + file_path.split('\\')[-1].split('.')[-1]
            file_size = get_file_size(file_path)
            
            err.fkt = 'PST040'
            if offset >= file_size:
                print 'Offset ' + offset + ' is larger than file size!'
                return -1
            elif offset >= file_size - val_length:
                print 'Offset ' + offset + ' is to large to get the value in file. '   + file_name_show + path_show + ext_show
            
            try:
                counter += 1
                err.fkt = 'PST050'
                Opened_file = open(file_path, 'rb')
                err.fkt = 'PST060'
                Opened_file.seek(offset)
                err.fkt = 'PST070'
                val = Opened_file.read(val_length)
                

                if val_length == 4:
                    err.fkt = 'PST080'
                    val_hex = format_hex(four_bytes_to_int_LE(val), val_length)
                elif val_length == 2:
                    err.fkt = 'PST090'
                    val_hex = format_hex(two_bytes_to_int_LE(val), val_length)  
                elif val_length == 1:
                    err.fkt = 'PST100'
                    val_hex = format_hex(one_byte_to_int_LE(val), val_length)
                else:
                    print 'Unsupported value length!'
                    return -1

                err.fkt = 'PST110'
                if enable_calc == 1:
                    if calc_offset < file_size - val_length:
                        Opened_file.seek(calc_offset)
                        calc_val = Opened_file.read(val_length)
                    else:
                        print 'Wrong calculation offset! ' + 'Fkt: ' + err.fkt
                        
                        

                err.fkt = 'PST120'
                if show_filenames == 1:
                    file_name_show = ' File: ' + file_name
                else:
                    file_name_show = ''
                    
                err.fkt = 'PST130'    
                if show_paths == 1:
                    path_show = ' Path: ' + file_path
                else:
                    path_show = ''    
                    
                err.fkt = 'PST140' 
                if show_extensions == 1:
                    ext_show = ' Extension: ' + file_ext
                else:
                    ext_show = ''
                    
                err.fkt = 'PST150' 
                if show_file_size == 1:
                    size_show = ' File_Size: ' + str(file_size)
                else:
                    ext_show = ''                
                    

                
                err.fkt = 'PST160'
                val_ascii = hex_to_ascii(val_hex)
                
                err.fkt = 'PST170'
                if mode == 'STOP_IMMEDIATE':
                    stop_arr.append(val_hex)
                    for value in stop_arr:
                        if value != val_hex:
                            print 'Found different value: ' + val_hex + ' \\ ' + val_ascii +           size_show + file_name_show + path_show + ext_show
                            return 0                
                
                
                if endianess == 'L':
                    err.fkt = 'PST180'
                    if val_length == 4:
                        val_int_LE = four_bytes_to_int_LE(val)
                        if enable_calc == 1:
                            calc_val_final = four_bytes_to_int_LE(calc_val)
                            calc_result = do_calculation(val_int_LE, calc_val_final, operator) 
                    elif val_length == 2:
                        val_int_LE = two_bytes_to_int_LE(val)
                        if enable_calc == 1:
                            calc_val_final = two_bytes_to_int_LE(calc_val)
                            calc_result = do_calculation(val_int_LE, calc_val_final, operator)                        
                    elif val_length == 1:
                        val_int_LE = one_byte_to_int_LE(val)
                        if enable_calc == 1:
                            calc_val_final = one_byte_to_int_LE(calc_val)
                            calc_result = do_calculation(val_int_LE, calc_val_final, operator)    
                     
                    err.fkt = 'PST190'        
                    if enable_calc == 1:
                        calc_show = ' Calc result: ' + str(calc_result)
                    else:
                        calc_show = ''
                        
                    print adjust_counter(counter) + ') ' + 'Hex: ' + val_hex +' Ascii: ' + val_ascii +  ' Int_LE: ' + str(val_int_LE) +       calc_show + size_show + file_name_show + path_show + ext_show
                    
                elif endianess == 'B':
                    err.fkt = 'PST200'
                    if val_length == 4:
                        val_int_BE = four_bytes_to_int_BE(val)
                        if enable_calc == 1:
                            calc_val_final = four_bytes_to_int_BE(calc_val)
                            calc_result = do_calculation(val_int_BE, calc_val_final, operator)                         
                    elif val_length == 2:
                        val_int_BE = two_bytes_to_int_BE(val)
                        if enable_calc == 1:
                            calc_val_final = two_bytes_to_int_BE(calc_val)
                            calc_result = do_calculation(val_int_BE, calc_val_final, operator)                          
                    elif val_length == 1:
                        val_int_BE = one_byte_to_int_BE(val)    
                        if enable_calc == 1:
                            calc_val_final = one_byte_to_int_BE(calc_val)
                            calc_result = do_calculation(val_int_BE, calc_val_final, operator)  
                         
                    err.fkt = 'PST210'        
                    if enable_calc == 1:
                        calc_show = ' Calc result: ' + calc_result
                    else:
                        calc_show = ''                    
                        
                    print adjust_counter(counter) + ') ' + 'Hex: ' + val_hex +' Ascii: ' + val_ascii +  ' Int_BE: ' + str(val_int_BE) +       calc_show + size_show +  file_name_show + path_show + ext_show
                else:
                    print 'Unsupported endianess!'
                    return -1
                    

                
                Opened_file.close()
            except Exception as e:
                print 'Error occured in file ' + file_name + '!'
                print(str(e) + ', fkt: ' + err.fkt)
                continue            
            
    
    
  



p_input_folder = 'c:\\Program Files (x86)\\Steam\\steamapps\\common\\Adventure Time Finn and Jake Investigations'
p_mode = "NORMAL" #values: NORMAL, STOP_IMMEDIATE
p_offset = 8 #values: 0 to eof
p_val_length = 4   #values: 4, 2, 1
p_show_filenames = 1 #values: 0, 1
p_show_paths = 0 #values: 0, 1
p_endianess = 'L' #values: L, B
p_arr_extensions = ['.loc']
p_show_extensions = 0 #values: 0, 1
p_all_extensions = 0 #values: 0, 1
err = Errorlog('')
p_show_file_size = 1 #values: 0, 1

p_enable_calc = 0 #values: 0, 1
p_calc_offset = 12 #values: 0, 1
p_operator = '+' #values: +, -, *, /, ^, >>, <<

p_enable_regex = 1 #values: 0, 1
p_regex_filename_filter = '*00001000*' #values: any regex for filename

search_pattern(p_input_folder, p_mode, p_offset, p_val_length, p_show_filenames, p_show_paths, p_endianess, p_arr_extensions, 
               p_show_extensions, p_all_extensions, p_show_file_size, p_enable_calc, p_calc_offset, p_operator, p_enable_regex, p_regex_filename_filter)
