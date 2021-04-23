# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0


# Ver    Date        Author               Comment
# v0.1   08.12.2019  Bartlomiej Duda      Initial version
# v0.2   23.04.2021  Bartlomiej Duda      Rewritten to Python 3.7 + refactoring


import os
import glob
import shutil
import datetime


def bd_logger(in_str):
    '''
    Function for logging debug messages
    '''   
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    


def replace_chars_in_regular_txt(extension, txt_folder, in_encoding, out_encoding, in_mode):
    bd_logger("Starting function for extension " + extension + " and folder " + txt_folder)
    os.chdir(txt_folder)
    file_set = glob.glob(r'*.' + extension)
    file_set += glob.glob(r'*\*.' + extension)
    fold = '*\\'
    fold2 = ''
    for i in range(100):
        fold2 += fold
        file_set += glob.glob(fold2 + '*.' + extension)
    for file in file_set:
        txt_path = os.path.abspath(file)
        
        temp_path = os.path.dirname(txt_path)
        temp_filename = txt_path.split('\\')[-1].split('.')[0]
        temp_path += '\\' + temp_filename + '_temp.txt'
        
        bd_logger("Starting replacing in " + txt_path)
        
        # TEXT MODE 
        if in_mode == "text":
            out_temp_file = open(temp_path, 'wt+', encoding=out_encoding)
            txt_file = open(txt_path, 'rt', encoding=in_encoding)
            
            for line in txt_file:
                line = (
                    line
                        .replace('Ż', 'И')
                        .replace('Ó', 'О')
                        .replace('Ł', 'К')
                        .replace('Ć', 'Л')
                        .replace('Ę', 'Е')
                        .replace('Ś', 'Н')
                        .replace('Ą', 'А')
                        .replace('Ź', 'Б')
                        .replace('Ń', 'В')
                        
                        .replace('ż', 'и')
                        .replace('ó', 'о')
                        .replace('ł', 'к')
                        .replace('ć', 'л')
                        .replace('ę', 'е')
                        .replace('ś', 'н')
                        .replace('ą', 'а')
                        .replace('ź', 'б')
                        .replace('ń', 'в')
                        )
                out_temp_file.write(line)
        
        # BINARY MODE        
        elif in_mode == "bin":
            out_temp_file = open(temp_path, 'wb+')
            txt_file = open(txt_path, 'rb')  
            
            for line in txt_file:
                line = (
                    line
                        .replace(b'\xC5\xBB', b'\xC8')   # Ż
                        .replace(b'\xC3\x93', b'\xCE')   # Ó
                        .replace(b'\xC5\x81', b'\xCA')   # Ł
                        .replace(b'\xC4\x86', b'\xCB')   # Ć
                        .replace(b'\xC4\x98', b'\xC5')   # Ę
                        .replace(b'\xC5\x9A', b'\xCD')   # Ś
                        .replace(b'\xC4\x84', b'\xC0')   # Ą
                        .replace(b'\xC5\xB9', b'\xC1')   # Ź
                        .replace(b'\xC5\x83', b'\xC2')   # Ń
                    
                        .replace(b'\xC5\xBC', b'\xE8')   # ż
                        .replace(b'\xC3\xB3', b'\xEE')   # ó
                        .replace(b'\xC5\x82', b'\xEA')   # ł
                        .replace(b'\xC4\x87', b'\xEB')   # ć
                        .replace(b'\xC4\x99', b'\xE5')   # ę
                        .replace(b'\xC5\x9B', b'\xED')   # ś
                        .replace(b'\xC4\x85', b'\xE0')   # ą
                        .replace(b'\xC5\xBA', b'\xE1')   # ź
                        .replace(b'\xC5\x84', b'\xE2')   # ń   
                        
                        )
                out_temp_file.write(line)
                
        else:
            raise Exception("Wrong mode selected!")
            
            
        out_temp_file.close()
        txt_file.close()
        shutil.move(temp_path, txt_path)
        bd_logger("Chars replaced in " + txt_path)
        

def replace_chars_EXTENDED(tab_extensions, tab_folders, in_encoding, out_encoding, in_mode):
    for ext in tab_extensions:
        for fold in tab_folders:
            replace_chars_in_regular_txt(ext, fold, in_encoding, out_encoding, in_mode)
    bd_logger("EXTENDED REPLACE FINISHED.")
            

            
            
##RUN CHAR REPLACER
#path_to_txt_folder = 'C:\\Users\\User\\Desktop\\TEST'
#replace_chars_in_regular_txt('txt', path_to_txt_folder)


##RUN EXTENDED CHAR REPLACER
tab_extensions = ['txt', 'ini']
tab_folders = ['C:\\Users\\UserName\\GameName OmegaT\\target']   
in_encoding = "windows-1250"
out_encoding = "windows-1251"
in_mode = "bin"
replace_chars_EXTENDED(tab_extensions, tab_folders, in_encoding, out_encoding, in_mode)




# encodings list:
#  utf-8 - a.k.a. Unicode - international standard
#  iso-8859-1 - ISO standard for Western Europe and USA
#  iso-8859-2 - ISO standard for Central Europe (including Poland)
#  cp1250 or windows-1250 - Polish encoding on Windows
#  cp1251 or windows-1251 - Russian encoding on Windows
#  cp1252 or windows-1252 - Western European encoding on Windows
#  ASCII - ASCII characters only
