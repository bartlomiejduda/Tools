
#Tested on Python 2.7.5
#Author of this code: Bartlomiej Duda
#Contact: https://www.facebook.com/ikskoks
#This code/python script is for personal use ONLY
#It was made for XENTAX users


import argparse
import os
import sys
import time
import struct


parser = argparse.ArgumentParser()
parser.add_argument("plik_PAK", help="Sciezka do pliku PAK")

args = parser.parse_args()
unpak_root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) #pobiera lokalizacje tego pliku

(sciezka_PAK, nazwa_PAK) = os.path.split(args.plik_PAK)
(Krotka_nazwa_PAK, extension) = os.path.splitext(nazwa_PAK) 

pathname = os.path.dirname(sys.argv[1]) 
destination_dir = os.path.join(os.path.abspath(pathname), Krotka_nazwa_PAK) #wypakowuje pliki tam gdzie znajduje sie plik PAK

sciezka_do_pliku_pak = args.plik_PAK





NAGLOWEK_PACK = 0  #offset naglowka
NAGLOWEK_PACK_DLUGOSC = 4 #dlugosc naglowka PACK

WSKAZNIK_NA_OGON = 4 #offset wskaznika na ogon
DLUGOSC_WSKAZNIKA_NA_OGON = 4  #dlugosc wskaznika na ogon w bajtach

ROZMIAR_OGONA = 8 #offset rozmiaru ogona
ROZMIAR_OGONA_DLUGOSC = 4  #ilosc bajtow na rozmiar ogona

DIRECTORY_ENTRY_LENGTH = 64   #wielkosc calego bloku na ogonie
DIRECTORY_ENTRY_FILE_PATH_LENGTH = 56  #nazwa pliku i wszystkie zera za nia
DIRECTORY_ENTRY_FILE_OFFSET_LENGTH = 4 #offset spakowanego pliku
DIRECTORY_ENTRY_FILE_LENGTH = 4 #rozmiar spakowanego pliku

def unpack_integer(binary_value):
    return struct.unpack('i', binary_value)[0]

def unpack_null_terminated_string(binary_value): #padding?
    return binary_value.split(b'\x00')[0] #zwraca sciezke pliku bez zer

def extract(sciezka_do_pliku_pak, unpack_root_dir=None):
    pak_file = open(sciezka_do_pliku_pak, 'rb')

    pak_file.seek(WSKAZNIK_NA_OGON) #przesuwa wskazywany offset na wzkaznik, czyli na 4 bajt w PAK
    directory_offset_in_binary = pak_file.read(DLUGOSC_WSKAZNIKA_NA_OGON) #czyta 4 bajty (wskaznik) i zapisuje do zmiennej
    directory_offset = unpack_integer(directory_offset_in_binary) #zamienia wskaznik na string Pythona (?)

    pak_file.seek(ROZMIAR_OGONA) #przesuwa wskazywany offset na "rozmiar ogona" w PAK, czyli 8 bajt
    directory_size_in_binary = pak_file.read(ROZMIAR_OGONA_DLUGOSC) #jw
    directory_size = unpack_integer(directory_size_in_binary) #jw

    entries_in_directory = directory_size / DIRECTORY_ENTRY_LENGTH #ilosc plikow w PAK, 70784 / 64 = 1106

    for directory_entry in xrange(entries_in_directory):  #petla wykonuje sie dla 1106 plikow
        pak_file.seek(directory_offset + (directory_entry * DIRECTORY_ENTRY_LENGTH)) # 4 + 1*64 = 68, 4 + 2*64 = 134

        file_path_in_binary = pak_file.read(DIRECTORY_ENTRY_FILE_PATH_LENGTH) #czyta nazwe pliku (i wszystkie zera)
        file_path = unpack_null_terminated_string(file_path_in_binary) #sciezka pliku bez zer w zmiennej

        file_offset_in_archive_in_binary = pak_file.read(DIRECTORY_ENTRY_FILE_OFFSET_LENGTH) #czyta offset pliku w PAK
        file_offset_in_archive = unpack_integer(file_offset_in_archive_in_binary) #zapisuje to jako int w zmiennej

        file_length_in_binary = pak_file.read(DIRECTORY_ENTRY_FILE_LENGTH) #czyta rozmiar spakowanego pliku
        file_length = unpack_integer(file_length_in_binary) #jw

        file_path_components = os.path.split(file_path)
        file_path_directories = os.path.join(*file_path_components[:-1]) #katalogi
        file_path_basename = file_path_components[-1] #nazwa pliku

        unpack_dir = os.path.join(unpack_root_dir, file_path_directories)
        
        print "Wypakowuje '{0}' do katalogu '{1}'".format(
            file_path_basename,
            unpack_dir,
        )

        if not os.path.isdir(unpack_dir):   #jesli katalog "unpack_dir" nie istnieje
            os.makedirs(unpack_dir)   #to go tworzy (TO MUSI TU BYC)

        pak_file.seek(file_offset_in_archive) #przechodzi na offset pliku w PAK
        file_contents = pak_file.read(file_length) #czyta caly plik (najpierw pobiera jego welkosc)
        with open(os.path.join(unpack_dir, file_path_basename), 'wb') as output_file: #laczy sciezki i tworzy plik
            output_file.write(file_contents) #zapisuje zawartosc z PAK do pliku

    print "Wypakowano " + str(entries_in_directory) + " plikow."
    
        
    
extract(sciezka_do_pliku_pak, destination_dir)
