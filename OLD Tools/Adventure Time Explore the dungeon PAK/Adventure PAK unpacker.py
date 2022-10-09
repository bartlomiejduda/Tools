# -*- coding: utf-8 -*-

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
import binascii
import math

parser = argparse.ArgumentParser()
parser.add_argument("plik_PAK", help="Sciezka do pliku PAK")

args = parser.parse_args()
sciezka_do_PAK = args.plik_PAK

(sciezka_PAK, nazwa_PAK) = os.path.split(args.plik_PAK)
(Krotka_nazwa_PAK, extension) = os.path.splitext(nazwa_PAK) 

plik_PAK = open(sciezka_do_PAK, 'rb')
lista_plikow = open(os.path.join(sciezka_PAK + "\\" + Krotka_nazwa_PAK + "_filelist.txt"), 'wb+')

adres_konca_bloku = plik_PAK.read(4)
adres_konca_bloku = struct.unpack('i', adres_konca_bloku)[0]

liczba_wpisow_FILELINK = plik_PAK.read(4)
liczba_wpisow_FILELINK = struct.unpack('i', liczba_wpisow_FILELINK)[0]


nazwa_pliku = ""
czytany_padding = ""

for i in range(liczba_wpisow_FILELINK):
    offset_powrotu = plik_PAK.tell()
    FILELINK = plik_PAK.read(16)
    relatywny_offset_danych = plik_PAK.read(4)
    relatywny_offset_danych = struct.unpack('i', relatywny_offset_danych)[0]
    rozmiar_danych = plik_PAK.read(4)
    rozmiar_danych = struct.unpack('i', rozmiar_danych)[0]
    offset_poczatku_nazwy = plik_PAK.tell()
    #czytanie nazwy
    n = 0
    while 1:
        n = n+1
        znak = plik_PAK.read(1)
        nazwa_pliku = nazwa_pliku + znak
        if znak == '\x00':
            break  
    #czytanie paddingu    
    while 1:
        znak = plik_PAK.read(1)
        czytany_padding = czytany_padding + znak 
        if znak == 'F' or znak == 'M':
            off = plik_PAK.tell()
            plik_PAK.seek(off-1)
            break          
    #przygotowanie nazwy   
    (nazwa_folderu, nazwa_pliku) = nazwa_pliku.split(":")
    (nazwa_pliku, zzero) = nazwa_pliku.split('\x00')
    nazwa_pliku = nazwa_pliku.replace("/", "\\")
    offset_konca_wpisu = plik_PAK.tell()
    
    #zapisywanie do filelist.txt
    lista_plikow.write(nazwa_pliku)
    lista_plikow.write('\n')
    
    #zapisywanie
    plik_PAK.seek(adres_konca_bloku  + 64 + relatywny_offset_danych)
    aktualny_plik = plik_PAK.read(rozmiar_danych)
    
    #wyciecie samej nazwy pliku
    count = 0
    if nazwa_pliku.find("\\") != -1:
        count = nazwa_pliku.count("\\")
        nazwa_pliku.split("\\", count)
        if count == 1:
            (nazwa1, nazwa2) = nazwa_pliku.split("\\")
            nazwa_pliku = nazwa2
        if count == 2:
            (nazwa1, nazwa2, nazwa3) = nazwa_pliku.split("\\")
            nazwa_pliku = nazwa3
        
    #ustalenie sciezki    
    if count == 0:
        sciezka_zapisanego_pliku = os.path.join(sciezka_PAK + "\\" + Krotka_nazwa_PAK + "\\")
    if count == 1:
        sciezka_zapisanego_pliku = os.path.join(sciezka_PAK + "\\" + Krotka_nazwa_PAK + "\\" + nazwa1 + "\\")
    if count == 2:
        sciezka_zapisanego_pliku = os.path.join(sciezka_PAK + "\\" + Krotka_nazwa_PAK + "\\" + nazwa1 + "\\" + nazwa2 + "\\")
    

    print str(sciezka_zapisanego_pliku + nazwa_pliku)     
    
    if not os.path.isdir(sciezka_zapisanego_pliku):  
                os.makedirs(sciezka_zapisanego_pliku) 
    with open(os.path.join(os.path.abspath(sciezka_zapisanego_pliku), nazwa_pliku), 'wb+') as plik_wyjsciowy: 
                plik_wyjsciowy.write(aktualny_plik)  
    
    plik_PAK.seek(offset_konca_wpisu)