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
parser.add_argument("lista_plikow.txt", help="Lista plikow")
parser.add_argument("folder_z_plikami", help="Folder zawierajacy wszystkie pliki")

args = parser.parse_args()
lista_plikow = args.lista_plikow.txt
folder_z_plikami = args.folder_z_plikami

(sciezka_listy, nazwa_listy) = os.path.split(args.lista_plikow.txt)
(Krotka_nazwa_listy, extension) = os.path.splitext(nazwa_PAK) 
(krotsza_nazwa_listy, koncowka) = os.path.split(Krotka_nazwa_listy, "lista")

lista = open(lista_plikow, 'rt')
nowypak = open(os.path.join(sciezka_listy + "\\" + krotsza_nazwa_listy + ".pak"),"wb+") 

nowypak.write(8 * '\xFF')

liczba_plikow  = sum(1 for line in open(lista_plikow))
for i in range(liczba_plikow):
    sciezka_pliku_na_liscie = lista.readline()
    (sciezka_pliku_na_liscie_okrojona, nazwa_pliku_na_liscie) = os.path.split(sciezka_pliku_na_liscie) 
    
    nowypak.write("FILELINK_____END")
    
    