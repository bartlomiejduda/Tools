#ENGLISH
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

parser = argparse.ArgumentParser()
parser.add_argument("plik_FBS", help="Sciezka do pliku FBS")

args = parser.parse_args()
(sciezka_FBS, nazwa_FBS) = os.path.split(args.plik_FBS)
(Krotka_nazwa_FBS, extension) = os.path.splitext(nazwa_FBS) 
sciezka_do_FBS = args.plik_FBS

nazwa_skryptu = Krotka_nazwa_FBS + "_skrypt" + ".txt"
nazwa_repack_data = Krotka_nazwa_FBS + "_repack_data" + ".dat"
pelna_sciezka_skryptu = os.path.join(os.path.abspath(sciezka_FBS), nazwa_skryptu)
print pelna_sciezka_skryptu

plik_FBS = open(sciezka_do_FBS, 'rb')
skrypt = open(pelna_sciezka_skryptu, 'wt')
repack_data = open(os.path.join(os.path.abspath(sciezka_FBS), nazwa_repack_data), 'wb')
repack0 = liczba_linijek_tekstu = plik_FBS.read(4)
liczba_linijek_tekstu = struct.unpack('i', liczba_linijek_tekstu)[0]

repack_data.write(repack0)  
repack01 = plik_FBS.read(16)
repack_data.write(repack01) 

for i in range(liczba_linijek_tekstu):
    rozmiar = plik_FBS.read(4)
    rozmiar = struct.unpack('i', rozmiar)[0]
    przeczytany_tekst = plik_FBS.read(rozmiar-1)
    skrypt.write(przeczytany_tekst)
    if i+1 != liczba_linijek_tekstu:
        skrypt.write('\n')
    print i+1, przeczytany_tekst
    repack1 = plik_FBS.read(25)
    repack2 = warunek = plik_FBS.read(4)
    warunek = struct.unpack('i', warunek)[0]
    if warunek >= 3:                #bardzo wazny warunek, bez tego skrypt sie sypie
        repack3 = plik_FBS.read(warunek+16)                   
    else:
        repack4 = plik_FBS.read(17)
    
    if Krotka_nazwa_FBS == '_fb0x02':
        if i==210 or i==626:    #wyjatki od reguly
            repack5 = plik_FBS.read(1)  


    repack_data.write(repack1)
    repack_data.write(repack2)
    if warunek >= 3: 
        repack_data.write(repack3)
    else:
        repack_data.write(repack4)
    if Krotka_nazwa_FBS == '_fb0x02':
        if i==210 or i==626:
            repack_data.write(repack5)
    repack_data.write('\xFF\xFF')