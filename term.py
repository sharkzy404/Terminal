#!/usr/bin/env python
from os import system as sys
import sys as sy
from colorama import Fore as F
import time as tm
import socket
import subprocess as sub
import random as rd
#IMPORTING LIBRARIES......
from os.path import exists
import os
import re
import uuid
import ipaddress
import requests as r
from tqdm import tqdm
import platform as pt

#CLEAR SCREEN......
sys("clear")
pt = pt.system()
if pt != "Linux":
    print(F.RED+"[*]OPERARING SYSTEM NOT SUPPORTED")
    quit(0)
else:
    pass


def inpu():
    print ("\n")
    subt = sub.getoutput("whoami")
    data =  input(F.YELLOW+f".———[{subt}@Shark]\n|\n°———> "+ F.GREEN)
    return data



#DECLARING CLASS......
class shark:
    def __init__(self):
        #Run OOP's
        self.runner = "Runner"
        self.soc = socket

    def main(self):
        data = """
                   Welcome To Mr.Shark Terminal"
                   For help and functions: @help """
        print (F.GREEN+data)
    



    #HELP LIST FUNCTION.......
    def help(self):
        tools = """
[1]. Getting Ip address: @get -ip [target]
     Example: @get -ip google.com
[2]. Port scanning multiple: @port -scan [target]
     Example: @port -scan 127.0.0.1
[3]. Port scanning single: @port -scan -s [target] [port]
     Example: @port--s -scan 127.0.0.1 80
[4]. Convert Number to Binary: @num -b [number] [base]
     Example: @num -b 2000 2
[5]. Convert Binary to Number: @bina -n [binary] [base]
     Example: @bina -n 1011101010 2
[6]. Convert Alphabet to Binary: @alpha -b
     Example: @alpha -b 
[7]. Convert Binary to Alphabet: @bina -a 
     Example: @bina -a 
[8]. To get device NETWORKS INFO: @ip -details
     Example: @ip -details
[9]. To get cpu info: @cpu
     Example: @cpu
[10]. To open server: @open -server
     Example: @open -server
     Note: To exit chat any user can send "@bye"
         : Only Accepts Telnet service for communication..
[11].To create file: @file <option> <file_name>
     Options: -C create file
              -A append data to existsing file
              -D delete file
              -R read data from a file
              -V check if file exists
              -ED encrypt/decrypt file
     Example: @file -CADRV(ED) filename.txt
[12].To send message to a whatsapp contact: @send -w <number>
    Example: @send -w +1234567890
[13].To send file via wifi: @send -file
     To reciev file       : @recv -file <host> <port>
     Example: @recv @file 127.0.0.1 12345
     NOTE   : Program cant send File with Permission..
[13]. To exit program: @exit

MORE Functions COMING...

        """
        print (F.BLUE+tools)





    def get_ip(self, host): #1
        try:
            data = self.soc.gethostbyname(host)
            print (F.BLUE+f"[✓]{host}: {data}")
        except:
            print (F.RED+"[x]Error, maybe invalid host or no network connection [*]")





    def port_scan(self, ip): #2
        data = sub.getoutput(f'ping -w 1 {ip} ')

        try:
            re_search = re.search(r'(time=)(\d+)', data)
            interval = int(re_search.group(2))/1000
            print (F.CYAN+"[*]STARTING SCANNING IN TIME INTERVAL: "+F.YELLOW+str(interval))


            total_port = 0
            port = -1
            for i in range(65354):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    port += 1
                    sock.settimeout(interval)
                    check =  sock.connect_ex((ip, port))
                    if check == 0:
                        total_port += 1
                        print (F.BLUE+f"[✓]port {port} opened for {ip}")
                        sock.close()
                    else:
                        pass
                        sock.close()
                except:
                    break
            print (F.GREEN+f"[*]Total port opened for {ip} is : {total_port}")
            sock.close()
        except:
            print(F.RED+"[OPP's]SERVER NOT RECHEABLE :'( ")


    


    def port_scan_sin(self, ip, port): #3
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            check = sock.connect_ex((ip, int(port)))
            if check == 0:
                print (F.BLUE+f"[✓]Port: {port} opened")
                sock.close()
            else:
                print (F.BLUE+f"[x]Port: {port} closed")
                sock.close()

        except:
            print (F.RED+"[x]An error occured, Internet Issue")
            sock.close()






    def Bina_Num(self, binary, base): #4
        try:
            print (F.GREEN+"[*]OUTPUT"+F.BLUE)
            print (F.BLUE+str(int(binary, int(base))))
        except:
            print (F.RED+"[x]An error occured")





    def Num_Bina(self, num, base): #5
        try:
            num = int(num)
            base = int(base)
            print (F.GREEN+"[*]OUTPUT"+F.BLUE)
            print (F.BLUE+bin(num) [base: ])
        except:
            print (F.RED+"[x]An error occured")




    def Alpha_Bina(self): #6
        alph = input(F.YELLOW+"[*]Enter Text: "+F.WHITE)
        alph = alph.split(" ")
        num = -1
        try:
            print (F.GREEN+"[*]OUTPUT"+F.BLUE)
            while True:
                num += 1
                try:
                    for data in bytearray(alph[num], "utf-8"):
                        print (format(data, "b"), end = " ")
                    print ("\n")
                except:
                    break
        except:
            print (F.RED+"[x]An error occured")






    def Bina_Alpha(self): #7
        try:
            splita = input(F.YELLOW+"[*]Enter Binary: "+F.WHITE)
            splita = splita.split(" ")
            print (F.GREEN+"[*]OUTPUT"+F.BLUE)
            for data in splita:
                data1 = int(data, 2)
                charac = chr(data1)
                print (charac, end = "")
            print ("\n")
        except:
            print (F.RED+"[x]An error occured")




    def get_device_ip(self): #8
        #sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #sock.settimeout(2)
        url = "https://github.com"
        try:
            #if sock.connect_ex(("google.com", 80)) == 0:
            if r.get(url, timeout=1):
                curl = sub.run(['curl', 'ifconfig.me'], capture_output=True, text=True)
                curl = curl.stdout.strip()
                if curl != "<HTML></HTML>":
                    print(F.CYAN+"[*] PUBLIC IP: "+F.BLUE+str(curl))
                else:
                    print(F.CYAN+"[*] PUBLIC IP: "+F.BLUE+"inactive")
         
            else:
                print(F.CYAN+"[*] PUBLIC IP: "+F.BLUE+"Cant connect to Server")
        except:
            print(F.CYAN+"[*] PUBLIC IP: "+F.BLUE+"Cant connect to Server")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print(F.CYAN+"[*] PRIVATE IP: "+F.BLUE+sub.getoutput('ifconfig | grep netmask').split(" ")[9])
        except:
            print(F.CYAN+"[*] PRIVATE IP: "+F.BLUE+"inactive")
        try:
            ip_wl = sub.getoutput('ifconfig | grep netmask').split(" ")[21]
            check = re.search(r'(\d+\.){3}', ip_wl)
            if check:
                print (F.CYAN+"[*] IP:WLAN: "+F.BLUE+ip_wl)
            else:
                print(F.CYAN+"[*] IP:WLAN: "+F.BLUE+"inactive")
        except:
            print(F.CYAN+"[*] IP:WLAN: "+F.BLUE+"inactive")
        try:
            print(F.CYAN+"[*] IPV6:INET: "+F.BLUE+sub.getoutput('ifconfig | grep inet6').split(" ")[24])
        except:
            print(F.CYAN+"[*] IPV6:INET: "+F.BLUE+"inactive")
        try:
            print(F.CYAN+"[*] IPV6:WLAN: "+F.BLUE+sub.getoutput('ifconfig | grep inet').split(" ")[24])
        except:
            print(F.CYAN+"[*] IPV6:WLAN: "+F.BLUE+"false")
        try:
            print(F.CYAN+"[*] VPN TUNNEL: "+F.BLUE+sub.getoutput('ifconfig | grep destination').split(" ")[15])
        except:
            print(F.CYAN+"[*] VPN TUNNEL: "+F.BLUE+"inactive")
        
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(5, -1, -1)])
        ip_network = ipaddress.IPv4Network(ip_address, strict=False)
        subnet = ip_network.network_address
        net = ip_network.netmask
        print(F.CYAN+"[*] MAC: "+F.BLUE+str(mac_address))
        print(F.CYAN+"[*] SUBNET: "+F.BLUE+str(subnet))
        print(F.CYAN+"[*] NETMASK: "+F.BLUE+str(net))
        sock.close()






    def cpu_info(self): #9
        try:
            sys("cat /proc/cpuinfo")
        except:
            print ("[x]An error occured")




    def open_server(self): #10
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock = socket.socket()
        print (F.CYAN+"[NOTE]: CONNECT VIA TELNET: ONLY SUPPORT WLAN")  
        print (F.YELLOW+"[✓]Starting Server")

        tm.sleep(2)
        a1, a2, a3 = str(rd.randint(1,6)), str(rd.randint(1,6)), str(rd.randint(1,6))
        try:
            ip_wl = sub.getoutput('ifconfig | grep inet').split(" ")[51]
        except:
            pass
        ip_in = sub.getoutput('ifconfig | grep inet').split(" ")[9]
        try:
            check = re.search(r'(\d+\.){3}', ip_wl)
            if check:
                ip = ip_wl
            else:
                ip = ip_in
        except:
            ip = ip_in
        port = a3+a2+a1+a2+a3
        print (F.BLUE+"[✓]Server Started")
        tm.sleep(1)
        print (F.GREEN+f"[*]IP: {ip}: [*]PORT: {port}")
    
        sock.bind(("0.0.0.0", int(port)))
        sock.listen(5)
        c, addr = sock.accept()

        while True:
            c.send("[*]Waiting for incoming Message::\n".encode())
            out_mes = input(F.YELLOW+"[*]Send-Message: ")
            if "@bye" in out_mes:
                c.close()
                break
            c.send(f"[*]Receiced message: {out_mes}\n[*]Send-Message: ".encode())
            print ("Message Sent\nWaiting for incoming Message::")

            inp_mes = c.recv(1024).decode()
            print (f"[*]Received-Message: {inp_mes}")
            if "@bye" in inp_mes:
                c.close()
                break





    def file_sys(self, option, file): #11
        if option == "-C":
            if exists(file) == False:
                data = input(F.YELLOW+"[*]Enter Data: "+F.WHITE)
                open_file = open(file, "w")
                open_file.write(data)
                print (F.BLUE+"[✓]File created successfully")
                open_file.close()
            else:
                print (F.RED+"[*]File already exists, wish to rewrite it")
                opt = input(F.YELLOW+"[*]Y/N: "+F.WHITE).upper()
                if opt == "N":
                    print (F.BLUE+"[✓]File was maintained")
                elif opt == "Y":
                    data = input(F.YELLOW+"[*]Enter Data: "+F.WHITE)
                    open_file = open(file, "w")
                    open_file.write(data)
                    print (F.BLUE+"[✓]File created successully")
                    open_file.close()
                else:
                    print (F.RED+"[x]Error, try inputing details")

        elif option == "-A":
            try:
                if exists(file):
                    data = input(F.YELLOW+"[*]Enter Data: "+F.WHITE)
                    open_file = open(file, "a")
                    open_file.write(data)
                    open_file.close()
                    print (F.BLUE+"[✓]Done")
                else:
                    print (F.RED+"[x]File doesnt exists")
            except:
                print (F.RED+"[x]An error occured")
        elif option == "-D":
            if exists(file):
                os.remove(file)
                print (F.BLUE+"[✓]File deleted ")
            else:
                print (F.RED+"[x]File doesnt exists")
        elif option == "-V":
            if exists(file):
                print (F.BLUE+"[✓]File exists")
            else:
                print (F.RED+"[x]File doesnt exists")
        elif option == "-R":
            if exists(file):
                open_file = open(file, "r")
                print (F.BLUE+f"Data: {open_file.read()}")
            else:
                print (F.RED+"[x]File doesnt exists")
        elif option == "-ED":
            if exists(file):
                open_file = open(file, "r")
                data = open_file.read()
                open_file.close()
                reg = re.search(r"enc=", data)
                if reg != None:
                    print (F.GREEN+"[*]File is in encrypted format\n[*]Wish to decrypt")
                    opt = input(F.YELLOW+"[*]Y/N: "+F.WHITE).upper()
                    if opt == "Y":
                        decryp_hash = str(0000)
                        data1 = data.replace("enc=", "").encode()
                        rep = len(data)-1//len(decryp_hash)+1
                        a4 = (decryp_hash*rep)[:len(data)].encode()
                        new_data = bytes([i1^i2 for (i1,i2) in zip(data1 , a4)])
                        dec_data = new_data.decode()
                        rep_data = dec_data.replace("~", " ")
                        new_file = open(file, "w")
                        new_file.write(rep_data)
                        new_file.close()
                        print (F.BLUE+"[*]Decrypting File.....")
                        tm.sleep(1)
                        print (F.BLUE+"[✓]File Decrypted succesfully")
                    elif opt == "N":
                        print (F.BLUE+"[✓]Ok")
                    else:
                        print (F.RED+"[x]Error, invalid input")

                elif reg == None:
                    print (F.GREEN+"[*]File is in decrypted Format\n[*]Wish to encrypt")
                    opt = input(F.YELLOW+"[*]Y/N: "+F.WHITE).upper()
                    if opt == "Y":
                        decryp_hash = str(0000)
                        data1 = data.replace(" ", "~").encode()
                        rep = len(data)-1//len(decryp_hash)+1
                        a4 = (decryp_hash*rep)[:len(data)].encode()
                        new_data =b"enc=" + bytes([i1^i2 for (i1,i2) in zip(data1, a4)])
                        new_file = open(file, "w")
                        new_file.write(new_data.decode())
                        new_file.close()
                        print (F.BLUE+"[*]Encrpyting file.....")
                        tm.sleep(2)
                        print (F.BLUE+"[✓]File Encrypted successfully")
                    elif opt == "N":
                        print (F.BLUE+"[✓]Ok")
                    else:
                        print (F.RED+"[x]Error, invalid input")
            else:
                print (F.RED+"[x]File doesnt exists")





    def send_mess(self, number): #12
        try:
            message = input(F.YELLOW+"Message: "+F.WHITE).replace(" ", "%20")
            sys(f'xdg-open https://wa.me/{number}?text={message}')
            print (F.BLUE+"[*]OPENING WHATSAPP....")
        except:
            print ("[x]An Error occured")



    def send_file(self): #13
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        a1, a2, a3 = str(rd.randint(1,6)), str(rd.randint(1,6)), str(rd.randint(1,6))
        port = a3+a2+a1+a2+a3
        sock.bind(('0.0.0.0', int(port)))
        print (F.BLUE+"[✓]SERVER STARTED")
        try:
            ipw = sub.getoutput('ifconfig | grep netmask').split(" ")[21]
            check = re.search(r'(\d+\.){3}', ipw)
            if check:
                ip = ipw
            else:
                ip = sub.getoutput('ifconfig | grep netmask').split(" ")[9]

        except:
            ip = sub.getoutput('ifconfig | grep netmask').split(" ")[9]
        print(F.GREEN+f'[*]IP: {ip} : PORT {port}'+F.CYAN)

        sock.listen(5)

        file_path = input(F.YELLOW+"[%]/path/to/file: "+F.WHITE)
        print (F.BLUE+"[*]WAITING FOR USER TO RECIEVE")
        size = open(file_path, 'rb')
        size = len(size.read())

        num = 0
        while True:
            try:
                num += 1
                split1 = file_path.split("/")
                file = split1[num]

            except:
                break

        c, addr = sock.accept()
        c.send(f'[*]INCOMING FILE! [NAME: {file}] [SIZE: {size}bytes]\n'.encode())
        choice = c.recv(1024).decode()
        if "YES" in choice: 
            c.send(str(size).encode())
            print (F.CYAN+"") 
            with tqdm(total=size, unit='B', unit_scale=True, desc="Uploading", ascii=False) as progress_bar:
                with open(file_path, 'rb') as file:
                    for data in iter(lambda: file.read(1024), b''):
                        c.send(data)
                        progress_bar.update(len(data))
            c.close()
            print(F.BLUE+"[✓]FILE UPLOADED")
        else:
            c.close()


    def recv_file(self, ip, port): #14
        c_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c_socket.connect((ip, int(port)))
        print(F.BLUE+"[✓]CONNECTED TO SERVER")
        #tm.sleep(1)
        data = c_socket.recv(1024).decode()
        print (F.BLUE+data)

        file = input(F.YELLOW+"[%]/save/to/path/to/file: "+F.WHITE)

        choice = input(F.YELLOW+"[*]WISH TO ACCEPT: Y/N: "+F.WHITE).upper()
        if choice == "Y":
            c_socket.send("YES".encode())
            size = c_socket.recv(1024).decode()
            size = int(size)
            print (F.CYAN+"")
            with tqdm(total=size, unit='B', unit_scale=True, desc="Downloading", ascii=False) as progress_bar:
                with open(file, 'wb') as new_file:
                    while True:
                        rec = c_socket.recv(1024)
                        if not rec:
                            break
                            c_socket.close()
                        new_file.write(bytes(rec))
                        progress_bar.update(len(rec))
            c_socket.close()
            print (F.BLUE+"[✓]FILE DOWNLOADED")
            





#RUNNING ALL FUNCTIONS
shark = shark()
if __name__ == '__main__':
    shark.main()
    while True:
        data = inpu()
        try:
            #data = inpu()
            if "@get -ip" in data: #1
                shark.get_ip(data.split()[2])
            elif "@port -scan" in data: #2
                shark.port_scan(data.split()[2])
            elif "@port--s -scan" in data: #3
                shark.port_scan_sin(data.split()[2], data.split()[3])
            elif "@bina -a" in data: #4
                shark.Bina_Alpha()
            elif "alpha -b" in data: #5
                shark.Alpha_Bina()
            elif "@num -b" in data: #6
                shark.Num_Bina(data.split()[2], data.split()[3])
            elif "@bina -n" in data: #7
                shark.Bina_Num(data.split()[2], data.split()[3])
            elif data == "@ip -details": #8
                shark.get_device_ip()
            elif data == "@cpu": #9
                shark.cpu_info()
            elif data == "@open -server": #10
                shark.open_server()
            elif "@file" in data: #11
                shark.file_sys(data.split()[1], data.split()[2])
            elif "@send -w" in data: #12
                shark.send_mess(data.split()[2])
            elif "@help" in data: #13
                shark.help()
            elif data == "@send -file": #14
                shark.send_file()
            elif "@recv -file" in data: #15
                shark.recv_file(data.split()[2], data.split()[3])
            elif "@exit" in data:
                print (F.RED+"[✓]EXITING PROGRAM...")
                tm.sleep(1)
                break
            else:
                sys(data)
        except:
                print (F.RED+"[x] AN ERROR OCCURED")
