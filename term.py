#!/usr/bin/env python
try:
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
    import json
    from tqdm import tqdm
    import platform as pt
    import psutil as p
    import phonenumbers as phone
    from phonenumbers import carrier, geocoder, timezone
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import *
    from tenable.io import TenableIO

except ModuleNotFoundError as err:
    print (f'shark: {err}')
    quit(0)


from os import system as sys
#CLEAR SCREEN......
sys("clear")

#check for supported operating system
pt = pt.system()
if pt != "Linux":
    print(F.RED+"[*]OPERARING SYSTEM NOT SUPPORTED")
    quit(0)
else:
    pass

#input function
def inpu():
    try:
        print ("\n")
        subt = sub.getoutput("whoami")
        direc = os.getcwd()
        num = -1
        while True:
            try:
                num += 1
                new_direc = direc.split("/")[num]
                new_path = F.BLUE+new_direc+F.YELLOW
            except:
                break
        
        s = F.BLUE+"$"
        data =  input(F.YELLOW+f"{F.BLUE}.{F.YELLOW}——[{F.BLUE}{subt}{F.GREEN}@{F.CYAN}Shark{F.YELLOW}]——[~/{new_path}]\n|\n{F.BLUE}°{F.YELLOW}——{s} "+ F.GREEN)
        return data
    except:
        quit(0)



#DECLARING CLASS for the whole function
class shark:
    def __init__(self):
        #Run OOP's
        self.runner = "Runner"
        self.soc = socket
    #load the terminal on start
    def main(self):
        num = 0
        for i in range(300):
            num += 0.2
            d = F.YELLOW+'━'*int(num)
            print(f'{d}', end="\r", flush=True)
            tm.sleep(0.001)
        print(" "*60)
        data = f"""
                {F.CYAN}♣WELCOME·TO·MR·SHARK·TERMINAL♠
                {F.GREEN} For help and functions: {F.CYAN}@help
                    {F.BLUE}Ctrl+c to close if stuck 
                    """
        print (data)
    



    #HELP LIST FUNCTION.......
    def help(self): #1
        tools = f'''
[1]. Getting Ip address: {F.CYAN}@get -ip [target]{F.GREEN}
     Example: {F.BLUE}@get -ip google.com{F.GREEN}
[2]. Port scanning multiple: {F.CYAN}@port -scan [target]{F.GREEN}
     Example: {F.BLUE}@port -scan 127.0.0.1{F.GREEN}
[3]. Port scanning single: {F.CYAN}@port -scan -s [target] [port]{F.GREEN}
     Example: {F.BLUE}@port--s -scan 127.0.0.1 80{F.GREEN}
[4]. Convert Number to Binary: {F.CYAN}@num -b [number] [base]{F.GREEN}
     Example: {F.BLUE}@num -b 2000 2{F.GREEN}
[5]. Convert Binary to Number: {F.CYAN}@bina -n [binary] [base]{F.GREEN}
     Example: {F.BLUE}@bina -n 1011101010 2{F.GREEN}
[6]. Convert Alphabet to Binary: {F.CYAN}@alpha -b{F.GREEN}
     Example: {F.BLUE}@alpha -b{F.GREEN} 
[7]. Convert Binary to Alphabet: {F.CYAN}@bina -a{F.GREEN}
     Example: {F.BLUE}@bina -a{F.GREEN} 
[8]. To get device NETWORKS INFO: {F.CYAN}@ip -details{F.GREEN}
     Example: {F.BLUE}@ip -details{F.GREEN}
[9]. To get cpu info: {F.CYAN}@cpu{F.GREEN}
     Example: {F.BLUE}@cpu{F.GREEN}
[10].To start wifi chat room: 
      HOST   : {F.CYAN}@open -server{F.GREEN}
      CLIENT : {F.CYAN}@con -server <ip> <port>{F.GREEN}
      Example: {F.CYAN}@con -server 127.0.0.1 12345{F.GREEN} 
      Note   : {F.BLUE}To exit chat any user can input "@bye"..{F.GREEN}
             : {F.BLUE}Doesn't support telnet{F.GREEN}
[11].To create file: {F.CYAN}@file <option> <file_name>{F.GREEN}
     Options: {F.BLUE}-C create file{F.GREEN}
              {F.BLUE}-A append data to existsing file{F.GREEN}
              {F.BLUE}-D delete file{F.GREEN}
              {F.BLUE}-R read data from a file{F.GREEN}
              {F.BLUE}-V check if file exists{F.GREEN}
              {F.BLUE}-ED encrypt/decrypt file{F.GREEN}
     Example: {F.BLUE}@file -CADRV(ED) filename.txt{F.GREEN}
     NOTE   : {F.BLUE}Can only encrypt and decrypt text contained file{F.GREEN}
[12].To send message to a whatsapp contact: {F.CYAN}@send -w <number>{F.GREEN}
    Example: {F.BLUE}@send -w +1234567890{F.GREEN}
[13].To send file via wifi: {F.CYAN}@send -file{F.GREEN}
     To recieve file       : {F.CYAN}@recv -file <host> <port>{F.GREEN}
     Example: {F.BLUE}@recv @file 127.0.0.1 12345{F.GREEN}
     NOTE   : {F.BLUE}Program cant send File with Permission..{F.GREEN}
            : {F.BLUE}Doesn't suppport telnet{F.GREEN}
[14].To start remote shell via wifi::
     HOST   : {F.CYAN}@shell -host{F.GREEN}
     CLIENT : {F.CYAN}@shell -client <ip> <port>{F.GREEN}
     Example: {F.BLUE}@shell -client 127.0.0.1 12345{F.GREEN}
     NOTE   : {F.BLUE}Doesn't support telnet{F.GREEN}
            : {F.BLUE}To exit session input <exit>{F.GREEN}
[15].To encrypt a text: {F.CYAN}@crypt -t{F.GREEN}
     Example: {F.BLUE}@crypt -t{F.GREEN}
     Note   : {F.BLUE}Can only encrypt string format not(int, bytes){F.GREEN}
[16].To check mobile number details: {F.CYAN}@check -no <country code> <number>{F.GREEN}
     Example: {F.BLUE}@check -no +123123450000{F.GREEN}
     NOTE   : {F.BLUE}Without country code: default is <+62>{F.GREEN}
[17].To scan vulnerability: {F.CYAN}@scan -v <target>{F.GREEN}
     Example: {F.BLUE}@scan -v 192.168.00.00{F.GREEN}
     NOTE   : {F.BLUE}GET YOUR CREDENTIAL (ACCESS , SECRET & API K              EY) FROM tenable.io website{F.GREEN}
[18].To analyse connected network: {F.CYAN}@net -a <target>{F.GREEN}
     Example: {F.BLUE}@net -a 192.168.00.00/00{F.GREEN}
     NOTE   : {F.BLUE}Program requires root priviledge{F.GREEN}
[19].To sniff packet: {F.CYAN}@sniff -p <interface>{F.GREEN}
     Example: {F.BLUE}@sniff -p [eth0/wlan0]{F.GREEN}
     NOTE   : {F.BLUE}Program requires root priviledge{F.GREEN}
[20].To check weather: {F.CYAN}@check -w <city>{F.GREEN}
     Example: {F.BLUE}@check -w London{F.GREEN}
     NOTE   : {F.BLUE}Get your api key from api.openweathermap.org{F.GREEN} 
[00]. To exit program: {F.CYAN}@exit{F.GREEN}

MORE Functions COMING... '''
        print (F.GREEN+tools)




    #getting dns details of web host
    def get_ip(self, host): #2
        try:
            data = self.soc.gethostbyname(host)
            print (F.CYAN+f"[✓]{host}: {F.BLUE}{data}")
        except:
            print (F.RED+"[x]Error, maybe invalid host or no network connection [*]")




    #multiple port scanning using ping results as timeout
    def port_scan(self, ip): #3
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

    


   #single port scan
    def port_scan_sin(self, ip, port): #4
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




   #converting binary to interger
    def Bina_Num(self, binary, base): #5
        try:
            print (F.GREEN+"[%]OUTPUT"+F.BLUE)
            print (F.BLUE+str(int(binary, int(base))))
        except:
            print (F.RED+"[x]An error occured")




    #converting number to binary
    def Num_Bina(self, num, base): #6
        try:
            num = int(num)
            base = int(base)
            print (F.GREEN+"[%]OUTPUT"+F.BLUE)
            print (F.BLUE+bin(num) [base: ])
        except:
            print (F.RED+"[x]An error occured")



 
    #convertinh alphabet to binary
    def Alpha_Bina(self): #7
        alph = input(F.YELLOW+"[%]Enter Text: "+F.WHITE)
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




     # converting binary to alphabet
    def Bina_Alpha(self): #8
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




   # getting device network details
    def get_device_ip(self): #9
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
        net = ip_network.netmask
        print(F.CYAN+"[*] MAC: "+F.BLUE+str(mac_address))
        print(F.CYAN+"[*] SUBNET: "+F.BLUE+str(net))
        sock.close()



   
    #getting device cpu information
    def cpu_info(self): #10
        try:
            print (F.BLUE+"[*]CPU DETAILS: ctrl+c to exit")

            while True:

                cpu_p = F.GREEN+str(p.cpu_percent())+'%'
                cpu_us =F.GREEN+str(p.cpu_count(logical=False))
                cpu_l = F.GREEN+str(p.cpu_count(logical=True))

                ram = p.virtual_memory()
                disk = p.disk_partitions()[0]
                d_usage = p.disk_usage(disk.mountpoint)

                total_ram = F.BLUE+str((ram.total // (1024 ** 2))//1024)

                ram_used = F.BLUE+str((ram.used // (1024 ** 2)) // 1024)

                cu = F.CYAN+'CPU USAGE'
                co = F.CYAN+'CPU CORES'
                cl = F.CYAN+'LOGICAL CPU'
                ra = F.CYAN+'RAM:'


                print (f'{cu}:{cpu_p} | {co}:{cpu_us} | {cl}:{cpu_l} | A-{ra}:{ram_used}/{total_ram}GB', end='\r', flush=True)
                tm.sleep(0.5)

        except:
            print (F.RED+"\n[*]EXITED")





   #open server for wifi chat
    def open_server(self): #11
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #sock = socket.socket()
        print (F.CYAN+"[NOTE]: ONLY SUPPORT WLAN")
        print(F.CYAN+"......: @bye to close chat")

        tm.sleep(1)
        a1, a2, a3 = str(rd.randint(1,6)), str(rd.randint(1,6)), str(rd.randint(1,5))
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
        print (F.BLUE+"[✓]SERVER STARTED")
        tm.sleep(1)
        print (F.GREEN+f"[*]IP: {ip}: [*]PORT: {port}")
    
        sock.bind(("0.0.0.0", int(port)))
        sock.listen(5)
        c, addr = sock.accept()

        while True:
            sen = input(F.CYAN+"[%]SEND-MESSAGE: "+F.WHITE)
            c.send(sen.encode())
            print (F.BLUE+"[✓]MESSAGE SENT")
            print (F.GREEN+"[*]WAITING FOR INCOMING MESSAGE")
            if sen == "@bye":
                tm.sleep(1)
                print (F.RED+"[*]CLOSING CHAT")
                c.close()
                break
            rec = c.recv(20480).decode()
            print (F.CYAN+"[*]RECEIVED-MESSAGE: ",F.WHITE+rec)
            if rec == "@bye":
                tm.sleep(1)
                print (F.RED+"[*]USER CLOSED CHAT")
                c.close()
                break




    #connect to wifi chat server
    def connect_server(self, ip, port): #12
         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         sock.connect((ip, int(port)))
            
         print (F.BLUE+"[✓]CONNECTED TO SERVER")
         tm.sleep(1)
         while True:
             print(F.GREEN+"[*]WAITING FOR INCOMING MESSAGE")
             rec = sock.recv(20480).decode()
             print (F.CYAN+"RECIEVED-MESSAGE: "+F.WHITE+rec)
             if rec == "@bye":
                 tm.sleep(1)
                 print(F.RED+"[*]USER CLOSED CHAT")
                 sock.close()
                 break
             sen = input(F.CYAN+"[%]SEND-MESSAGE: "+F.WHITE)
             sock.send(sen.encode())
             print (F.BLUE+"[✓]MESSAGE SENT")
             if sen == "@bye":
                 print (F.RED+"[*]CLOSING CHAT")
                 tm.sleep(1)
                 sock.close()
                 break




   # file systems 
    def file_sys(self, option, file): #13
        if option == "-C":
            if exists(file) == False:
                data = input(F.YELLOW+"[%]Enter Data: "+F.WHITE)
                open_file = open(file, "w")
                open_file.write(data)
                print (F.BLUE+"[✓]File created successfully".upper())
                open_file.close()
            else:
                print (F.RED+"[*]File already exists, wish to rewrite it".upper())
                opt = input(F.YELLOW+"[*]Y/N: "+F.WHITE).upper()
                if opt == "N":
                    print (F.BLUE+"[✓]File was maintained".upper())
                elif opt == "Y":
                    data = input(F.YELLOW+"[%]Enter Data: "+F.WHITE)
                    open_file = open(file, "w")
                    open_file.write(data)
                    print (F.BLUE+"[✓]File created successully".upper())
                    open_file.close()
                else:
                    print (F.RED+"[x]Error, try inputing valid data".upper())

        elif option == "-A":
            try:
                if exists(file):
                    data = input(F.YELLOW+"[%]Enter Data: "+F.WHITE)
                    open_file = open(file, "a")
                    open_file.write(data)
                    open_file.close()
                    print (F.BLUE+"[✓]Done".upper())
                else:
                    print (F.RED+"[x]File doesnt exists".uppper())
            except:
                print (F.RED+"[x]An error occured")
        elif option == "-D":
            if exists(file):
                os.remove(file)
                print (F.BLUE+"[✓]File deleted ".upper())
            else:
                print (F.RED+"[x]File doesnt exists".upper())
        elif option == "-V":
            if exists(file):
                print (F.BLUE+"[✓]File exists".upper())
            else:
                print (F.RED+"[x]File doesnt exists".upper())
        elif option == "-R":
            if exists(file):
                try:
                    open_file = open(file, "r")
                    print (F.BLUE+f"Data: {open_file.read()}")
                except:
                    open_file = open(file, 'rb')
                    print (F.BLUE+f"Data: {open_file.read()}")
            else:
                print (F.RED+"[x]File doesnt exists")
        elif option == "-ED":
            if exists(file):
                open_file = open(file, 'rb')
                data = open_file.read()
                open_file.close()

                reg = re.search(r"enc=", str(data))
                if reg != None:
                    print (F.GREEN+"[*]FILE IS IN ENCRYPTED FORMAT!!\n[*]WISH TO DECRYPT?")
                    opt = input(F.YELLOW+"[*]Y/N: "+F.WHITE).upper()
                    if opt == "Y":
                        #decryption here
                        print(F.BLUE+"[*]NOTE: KEY MUST BE EITHER 16, 24 OR 32 BYTES CHARACTER\n[*]MEANING YOUR KEY SHOULD BE ↑ABOVE↑ BYTES CHARACTER LONG")
                        key = input(F.CYAN+"[%]KEY: "+F.WHITE)
                        if len(key) == 16 or len(key) == 24 or len(key) == 32:
                            key = key.encode()
 
                            buffer_size = 65536
                            open_file = open(file, "rb")
                            iv = open_file.read(16)
                            open_file.close()
  
                            cipher_encrypt = AES.new(key, AES.MODE_CFB, iv=iv)
                            open_file = open(file, 'rb')
                            buffer = open_file.read(buffer_size)
                            output_file = open(file, "wb")

                            while len(buffer) > 0:
                                new = buffer.replace(b"enc=", b"")
                                decrypted_bytes = cipher_encrypt.decrypt(new)
                                new_data = decrypted_bytes
                                output_file.write(new_data)
                                buffer = open_file.read(buffer_size)

                            open_file.close()
                            output_file.close()

                            num = 0
                            for i in range(200):
                                num += 0.2
                                d = F.GREEN+"━"*int(num)
                                tm.sleep(0.01)
                                print(f'{F.BLUE}DECRYPTING FILE: {d}', end="\r", flush=True)
                            tm.sleep(0.2)
                            print (F.BLUE+"[✓]FILE DECRYPTED SUCCESSFULLY                                ")

                        else:
                            print (F.RED+"[x]INVALID KEY BYTE SIZE")

                    elif opt == "N":
                        print (F.BLUE+"[✓]OK")

                    else:
                        print (F.RED+"[x]Error, invalid input")

                elif reg == None:
                    print (F.GREEN+"[*]FILE IS IN DECRYPTED FORMAT!!\n[*]WISH TO ENCRYPT?")
                    opt = input(F.YELLOW+"[%]Y/N: "+F.WHITE).upper()
                    if opt == "Y":
                        #encryption here
                        print(F.BLUE+"[*]NOTE: KEY MUST BE EITHER 16, 24 OR 32 BYTES CHARACTER\n[*]MEANING YOUR KEY SHOULD BE ↑ABOVE↑ BYTES CHARACTER LONG")
                        key = input(F.CYAN+"[%]KEY: "+F.WHITE)
                        if len(key) == 16 or len(key) == 24 or len(key) == 32:
                            key = key.encode()

                            buffer_size = 65536 
                            
                            cipher_encrypt = AES.new(key, AES.MODE_CFB)
                            open_file = open(file, 'rb')
                            buffer = open_file.read(buffer_size)
                            output_file = open(file, "wb")
                            output_file.write(cipher_encrypt.iv)

                            while len(buffer) > 0:
                                ciphered_bytes = cipher_encrypt.encrypt(buffer)
                                new_data = b'enc='+ciphered_bytes
                                output_file.write(new_data)
                                buffer = open_file.read(buffer_size)
                            open_file.close()
                            output_file.close()

                            num = 0
                            for i in range(200):
                                num += 0.2
                                d = F.GREEN+"━"*int(num)
                                tm.sleep(0.01)
                                print(f'{F.BLUE}ENCRYPTING FILE:{d}', end="\r", flush=True)
                            tm.sleep(0.2)
                            print (F.BLUE+"[✓]FILE ENCRYPTED SUCCESSFULLY                                    ")
                            tm.sleep(0.6)
                            key_file = open("key.txt", "a")
                            cur_dir = os.getcwd()
                            key1 = str(key).replace("b", "")
                            key2 = key1.replace("'", "")
                            data = "∞[filnename= "+file+"|:|key= "+key2+" ]∞"
                            key_file.write(data)
                            print(f"{F.CYAN}[*]KEY SAVED ON {cur_dir}/key.txt")
                        else:
                            print(F.RED+"[x]INVALID KEY BYTE SIZE")

                    elif opt == "N":
                        print (F.BLUE+"[✓]OK")

                    else:
                        print (F.RED+"[x]Error, invalid input")
            else:
                print (F.RED+"[x]File doesnt exists")




    # send message to a whatsapp contact
    def send_mess(self, number): #14
        try:
            message = input(F.YELLOW+"[%]Message: "+F.WHITE).replace(" ", "%20")
            sys(f'xdg-open https://wa.me/{number}?text={message}')
            print (F.BLUE+"[*]OPENING WHATSAPP....")
        except:
            print ("[x]An Error occured")




   #send file via wifi or localhost
    def send_file(self): #15
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        a1, a2, a3 = str(rd.randint(1,6)), str(rd.randint(1,6)), str(rd.randint(1,5))
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
        size = open(file_path, 'rb')
        size = len(size.read())
        print (F.BLUE+"[*]WAITING FOR USER TO RECIEVE")
        

        num = 0
        while True:
            try:
                num += 1
                file = file_path
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




   #recieve file via wifi or localhost
    def recv_file(self, ip, port): #16
        c_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c_socket.connect((ip, int(port)))
        print(F.BLUE+"[✓]CONNECTED TO SERVER")
        #tm.sleep(1)
        data = c_socket.recv(1024).decode()
        print (F.BLUE+data)

        file = input(F.YELLOW+"[%]/save/to/path/to/file: "+F.WHITE)

        choice = input(F.YELLOW+"[%]WISH TO ACCEPT: Y/N: "+F.WHITE).upper()
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




    # connect to shell client
    def shell_host(self): #17
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tm.sleep(1)
        a1, a2, a3 = str(rd.randint(1,6)), str(rd.randint(1,6)), str(rd.randint(1,5))
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
        print(F.CYAN+"[*]NOTE: input <exit> to close session")
        print (F.BLUE+"[✓]SHELL HOST STARTED")
        tm.sleep(1)
        print (F.GREEN+f"[*]IP: {ip}: [*]PORT: {port}")

        sock.bind(("0.0.0.0", int(port)))
        sock.listen(5)
        c, addr = sock.accept()
        print (F.GREEN+"[✓]CLIENT CONNECTED")

        while True:
            data = input(F.CYAN+"\n[shell]•••→ "+F.WHITE)
            if data == "exit":
                c.send(data.encode())
                print(F.RED+"[*]CLOSING SHELL")
                tm.sleep(1)
                c.close()
                break
            c.send(data.encode())
            rec = c.recv(51200).decode()
            print(F.WHITE+rec)




   # open shell connection
    def shell_client(self, ip, port): #18
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, int(port)))
        print(F.BLUE+"[✓]CONNECTED TO HOST")
        tm.sleep(1)
        print(F.CYAN+"[*]SHELL ACTIVITY IN PROGRESS")
        
        while True:
            data = sock.recv(1024).decode()
            if data == "exit":
                print (F.RED+"[*]CLOSING SHELL")
                tm.sleep(1)
                sock.close()
                break
            elif data.startswith('cd '):
                path = data[3:]
                try:
                    os.chdir(path)
                    path = os.getcwd()
                    sock.send(f'~{path}'.encode())
                except:
                    sock.send("Invalid Directory".encode())
            else:
                decode_data = sub.getoutput(data)
                sock.send(f'|{decode_data}'.encode())




    # encrypt string 
    def crypt(self): #19
        data = input(F.CYAN+"[%]Data: "+F.WHITE)
        data1 = data.replace(" ", "~").encode()
        cryp_hash = str(0000)
        rep = len(data)-1//len(cryp_hash)+1
        a4 = (cryp_hash*rep)[:len(data)].encode()
        new_data = bytes([i1^i2 for (i1,i2) in zip(data1 , a4)])
        dec_data = new_data.decode()
        rep1 = dec_data.replace("~", " ")
        print(F.CYAN+"[*]Data: "+F.BLUE+rep1)




   # phone number osint
    def check_phone(self, number): #20
        user_phone = number
        C = F.CYAN
        B = F.BLUE

        default_region = 'ID'

        parsed_num = phone.parse(user_phone, default_region)
        region_code = phone.region_code_for_number(parsed_num)
        jenis_provider = carrier.name_for_number(parsed_num, "en")
        location = geocoder.description_for_number(parsed_num, "id")
        is_valid_number = phone.is_valid_number(parsed_num)
        is_possible_number = phone.is_possible_number(parsed_num)
        formatted_number = phone.format_number(parsed_num, phone.PhoneNumberFormat.INTERNATIONAL)

        formated_num_mo = phone.format_number_for_mobile_dialing(parsed_num, default_region, with_formatting=True)

        number_type = phone.number_type(parsed_num)
        timezone1 = phone.timezone.time_zones_for_number(parsed_num)
        timezoneF = ', '.join(timezone1)
        
        num = 0
        r = 0
        for i in range(100):
            num += 0.2
            d = F.GREEN+'█'*int(num)
            r += 1
            tm.sleep(0.01)
            print(f'{B}[*]LOADING INFORMATION: {d} : {C}{str(r)}%', end='\r', flush=True)

        print(f"\n\n{C}[*]Location             :{B}{location}")
        print(f"{C}[*]Region Code          :{B}{region_code}")
        print(f"{C}[*]Timezone             :{B}{timezoneF}")
        print(f"{C}[*]Operator             :{B}{jenis_provider}")
        print(f"{C}[*]Valid number         :{B}{is_valid_number}")
        print(f"{C}[*]Possible number      :{B}{is_possible_number}")
        print(f"{C}[*]International format :{B}{formatted_number}")
        print(f"{C}[*]Mobile format        :{B}{formated_num_mo}")
        print(f"{C}[*]Original number      :{B}{parsed_num.national_number}")
        print(f"{C}[*]E.164 format         :{B}{phone.format_number(parsed_num, phone.PhoneNumberFormat.E164)}")
        print(f"{C}[*]Country code         :{B}{parsed_num.country_code}")
        print(f"{C}[*]Local number         :{B}{parsed_num.national_number}")
        if number_type == phone.PhoneNumberType.MOBILE:
            print(f"{C}[*]Type                 :{B}This is a mobile number")
        elif number_type == phone.PhoneNumberType.FIXED_LINE:
            print(f"{C}[*]Type                 :{B}This is a fixed-line number")
        else:
            print(f"{C}[*]Type                 :{B}This is another type of number")




   # vulnerability scanner
    def scan_vul(self, target): #21
        api_key = input(F.YELLOW+"[*]API-KEY : "+F.WHITE)
        secret_key = input(F.YELLOW+"[%]SECRET-KEY: "+F.WHITE)
        access_key = input(F.YELLOW+"[%]ACESS-KEY: "+F.WHITE)

        api_url = 'https://cloud.tenable.com/api/v2/policies'
        headers = {
                'Content-Type': 'application/json',
                'X-ApiKeys': f'accessKey={access_key};secretKey={secret_key}'
                }

        try:
            response = r.get(api_url, headers)
            if response.status_code == 200:
                policies = response.json()

                for policy in policies['policies']:
                    policy_id = policy['policy_id']

                load = TenableIO(api_key=api_key, secret_key=secret_key)
                scan = load.scans.create("My scan", targets=[target], policy_id=policy_id)
                scan.launch()

                while scan.status() != 'completed':
                    pass

                results = scan.results()
                for vul in results['vulnerabilities']:
                    print(f"{F.BLUE}[*]Vulnerabilty: {F.GREEN}{vul['plugin_name']}\t{F.BLUE}[*]Severity: {F.GREEN}{vul['severity']}")
            
            else:
                print(f"{F.RED}[x]ERROR: {F.BLUE}{response.status_code}-{F.GREEN}{response.text}")
        except requests.exceptions.RequestException as e:
            print(F.RE+"[x]Error connecting to host")




    #scan a network
    def net_scan(self, target): #22
        
        arp_request = ARP(pdst=target)

        ether = Ether(dst='ff:ff:ff:ff:ff:ff')
        packet = ether/arp_request

        result = srp(packet, timeout=3, verbose=0)[0]
        devices_list = []

        for sent, received in result:
                devices_list.append({'ip': received.psrc, 'mac': received.hwsrc})
        return device_list

            
        data = device_list
        for device in data:
                print(f"{F.BLUE}IP: {F.GREEN}{device['ip']} || {F.BLUE}MAC: {F.GREEN}{device['mac']}")




    #scan a packet
    def packet_sniffer(self, interface): #23
        packets = sniff(prn=lambda x: x.summary(), filter="tcp", iface=interface, store=0, count=10)
        for packet in packets:
            print(F.BLUE+packet.summary())




   # check weather
    def weather(self, city): #24
        try:
            api_key = input(F.YELLOW+"[%]API-KEY: "+F.WHITE)
            base_url = "http://api.openweathermap.org/data/2.5/weather"
            params = {"q": city, "appid": api_key, "units": "metric"}
            response = r.get(base_url, params=params)
            data = response.json()
            if response.status_code == 200:
                main_weather = data["weather"][0]["description"]
                temperature = data["main"]["temp"]
                print(f"{F.BLUE}WEATHER: {F.GREEN}{main_weather} \t {F.BLUE}TEMPERATURE: {F.GREEN}{temperature}°C")
            else:
                print(F.RED+"[x]Error loading credentials")
        except r.exceptions.RequestException as e:
            print(F.RED+"[x]Error connecting to host")
            








#RUNNING ALL FUNCTIONS
shark = shark()
if __name__ == '__main__':
    shark.main()
    while True:
        data = inpu()
        try:
            #data = inpu()
            if "@help" in data: #1
                shark.help()
            elif "@get -ip" in data: #2
                shark.get_ip(data.split()[2])
            elif "@port -scan" in data: #3
                shark.port_scan(data.split()[2])
            elif "@port--s -scan" in data: #4
                shark.port_scan_sin(data.split()[2], data.split()[3])
            elif "@bina -a" in data: #5
                shark.Bina_Alpha()
            elif "alpha -b" in data: #6
                shark.Alpha_Bina()
            elif "@num -b" in data: #7
                shark.Num_Bina(data.split()[2], data.split()[3])
            elif "@bina -n" in data: #8
                shark.Bina_Num(data.split()[2], data.split()[3])
            elif "@ip -details" in data: #9
                shark.get_device_ip()
            elif "@cpu" in data: #10
                shark.cpu_info()
            elif "@open -server" in data: #11
                shark.open_server()
            elif "@con -server" in data: #12
                shark.connect_server(data.split()[2], data.split()[3])
            elif "@file" in data: #13
                shark.file_sys(data.split()[1], data.split()[2])
            elif "@send -w" in data: #14
                shark.send_mess(data.split()[2])
            elif "@send -file" in data: #15
                shark.send_file()
            elif "@recv -file" in data: #16
                shark.recv_file(data.split()[2], data.split()[3])
            elif data == "@shell -host": #17
                shark.shell_host()
            elif "@shell -client" in data: #18
                shark.shell_client(data.split()[2], data.split()[3])
            elif "@crypt" in data: #19
                shark.crypt()
            elif "@check -no" in data: #20
                shark.check_phone(data.split()[2])
            elif "@scan -v" in data: #21
                shark.scan_vul(data.split()[2])
            elif "@net -a" in data: #22
                shark.net_scan(data.split()[2])
            elif "@sniff -p" in data: #23
                shark.packet_sniffer(data.split()[2])
            elif "@check -w" in data: #24
                shark.weather(data.split()[2])
            elif "@exit" in data: #00
                print (F.RED+"[✓]EXITING PROGRAM...")
                tm.sleep(1)
                break
            elif data.lstrip().startswith('cd') and "cd" != data.strip():
                d_path = ' '.join(filter(None, data.split()))
                path = d_path[3:]
                try:
                    os.chdir(path)
                except:
                    print (f"cd:{path}: No such file or directory")
            elif data.strip() == 'cd':
                
                os.chdir(os.path.expanduser("~"))
            
            else:
                print (F.WHITE+"")
                sys(data)
        except FileNotFoundError as er:
            print(F.RED+"[x]", er)
        except IsADirectoryError as er:
            print(F.RED+"[x]", er)
        except ValueError as er:
            print(F.RED+"[x]", er)
        except TypeError as er:
            print(F.RED+"[x]", er)
        except ValueError as er:
            print(F.RED+"[x]", er)
        except PermissionError as er:
            print(F.RED+"[x]", er,": needs administrator priviledge")
        except KeyboardInterrupt:
            print(F.CYAN+"[✓] Closed")
        except:
            print (F.RED+"[x]An Error occured")
