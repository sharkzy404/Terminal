from os import system as sys
from colorama import Fore as F
import time as tm
import socket
import subprocess as sub
import random as rd
from os.path import exists
import os
import re

sys("clear")

def inpu():
    print ("\n")
    subt = sub.getoutput("whoami")
    data =  input(F.YELLOW+f".———[{subt}@Shark]\n|\n°———> "+ F.GREEN)
    return data

class shark:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.soc    = socket
        self.sock   = socket.socket()

    def main(self):
        data = """
                   "Welcome To Mr.Shark Terminal"
                   For help and functions: @help """
        print (F.GREEN+data)

    def help(self):
        tools = """
[1]. Getting Ip address: @get -ip [target]
     Example: @get -ip google.com
[2]. Port scanning: @port -scan [target]
     Example: @port -scan 127.0.0.1
[3]. Convert Number to Binary: @num -b [number] [base]
     Example: @num -b 2000 2
[4]. Convert Binary to Number: @bina -n [binary] [base]
     Example: @bina -n 1011101010 2
[5]. Convert Alphabet to Binary: @alpha -b
     Example: @alpha -b
[6]. Convert Binary to Alphabet: @bina -a
     Example: @bina -a
[7]. To get device IP address: @ip -details
     Example: @ip -details
[8]. To get cpu info: @cpu
     Example: @cpu
[9]. To open server: @open -server
     Example: @open -server
     Note: multiple servers cant be opened at once,
           The program is going to close and restart,
           If trying to open another server after force closing,
           A recent connection.
     Note: The program should be named term.py: because thats the file,
           Its going to re-open, you can modify it....
[10].To create file: @file <option> <file_name>
     Options: -C create file
              -A append data to existsing file
              -D delete file
              -R read data from a file
              -V check if file exists
              -ED encrypt/decrypt file
     Example: @file -CADVEnDe filename.txt
[11].To send message to a whatsapp contact: @send -w <number>
    Example: @send -w +1234567890

[12]. To exit the program: @exit

MORE Functions COMING...

        """
        print (F.GREEN+tools)

    def get_ip(self, host): #1
        try:
            data = self.soc.gethostbyname(host)
            print (F.BLUE+f"{host}: {data}")
        except:
            print (F.RED+"[*] Error, maybe invalid host or no network connection [*]")

    def port_scan(self, ip): #2
        try:
            total_port = 0
            port = 0
            self.socket.settimeout(0.05)
            for i in range(65536):
                port += 1
                try:
                    self.socket.connect((ip, port))
                    total_port += 1
                    print (F.BLUE+f"Port {port} opened for {ip}")
                    self.socket.close()
                    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.socket.settimeout(0.05)
                except KeyboardInterrupt:
                    break
                except:
                    self.socket.close()
                    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREM)
                    self.socket.settimeout(0.05)
                    pass
            print (F.YELLOW+f" [*]Total port opened for {ip} is : {total_port} ")
        except KeyboardInterrupt:
            pass

    def Bina_Num(self, binary, base): #3
        try:
            print (int(binary, int(base)))
        except:
            print (F.RED+"[*] an error occured [*]")

    def Num_Bina(self, num, base): #4
        try:
            num = int(num)
            base = int(base)
            print (bin(num) [base: ])
        except:
            print (F.RED+"[*] an error occured [*]")

    def Alpha_Bina(self): #5
        alph = input(F.BLUE+"[*] data: ").split(" ")
        num = -1
        try:
            while True:
                num += 1
                try:
                    for data in bytearray(alph[num], "utf-8"):
                        print (format(data, "b"))
                except:
                    break
        except:
            print (F.RED+"[*] an error occured [*]")

    def Bina_Alpha(self): #6
        try:
            splita = input(F.BLUE+"[*] data: ").split(" ")
            for data in splita:
                data1 = int(data, 2)
                charac = chr(data1)
                print (charac, end = "")
            print ("\n")
        except:
            print (F.RED+"[*] an error occured [*]")

    def get_device_ip(self): #7
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(('192.255.255.255',1))
            print (F.BLUE+sock.getsockname()[0])
        except:
            print(F.BLUE+sub.getoutput('ifconfig').split(" ")[13])

    def cpu_info (self): #8
        try:
            sys("cat /proc/cpuinfo")
        except:
            print ("[*] an error occured [*]")

    def open_server(self): #9
        tm.sleep(2)
        print (F.YELLOW+"[*] Starting Server")
        print (F.GREEN+"[*] To close connection Ctrl -C")

        tm.sleep(2)
        a1, a2, a3 = str(rd.randint(1,6)), str(rd.randint(1,6)), str(rd.randint(1,6))
        ip = sub.getoutput('ifconfig').split(" ")[13]
        port = a3+a2+a1+a2+a3
        try:
            self.sock.bind(("0.0.0.0", int(port)))
            print (F.BLUE+"Server Started")
            tm.sleep(1)
            print (F.GREEN+f"IP: {ip}: PORT: {port}")

            self.sock.listen(5)

            c, addr = self.sock.accept()

            while True:
                c.send("Waiting for incoming Message::\n".encode())
                out_mes = input("[*]Send-Message: ")
                if out_mes == "bye":
                    c.close()
                    break
                c.send(f"Receiced message: {out_mes}\n[*]Send-Message: ".encode())
                print ("Message Sent\nWaiting for incoming Message::")

                inp_mes = c.recv(1024).decode()
                print (f"[*]Received-Message: {inp_mes}")
                if inp_mes == "bye":
                    c.close()
                    break
        except KeyboardInterrupt:
            print (F.RED+" [*] Forced Closed [*]")
        except OSError:
            print (F.RED+"[*]Socket already opened: Closing and RestartingProgram in 2secs [*]")
            tm.sleep(2)
            sys("python term.py")


    def file_sys(self, option, file): #10
        if option == "-C":
            if exists(file) == False:
                data = input(F.BLUE+"[*] Enter Data: ")
                open_file = open(file, "w")
                open_file.write(data)
                print (F.GREEN+"File created successfully")
                open_file.close()
            else:
                print ("File already exists, wish to rewrite it")
                opt = input("Y/N: ").upper()
                if opt == "N":
                    print ("File was maintained")
                elif opt == "Y":
                    data = input("[*] Enter Data: ")
                    open_file = open(file, "w")
                    open_file.write(data)
                    print ("File created successully")
                    open_file.close()
                else:
                    print ("Error, try inputing details")

        elif option == "-A":
            try:
                if exists(file):
                    data = input("[*] Enter Data: ")
                    open_file = open(file, "a")
                    open_file.write(data)
                    open_file.close()
                    print ("Done")
                else:
                    print ("File doesnt exists")
            except:
                print ("[*] an error occured [*]")
        elif option == "-D":
            if exists(file):
                os.remove(file)
                print ("File deletes successfully")
            else:
                print ("File doesnt exists")
        elif option == "-V":
            if exists(file):
                print ("File exists")
            else:
                print ("File doesnt exists")
        elif option == "-R":
            if exists(file):
                open_file = open(file, "r")
                print (f"Data: {open_file.read()}")
            else:
                print ("File doesnt exists")
        elif option == "-ED":
            if exists(file):
                open_file = open(file, "r")
                data = open_file.read()
                open_file.close()
                reg = re. compile( '[@_!#$%^&*()<>?/\|}{~:]' )
                if reg.search(data) != None:
                    print ("File is in encrypted format\nWish to decrypt")
                    opt = input("Y/N: ").upper()
                    if opt == "Y":
                        decryp_hash = str(0000)
                        data1 = data.encode()
                        rep = len(data)-1//len(decrp_hash)+1
                        a4 = (decryp_hash*rep)[:len(data)].encode()
                        new_data = bytes([i1^i2 for (i1,i2) in zip(data1, a4)])
                        dec_data = new_data.decode()
                        rep_data = dec_data.replace("~", " ")
                        new_file = open(file, "w")
                        new_file.write(rep_data)
                        new_file.close()
                        print ("Decrypting File.....")
                        tm.sleep(1)
                        print ("File Decrypted succesfully")
                    elif opt == "N":
                        print ("Ok")
                    else:
                        print ("Error, invalid input")

                elif reg.search(data) == None:
                    print ("File is in decrypted Format\nWish to encrypt")
                    opt = input("Y/N: ").upper()
                    if opt == "Y":
                        decryp_hash = str(0000)
                        data1 = data.replace(" ", "~").encode()
                        rep = len(data)-1//len(decryp_hash)+1
                        a4 = (decryp_hash*rep)[:len(data)].encode()
                        new_data = bytes([i1^i2 for (i1,i2) in zip(data1, a4)])
                        new_file = open(file, "w")
                        new_file.write(new_data.decode())
                        new_file.close()
                        print ("Encrpyting file.....")
                        tm.sleep(2)
                        print ("File Encrypted successfully")
                    elif opt == "N":
                        print ("Ok")
                    else:
                        print ("Error, invalid input")
            else:
                print ("File doesnt exists")


    def send_mess(self, number): #11
        try:
            message = input("Message: ").replace(" ", "%20")
            sys(f'xdg-open https://wa.me/{number}?text={message}')
            print ("done")
        except:
            print ("Error occured")

    def exit(self): #12
        print (F.BLUE+"[*] QUITING PROGRAM [*]" )
        tm.sleep(1.5)
        quit(0)


shark = shark()
if __name__ == '__main__':
    shark.main()
    while True:
        data = inpu()
        if "@get -ip" in data: #1
            shark.get_ip(data.split()[2])
        elif "@port -scan" in data: #2
            shark.port_scan(data.split()[2])
        elif "@bina -a" in data: #3
            shark.Bina_Alpha()
        elif "@alpha -b" in data: #4
            shark.Alpha_Bina()
        elif "@num -b" in data: #5
            shark.Num_Bina(data.split()[2], data.split()[3])
        elif "@bina -n" in data: #6
            shark.Bina_Num(data.split()[2], data.split()[3])
        elif data == "@ip -details": #7
            shark.get_device_ip()
        elif data == "@cpu": #8
            shark.cpu_info()
        elif data == "@open -server": #9
            shark.open_server()
        elif "@file" in data: #10
            shark.file_sys(data.split()[1], data.split()[2])
        elif "@send -w" in data: #11
            shark.send_mess(data.split()[2])
        elif "@help" in data:
            shark.help()
        elif data == "@exit": #12
            shark.exit()
        else:
            sys(data)
