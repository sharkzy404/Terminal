#!/usr/bin/env python3
from os import system as sys

try:
    sys("pip install colorama")
    sys("pip install regex")
    sys("pip install tqdm")
    sys("pip install xdg")
    sys("pip install uuid")
    sys("pip install ipaddress")
    sys("pip install requests")
    sys("pip install psutil")
    sys("pip install phonenumbers")
    sys("pip install pycryptodome")
    sys("pip install tenable-io")
    sys("pip install pytenable")
    sys("pip install scapy")
except:
    print ("[*] An error occured")

path_to_pro = input("[*]::'/path/to/term.py': ")
path_to_bin = input("[*]::'/path/to/bin': ")

try:
    sys(f"chmod +x {path_to_pro}")
    sys(f"ln -s {path_to_pro} {path_to_bin}/term")
    print ("[*] IF NOT ERROR: Start Terminal By executing: 'term'")
except:
    print ("[*] An Error Occured")




