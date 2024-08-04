#!/bin/bash

echo 'Operating System: [android/kali] [1/2]: ' 
read user_input

if [ "$user_input" -eq 1 ]; then
    echo 'Installing Python3'
    pkg install python3
    echo 'Done'
    ./UTILS/android_setup.py
elif [ "$user_input" -eq 2 ]; then
    echo 'Installing Python3'
    apt-get install python3
    echo 'Done'
    ./UTILS/kali_setup.py
else
    echo 'Invalid input'
fi
