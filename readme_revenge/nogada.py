# -*- coding: utf-8 -*-

import sys
from pwn import *

"""
$ python -c 'print "A"*3000' | ./readme_revenge
$ gdb ./readme_revenge ./core
$ 
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x000000000045ad64 in __parse_one_specmb ()
(gdb) bt
#0  0x000000000045ad64 in __parse_one_specmb ()
#1  0x0000000000443153 in printf_positional ()
#2  0x0000000000446ed2 in vfprintf ()
#3  0x0000000000407a74 in printf ()
#4  0x0000000000400a56 in main ()
(gdb)
"""

r = process('./readme_revenge')

r.send('babo\n')

print (r.recv())
