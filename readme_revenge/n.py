# -*- coding: utf-8 -*-

import sys
from pwn import *
from binascii import unhexlify

lines = [line.rstrip('\n') for line in open('memdump')]

overwrites = ''
for l in lines:
    a = l.split()
    b = a[-8:]
    for c in b:
        d = c.replace('0x','')
        e = unhexlify(d)
        if e == '\x09' or e == '\x0a' or e == '\x0b' or e == '\x0c' or e == '\x0d' or e == '\x20':
            #print "[*] Found delimeter 0x%02X" % ord(e)
            e = '\x41'
        overwrites += e

#r.send(overwrites + '\n')

#print (r.recv())

print overwrites+'\n'
