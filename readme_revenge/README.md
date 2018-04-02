34C3 CTF 2017 pwn readme_revenge

## How-to

* $ python nogada.py

or

```
z@ubuntu:~/git/ctfs/readme_revenge$ export LIBC_FATAL_STDERR_=1
z@ubuntu:~/git/ctfs/readme_revenge$ socat TCP-LISTEN:8000,reuseaddr exec:"./readme_revenge",stderr

-----

Hi, z@ubuntu:~/git/ctfs/readme_revenge$ python n.py|nc localhost 8000
*** stack smashing detected ***: 34C3_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX terminated
======= Backtrace: =========
[0x40a29e]
[0x435a08]
[0x4359c1]
[0x45ad2e]
[0x443153]
[0x446ed2]
[0x407a74]
[0x400a56]
[0x400c84]
[0x400efd]
[0x40092a]
======= Memory map: ========
00400000-004b1000 r-xp 00000000 08:01 926295                             /home/z/git/ctfs/readme_revenge/readme_revenge
006b1000-006b7000 rw-p 000b1000 08:01 926295                             /home/z/git/ctfs/readme_revenge/readme_revenge
006b7000-006b8000 rw-p 00000000 00:00 0
00764000-00787000 rw-p 00000000 00:00 0                                  [heap]
7fd497f50000-7fd497f51000 rw-p 00000000 00:00 0
7ffe9ad7e000-7ffe9ad9f000 rw-p 00000000 00:00 0                          [stack]
7ffe9adc0000-7ffe9adc2000 r--p 00000000 00:00 0                          [vvar]
7ffe9adc2000-7ffe9adc4000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
Hi, z@ubuntu:~/git/ctfs/readme_revenge$
```

## Write-ups

* https://github.com/r00ta/myWriteUps/tree/master/34C32017/pwn_readme_revenge
