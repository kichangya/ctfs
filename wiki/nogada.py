#
# Google CTF 2017 pwn wiki
#

from pwn import *

r = process('./challenge', aslr=False)

r.send('USER\n')
r.send('zomo\n')
r.send('PASS\n')
r.send('babo1234\n')
r.interactive()
