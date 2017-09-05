#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
    printf("argv: %p\n", argv);
    printf("argv[0]: %p\n", argv[0]);

    printf("envp: %p\n", envp);
    printf("envp[0]: %p\n", envp[0]);
    return 0;
}
