/* This file has been generated by the Hex-Rays decompiler.
   Copyright (c) 2007-2017 Hex-Rays <info@hex-rays.com>

   Detected compiler: GNU C++
*/

#include <defs.h>


//-------------------------------------------------------------------------
// Function declarations

void *init_proc();
__int64 sub_4006A0();
// void free(void *ptr);
// int puts(const char *s);
// int printf(const char *format, ...);
// unsigned int alarm(unsigned int seconds);
// ssize_t read(int fd, void *buf, size_t nbytes);
// __int64 __gmon_start__(void); weak
// void *malloc(size_t size);
// void *realloc(void *ptr, size_t size);
// int setvbuf(FILE *stream, char *buf, int modes, size_t n);
// int atoi(const char *nptr);
signed __int64 sub_4007A0();
__int64 sub_4007D0();
signed __int64 sub_400810();
__int64 sub_400830();
__int64 __fastcall sub_40085D(__int64 a1, signed int a2);
__int64 __fastcall sub_4008C9(__int64 a1, int a2);
int sub_40094E();
int sub_400998();
unsigned int sub_4009FD();
_QWORD *sub_400A49();
int sub_400B14();
int sub_400BC2();
int sub_400D87();
int sub_400F7D();
__int64 __fastcall main(__int64 a1, char **a2, char **a3);
void __fastcall init(unsigned int a1, __int64 a2, __int64 a3);
void term_proc();
// void free(void *ptr);

//-------------------------------------------------------------------------
// Data declarations

__int64 (__fastcall *off_601E10[2])() = { &sub_400830, &sub_400810 }; // weak
__int64 (__fastcall *off_601E18)() = &sub_400810; // weak
__int64 (*qword_602010)(void) = NULL; // weak
_UNKNOWN unk_602088; // weak
_UNKNOWN unk_60208F; // weak
FILE *stdout; // idb
FILE *stdin; // idb
char byte_6020A0; // weak
__int64 qword_6020A8; // weak
// extern _UNKNOWN _gmon_start__; weak


//----- (0000000000400678) ----------------------------------------------------
void *init_proc()
{
  void *result; // rax

  result = &_gmon_start__;
  if ( &_gmon_start__ )
    result = (void *)__gmon_start__();
  return result;
}
// 400720: using guessed type __int64 __gmon_start__(void);

//----- (00000000004006A0) ----------------------------------------------------
__int64 sub_4006A0()
{
  return qword_602010();
}
// 602010: using guessed type __int64 (*qword_602010)(void);

//----- (0000000000400770) ----------------------------------------------------
#error "400776: positive sp value has been found (funcsize=3)"

//----- (00000000004007A0) ----------------------------------------------------
signed __int64 sub_4007A0()
{
  signed __int64 result; // rax

  result = &unk_60208F - &unk_602088;
  if ( (unsigned __int64)(&unk_60208F - &unk_602088) > 0xE )
    result = 0LL;
  return result;
}

//----- (00000000004007D0) ----------------------------------------------------
__int64 sub_4007D0()
{
  return 0LL;
}

//----- (0000000000400810) ----------------------------------------------------
signed __int64 sub_400810()
{
  signed __int64 result; // rax

  if ( !byte_6020A0 )
  {
    result = sub_4007A0();
    byte_6020A0 = 1;
  }
  return result;
}
// 6020A0: using guessed type char byte_6020A0;

//----- (0000000000400830) ----------------------------------------------------
__int64 sub_400830()
{
  return sub_4007D0();
}
// 400830: could not find valid save-restore pair for rbp

//----- (000000000040085D) ----------------------------------------------------
__int64 __fastcall sub_40085D(__int64 a1, signed int a2)
{
  unsigned int i; // [rsp+18h] [rbp-8h]
  int v4; // [rsp+1Ch] [rbp-4h]

  if ( a2 <= 0 )
    return 0LL;
  for ( i = 0; (signed int)i < a2; i += v4 )
  {
    v4 = read(0, (void *)(a1 + (signed int)i), (signed int)(a2 - i));
    if ( v4 <= 0 )
      break;
  }
  return i;
}

//----- (00000000004008C9) ----------------------------------------------------
__int64 __fastcall sub_4008C9(__int64 a1, int a2)
{
  int i; // [rsp+18h] [rbp-8h]

  if ( a2 <= 0 )
    return 0LL;
  for ( i = 0; a2 - 1 > i && (signed int)read(0, (void *)(i + a1), 1uLL) > 0 && *(_BYTE *)(i + a1) != 10; ++i )
    ;
  *(_BYTE *)(i + a1) = 0;
  return (unsigned int)i;
}

//----- (000000000040094E) ----------------------------------------------------
int sub_40094E()
{
  char nptr; // [rsp+0h] [rbp-30h]
  unsigned __int64 v2; // [rsp+28h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  sub_4008C9((__int64)&nptr, 32);
  return atoi(&nptr);
}

//----- (0000000000400998) ----------------------------------------------------
int sub_400998()
{
  puts("== 0ops Free Note ==");
  puts("1. List Note");
  puts("2. New Note");
  puts("3. Edit Note");
  puts("4. Delete Note");
  puts("5. Exit");
  puts("====================");
  printf("Your choice: ");
  return sub_40094E();
}

//----- (00000000004009FD) ----------------------------------------------------
unsigned int sub_4009FD()
{
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  return alarm(0x3Cu);
}

//----- (0000000000400A49) ----------------------------------------------------
_QWORD *sub_400A49()
{
  _QWORD *v0; // rax
  _QWORD *result; // rax
  signed int i; // [rsp+Ch] [rbp-4h]

  v0 = malloc(0x1810uLL);
  qword_6020A8 = (__int64)v0;
  *v0 = 256LL;
  result = (_QWORD *)qword_6020A8;
  *(_QWORD *)(qword_6020A8 + 8) = 0LL;
  for ( i = 0; i <= 255; ++i )
  {
    *(_QWORD *)(qword_6020A8 + 24LL * i + 16) = 0LL;
    *(_QWORD *)(qword_6020A8 + 24LL * i + 24) = 0LL;
    result = (_QWORD *)(qword_6020A8 + 24LL * i + 32);
    *result = 0LL;
  }
  return result;
}
// 6020A8: using guessed type __int64 qword_6020A8;

//----- (0000000000400B14) ----------------------------------------------------
int sub_400B14()
{
  __int64 v0; // rax
  unsigned int i; // [rsp+Ch] [rbp-4h]

  if ( *(_QWORD *)(qword_6020A8 + 8) <= 0LL )
  {
    LODWORD(v0) = puts("You need to create some new notes first.");
  }
  else
  {
    for ( i = 0; ; ++i )
    {
      v0 = *(_QWORD *)qword_6020A8;
      if ( (signed __int64)(signed int)i >= *(_QWORD *)qword_6020A8 )
        break;
      if ( *(_QWORD *)(qword_6020A8 + 24LL * (signed int)i + 16) == 1LL )
        printf("%d. %s\n", i, *(_QWORD *)(qword_6020A8 + 24LL * (signed int)i + 32));
    }
  }
  return v0;
}
// 6020A8: using guessed type __int64 qword_6020A8;

//----- (0000000000400BC2) ----------------------------------------------------
int sub_400BC2()
{
  __int64 v0; // rax
  void *v1; // ST18_8
  int i; // [rsp+Ch] [rbp-14h]
  int v4; // [rsp+10h] [rbp-10h]

  if ( *(_QWORD *)(qword_6020A8 + 8) < *(_QWORD *)qword_6020A8 )
  {
    for ( i = 0; ; ++i )
    {
      v0 = *(_QWORD *)qword_6020A8;
      if ( (signed __int64)i >= *(_QWORD *)qword_6020A8 )
        break;
      if ( !*(_QWORD *)(qword_6020A8 + 24LL * i + 16) )
      {
        printf("Length of new note: ");
        v4 = sub_40094E();
        if ( v4 > 0 )
        {
          if ( v4 > 4096 )
            v4 = 4096;
          v1 = malloc((128 - v4 % 128) % 128 + v4);
          printf("Enter your note: ");
          sub_40085D((__int64)v1, v4);
          *(_QWORD *)(qword_6020A8 + 24LL * i + 16) = 1LL;
          *(_QWORD *)(qword_6020A8 + 24LL * i + 24) = v4;
          *(_QWORD *)(qword_6020A8 + 24LL * i + 32) = v1;
          ++*(_QWORD *)(qword_6020A8 + 8);
          LODWORD(v0) = puts("Done.");
        }
        else
        {
          LODWORD(v0) = puts("Invalid length!");
        }
        return v0;
      }
    }
  }
  else
  {
    LODWORD(v0) = puts("Unable to create new note.");
  }
  return v0;
}
// 6020A8: using guessed type __int64 qword_6020A8;

//----- (0000000000400D87) ----------------------------------------------------
int sub_400D87()
{
  __int64 v1; // rbx
  int v2; // [rsp+4h] [rbp-1Ch]
  int v3; // [rsp+8h] [rbp-18h]

  printf("Note number: ");
  v3 = sub_40094E();
  if ( v3 < 0 || (signed __int64)v3 >= *(_QWORD *)qword_6020A8 || *(_QWORD *)(qword_6020A8 + 24LL * v3 + 16) != 1LL )
    return puts("Invalid number!");
  printf("Length of note: ");
  v2 = sub_40094E();
  if ( v2 <= 0 )
    return puts("Invalid length!");
  if ( v2 > 4096 )
    v2 = 4096;
  if ( v2 != *(_QWORD *)(qword_6020A8 + 24LL * v3 + 24) )
  {
    v1 = qword_6020A8;
    *(_QWORD *)(v1 + 24LL * v3 + 32) = realloc(*(void **)(qword_6020A8 + 24LL * v3 + 32), (128 - v2 % 128) % 128 + v2);
    *(_QWORD *)(qword_6020A8 + 24LL * v3 + 24) = v2;
  }
  printf("Enter your note: ");
  sub_40085D(*(_QWORD *)(qword_6020A8 + 24LL * v3 + 32), v2);
  return puts("Done.");
}
// 6020A8: using guessed type __int64 qword_6020A8;

//----- (0000000000400F7D) ----------------------------------------------------
int sub_400F7D()
{
  int v1; // [rsp+Ch] [rbp-4h]

  if ( *(_QWORD *)(qword_6020A8 + 8) <= 0LL )
    return puts("No notes yet.");
  printf("Note number: ");
  v1 = sub_40094E();
  if ( v1 < 0 || (signed __int64)v1 >= *(_QWORD *)qword_6020A8 )
    return puts("Invalid number!");
  --*(_QWORD *)(qword_6020A8 + 8);
  *(_QWORD *)(qword_6020A8 + 24LL * v1 + 16) = 0LL;
  *(_QWORD *)(qword_6020A8 + 24LL * v1 + 24) = 0LL;
  free(*(void **)(qword_6020A8 + 24LL * v1 + 32));
  return puts("Done.");
}
// 6020A8: using guessed type __int64 qword_6020A8;

//----- (0000000000401087) ----------------------------------------------------
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  sub_4009FD();
  sub_400A49();
  while ( 1 )
  {
    switch ( sub_400998() )
    {
      case 1:
        sub_400B14();
        break;
      case 2:
        sub_400BC2();
        break;
      case 3:
        sub_400D87();
        break;
      case 4:
        sub_400F7D();
        break;
      case 5:
        puts("Bye");
        return 0LL;
      default:
        puts("Invalid!");
        break;
    }
  }
}

//----- (0000000000401120) ----------------------------------------------------
void __fastcall init(unsigned int a1, __int64 a2, __int64 a3)
{
  __int64 v3; // r13
  __int64 v4; // rbx
  signed __int64 v5; // rbp

  v3 = a3;
  v4 = 0LL;
  v5 = &off_601E18 - off_601E10;
  init_proc();
  if ( v5 )
  {
    do
      ((void (__fastcall *)(_QWORD, __int64, __int64))off_601E10[v4++])(a1, a2, v3);
    while ( v4 != v5 );
  }
}
// 601E10: using guessed type __int64 (__fastcall *off_601E10[2])();
// 601E18: using guessed type __int64 (__fastcall *off_601E18)();

//----- (0000000000401194) ----------------------------------------------------
void term_proc()
{
  ;
}

#error "There were 1 decompilation failure(s) on 20 function(s)"
