/* This file has been generated by the Hex-Rays decompiler.
   Copyright (c) 2007-2017 Hex-Rays <info@hex-rays.com>

   Detected compiler: GNU C++
*/

#include <defs.h>


//-------------------------------------------------------------------------
// Function declarations

void *init_proc();
// void free(void *ptr);
// void srandom(unsigned int seed);
// char *strcpy(char *dest, const char *src);
// int puts(const char *s);
// int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen);
// size_t strlen(const char *s);
// int chdir(const char *path);
// void setbuf(FILE *stream, char *buf);
// uint16_t htons(uint16_t hostshort);
// int dup2(int fd, int fd2);
// int printf(const char *format, ...);
// uint32_t htonl(uint32_t hostlong);
// void *memset(void *s, int c, size_t n);
// int close(int fd);
// int setgroups(size_t n, const __gid_t *groups);
// __pid_t setsid(void);
// ssize_t read(int fd, void *buf, size_t nbytes);
// __sighandler_t signal(int sig, __sighandler_t handler);
// struct passwd *getpwnam(const char *name);
// __mode_t umask(__mode_t mask);
// void *malloc(size_t size);
// int fflush(FILE *stream);
// int listen(int fd, int n);
// void *realloc(void *ptr, size_t size);
// int setvbuf(FILE *stream, char *buf, int modes, size_t n);
// int bind(int fd, const struct sockaddr *addr, socklen_t len);
// int setgid(__gid_t gid);
// int open(const char *file, int oflag, ...);
// int accept(int fd, struct sockaddr *addr, socklen_t *addr_len);
// int atoi(const char *nptr);
// int sprintf(char *s, const char *format, ...);
// __pid_t getppid(void);
// void __noreturn exit(int status);
// int setuid(__uid_t uid);
// __pid_t fork(void);
// int socket(int domain, int type, int protocol);
// __int64 _gmon_start__(void); weak
signed __int64 deregister_tm_clones();
__int64 register_tm_clones();
signed __int64 _do_global_dtors_aux();
__int64 frame_dummy();
__pid_t __fastcall daemonize(const char *a1);
unsigned __int64 __fastcall background_process(const char *a1);
__int64 __fastcall serve_forever(uint16_t a1);
int __fastcall set_io(int a1);
__int64 __fastcall read_until_n(int a1, __int64 a2, char a3, unsigned int a4);
__int64 __fastcall read_until(int a1, __int64 a2, char a3);
unsigned __int64 seed();
unsigned __int64 __fastcall readline(__int64 a1, int a2);
__int64 menu();
__int64 edit_menu();
int __fastcall show_player_func(__int64 a1);
unsigned __int64 add_player();
unsigned __int64 delete_player();
unsigned __int64 select_player();
unsigned __int64 set_name();
unsigned __int64 set_attack();
unsigned __int64 set_defense();
unsigned __int64 set_speed();
unsigned __int64 set_precision();
int edit_player();
unsigned __int64 show_player();
int show_team();
int __cdecl main(int argc, const char **argv, const char **envp);
void __fastcall _libc_csu_init(unsigned int a1, __int64 a2, __int64 a3);
void term_proc();

//-------------------------------------------------------------------------
// Data declarations

__int64 (__fastcall *_frame_dummy_init_array_entry[2])() = { &frame_dummy, &_do_global_dtors_aux }; // weak
__int64 (__fastcall *_do_global_dtors_aux_fini_array_entry)() = &_do_global_dtors_aux; // weak
FILE *stdout; // idb
char completed_7585; // weak
__int64 selected; // weak
__int64 players[11]; // idb
// extern _UNKNOWN __gmon_start__; weak


//----- (0000000000400C20) ----------------------------------------------------
void *init_proc()
{
  void *result; // rax

  result = &__gmon_start__;
  if ( &__gmon_start__ )
    result = (void *)_gmon_start__();
  return result;
}
// 400EB0: using guessed type __int64 _gmon_start__(void);

//----- (0000000000400EC0) ----------------------------------------------------
#error "400EC6: positive sp value has been found (funcsize=3)"

//----- (0000000000400EF0) ----------------------------------------------------
signed __int64 deregister_tm_clones()
{
  return 7LL;
}

//----- (0000000000400F30) ----------------------------------------------------
__int64 register_tm_clones()
{
  return 0LL;
}

//----- (0000000000400F70) ----------------------------------------------------
signed __int64 _do_global_dtors_aux()
{
  signed __int64 result; // rax

  if ( !completed_7585 )
  {
    result = deregister_tm_clones();
    completed_7585 = 1;
  }
  return result;
}
// 603168: using guessed type char completed_7585;

//----- (0000000000400F90) ----------------------------------------------------
__int64 frame_dummy()
{
  return register_tm_clones();
}
// 400F90: could not find valid save-restore pair for rbp

//----- (0000000000400FB6) ----------------------------------------------------
__pid_t __fastcall daemonize(const char *a1)
{
  __pid_t result; // eax
  __pid_t v2; // [rsp+18h] [rbp-8h]

  result = getppid();
  if ( result != 1 )
  {
    v2 = fork();
    if ( v2 < 0 )
      exit(1);
    if ( v2 > 0 )
      exit(0);
    if ( setsid() < 0 )
      exit(1);
    umask(0);
    result = chdir(a1);
    if ( result < 0 )
      exit(1);
  }
  return result;
}

//----- (0000000000401033) ----------------------------------------------------
unsigned __int64 __fastcall background_process(const char *a1)
{
  struct passwd *v2; // [rsp+18h] [rbp-118h]
  char s; // [rsp+20h] [rbp-110h]
  unsigned __int64 v4; // [rsp+128h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  v2 = getpwnam(a1);
  if ( !v2 )
    exit(1);
  sprintf(&s, "/opt/riscure/%s", a1);
  daemonize(&s);
  if ( setgroups(0LL, 0LL) < 0 )
    exit(1);
  if ( setgid(v2->pw_gid) < 0 )
    exit(1);
  if ( setuid(v2->pw_uid) < 0 )
    exit(1);
  return __readfsqword(0x28u) ^ v4;
}

//----- (000000000040111F) ----------------------------------------------------
__int64 __fastcall serve_forever(uint16_t a1)
{
  int optval; // [rsp+10h] [rbp-30h]
  int fd; // [rsp+14h] [rbp-2Ch]
  int v4; // [rsp+18h] [rbp-28h]
  __pid_t v5; // [rsp+1Ch] [rbp-24h]
  __int16 s; // [rsp+20h] [rbp-20h]
  uint16_t v7; // [rsp+22h] [rbp-1Eh]
  uint32_t v8; // [rsp+24h] [rbp-1Ch]
  unsigned __int64 v9; // [rsp+38h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  v4 = 0;
  optval = 1;
  signal(17, (__sighandler_t)1);
  fd = socket(2, 1, 0);
  if ( fd < 0 )
    exit(1);
  if ( setsockopt(fd, 1, 2, &optval, 4u) < 0 )
    exit(1);
  memset(&s, 48, 0x10uLL);
  s = 2;
  v8 = htonl(0);
  v7 = htons(a1);
  if ( bind(fd, (const struct sockaddr *)&s, 0x10u) < 0 )
    exit(1);
  if ( listen(fd, 20) < 0 )
    exit(1);
  while ( 1 )
  {
    v4 = accept(fd, 0LL, 0LL);
    v5 = fork();
    if ( v5 < 0 )
      exit(1);
    if ( !v5 )
      break;
    close(v4);
  }
  close(fd);
  return (unsigned int)v4;
}

//----- (0000000000401294) ----------------------------------------------------
int __fastcall set_io(int a1)
{
  if ( dup2(a1, 0) < 0 )
    exit(1);
  if ( dup2(a1, 1) < 0 )
    exit(1);
  if ( dup2(a1, 2) < 0 )
    exit(1);
  return setvbuf(stdout, 0LL, 2, 0LL);
}

//----- (0000000000401317) ----------------------------------------------------
__int64 __fastcall read_until_n(int a1, __int64 a2, char a3, unsigned int a4)
{
  unsigned int v5; // [rsp+Ch] [rbp-24h]
  char v6; // [rsp+18h] [rbp-18h]
  signed int v7; // [rsp+2Ch] [rbp-4h]

  v5 = a4;
  v6 = a3;
  v7 = 0;
  do
  {
    if ( read(a1, (void *)(v7 + a2), 1uLL) <= 0 )
      exit(1);
    ++v7;
  }
  while ( v7 < v5 && *(_BYTE *)(v7 - 1LL + a2) != v6 );
  *(_BYTE *)(v7 - 1LL + a2) = 0;
  return (unsigned int)v7;
}

//----- (00000000004013A0) ----------------------------------------------------
__int64 __fastcall read_until(int a1, __int64 a2, char a3)
{
  char v4; // [rsp+8h] [rbp-18h]
  unsigned int v5; // [rsp+1Ch] [rbp-4h]

  v4 = a3;
  v5 = 0;
  do
  {
    if ( read(a1, (void *)((signed int)v5 + a2), 1uLL) <= 0 )
      exit(1);
    ++v5;
  }
  while ( *(_BYTE *)((signed int)v5 - 1LL + a2) != v4 );
  *(_BYTE *)((signed int)v5 - 1LL + a2) = 0;
  return v5;
}

//----- (000000000040141E) ----------------------------------------------------
unsigned __int64 seed()
{
  int buf; // [rsp+8h] [rbp-18h]
  int i; // [rsp+Ch] [rbp-14h]
  unsigned int seeda; // [rsp+10h] [rbp-10h]
  int fd; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  seeda = 0;
  fd = open("/dev/urandom", 0);
  if ( fd < 0 )
    exit(1);
  for ( i = 0; i <= 8; ++i )
  {
    if ( read(fd, &buf, 4uLL) <= 3 )
      exit(1);
    seeda ^= buf;
  }
  srandom(seeda);
  return __readfsqword(0x28u) ^ v5;
}

//----- (00000000004014C3) ----------------------------------------------------
unsigned __int64 __fastcall readline(__int64 a1, int a2)
{
  char buf; // [rsp+13h] [rbp-Dh]
  unsigned int i; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; a2 - 1 > i; ++i )
  {
    read(0, &buf, 1uLL);
    if ( buf == 10 )
      break;
    *(_BYTE *)(i + a1) = buf;
  }
  *(_BYTE *)(i + a1) = 0;
  return __readfsqword(0x28u) ^ v5;
}

//----- (000000000040154E) ----------------------------------------------------
__int64 menu()
{
  char nptr[4]; // [rsp+10h] [rbp-10h]
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  *(_DWORD *)nptr = 0;
  puts("0.- Exit");
  fflush(stdout);
  puts("1.- Add player");
  fflush(stdout);
  puts("2.- Remove player");
  fflush(stdout);
  puts("3.- Select player");
  fflush(stdout);
  puts("4.- Edit player");
  fflush(stdout);
  puts("5.- Show player");
  fflush(stdout);
  puts("6.- Show team");
  fflush(stdout);
  printf("Your choice: ");
  fflush(stdout);
  readline((__int64)nptr, 4);
  return (unsigned int)atoi(nptr);
}

//----- (0000000000401679) ----------------------------------------------------
__int64 edit_menu()
{
  char nptr[4]; // [rsp+10h] [rbp-10h]
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  *(_DWORD *)nptr = 0;
  puts("0.- Go back");
  fflush(stdout);
  puts("1.- Edit name");
  fflush(stdout);
  puts("2.- Set attack points");
  fflush(stdout);
  puts("3.- Set defense points");
  fflush(stdout);
  puts("4.- Set speed");
  fflush(stdout);
  puts("5.- Set precision");
  fflush(stdout);
  printf("Your choice: ");
  fflush(stdout);
  readline((__int64)nptr, 4);
  return (unsigned int)atoi(nptr);
}

//----- (000000000040178B) ----------------------------------------------------
int __fastcall show_player_func(__int64 a1)
{
  printf("\tName: %s\n", *(_QWORD *)(a1 + 16));
  fflush(stdout);
  printf(
    "\tA/D/S/P: %d,%d,%d,%d\n",
    *(unsigned int *)a1,
    *(unsigned int *)(a1 + 4),
    *(unsigned int *)(a1 + 8),
    *(unsigned int *)(a1 + 12));
  return fflush(stdout);
}

//----- (0000000000401801) ----------------------------------------------------
unsigned __int64 add_player()
{
  size_t v0; // rax
  unsigned int i; // [rsp+4h] [rbp-11Ch]
  char **s; // [rsp+8h] [rbp-118h]
  char src; // [rsp+10h] [rbp-110h]
  unsigned __int64 v5; // [rsp+118h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; i <= 0xA && players[i]; ++i )
    ;
  if ( i == 11 )
  {
    puts("Maximum number of players reached!");
    fflush(stdout);
  }
  else
  {
    printf("Found free slot: %d\n", i);
    fflush(stdout);
    s = (char **)malloc(0x18uLL);
    if ( s )
    {
      memset(s, 0, 0x18uLL);
      printf("Enter player name: ", 0LL);
      fflush(stdout);
      memset(&src, 0, 0x100uLL);
      readline((__int64)&src, 256);
      v0 = strlen(&src);
      s[2] = (char *)malloc(v0 + 1);
      if ( s[2] )
      {
        strcpy(s[2], &src);
        printf("Enter attack points: ", &src);
        fflush(stdout);
        readline((__int64)&src, 4);
        *(_DWORD *)s = atoi(&src);
        printf("Enter defense points: ", 4LL);
        fflush(stdout);
        readline((__int64)&src, 4);
        *((_DWORD *)s + 1) = atoi(&src);
        printf("Enter speed: ", 4LL);
        fflush(stdout);
        readline((__int64)&src, 4);
        *((_DWORD *)s + 2) = atoi(&src);
        printf("Enter precision: ", 4LL);
        fflush(stdout);
        readline((__int64)&src, 4);
        *((_DWORD *)s + 3) = atoi(&src);
        players[i] = (__int64)s;
      }
      else
      {
        printf("Could not allocate!", 256LL);
        fflush(stdout);
      }
    }
    else
    {
      puts("Could not allocate");
      fflush(stdout);
    }
  }
  return __readfsqword(0x28u) ^ v5;
}

//----- (0000000000401B16) ----------------------------------------------------
unsigned __int64 delete_player()
{
  void **ptr; // ST08_8
  unsigned int v2; // [rsp+4h] [rbp-1Ch]
  char nptr; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("Enter index: ");
  fflush(stdout);
  readline((__int64)&nptr, 4);
  v2 = atoi(&nptr);
  if ( v2 <= 0xA && players[v2] )
  {
    ptr = (void **)players[v2];
    players[v2] = 0LL;
    free(ptr[2]);
    free(ptr);
    puts("She's gone!");
    fflush(stdout);
  }
  else
  {
    puts("Invalid index");
    fflush(stdout);
  }
  return __readfsqword(0x28u) ^ v4;
}

//----- (0000000000401C05) ----------------------------------------------------
unsigned __int64 select_player()
{
  unsigned int v1; // [rsp+Ch] [rbp-14h]
  char nptr; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Enter index: ");
  fflush(stdout);
  readline((__int64)&nptr, 4);
  v1 = atoi(&nptr);
  if ( v1 <= 0xA && players[v1] )
  {
    selected = players[v1];
    puts("Player selected!");
    fflush(stdout);
    show_player_func(selected);
  }
  else
  {
    puts("Invalid index");
    fflush(stdout);
  }
  return __readfsqword(0x28u) ^ v3;
}
// 603170: using guessed type __int64 selected;

//----- (0000000000401CDB) ----------------------------------------------------
unsigned __int64 set_name()
{
  size_t v0; // rbx
  size_t v1; // rax
  void *v3; // [rsp+8h] [rbp-128h]
  char s; // [rsp+10h] [rbp-120h]
  unsigned __int64 v5; // [rsp+118h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  printf("Enter new name: ");
  fflush(stdout);
  readline((__int64)&s, 256);
  v0 = strlen(&s);
  if ( v0 <= strlen(*(const char **)(selected + 16)) )
    goto LABEL_5;
  v1 = strlen(&s);
  v3 = realloc(*(void **)(selected + 16), v1 + 1);
  if ( v3 )
  {
    *(_QWORD *)(selected + 16) = v3;
LABEL_5:
    strcpy(*(char **)(selected + 16), &s);
    return __readfsqword(0x28u) ^ v5;
  }
  puts("Could not realloc :(");
  fflush(stdout);
  return __readfsqword(0x28u) ^ v5;
}
// 603170: using guessed type __int64 selected;

//----- (0000000000401DF4) ----------------------------------------------------
unsigned __int64 set_attack()
{
  int *v0; // rbx
  __int64 nptr; // [rsp+0h] [rbp-20h]
  unsigned __int64 v3; // [rsp+8h] [rbp-18h]

  v3 = __readfsqword(0x28u);
  LODWORD(nptr) = 0;
  printf("Enter attack points: ", nptr);
  fflush(stdout);
  readline((__int64)&nptr, 4);
  v0 = (int *)selected;
  *v0 = atoi((const char *)&nptr);
  return __readfsqword(0x28u) ^ v3;
}
// 603170: using guessed type __int64 selected;

//----- (0000000000401E73) ----------------------------------------------------
unsigned __int64 set_defense()
{
  __int64 v0; // rbx
  __int64 nptr; // [rsp+0h] [rbp-20h]
  unsigned __int64 v3; // [rsp+8h] [rbp-18h]

  v3 = __readfsqword(0x28u);
  LODWORD(nptr) = 0;
  printf("Enter defense points: ", nptr);
  fflush(stdout);
  readline((__int64)&nptr, 4);
  v0 = selected;
  *(_DWORD *)(v0 + 4) = atoi((const char *)&nptr);
  return __readfsqword(0x28u) ^ v3;
}
// 603170: using guessed type __int64 selected;

//----- (0000000000401EF3) ----------------------------------------------------
unsigned __int64 set_speed()
{
  __int64 v0; // rbx
  __int64 nptr; // [rsp+0h] [rbp-20h]
  unsigned __int64 v3; // [rsp+8h] [rbp-18h]

  v3 = __readfsqword(0x28u);
  LODWORD(nptr) = 0;
  printf("Enter speed: ", nptr);
  fflush(stdout);
  readline((__int64)&nptr, 4);
  v0 = selected;
  *(_DWORD *)(v0 + 8) = atoi((const char *)&nptr);
  return __readfsqword(0x28u) ^ v3;
}
// 603170: using guessed type __int64 selected;

//----- (0000000000401F73) ----------------------------------------------------
unsigned __int64 set_precision()
{
  __int64 v0; // rbx
  __int64 nptr; // [rsp+0h] [rbp-20h]
  unsigned __int64 v3; // [rsp+8h] [rbp-18h]

  v3 = __readfsqword(0x28u);
  LODWORD(nptr) = 0;
  printf("Enter precision: ", nptr);
  fflush(stdout);
  readline((__int64)&nptr, 4);
  v0 = selected;
  *(_DWORD *)(v0 + 12) = atoi((const char *)&nptr);
  return __readfsqword(0x28u) ^ v3;
}
// 603170: using guessed type __int64 selected;

//----- (0000000000401FF3) ----------------------------------------------------
int edit_player()
{
  int result; // eax
  char v1; // [rsp+Bh] [rbp-5h]

  v1 = 0;
  result = selected;
  if ( selected )
  {
    while ( !v1 )
    {
      result = edit_menu();
      switch ( result )
      {
        case 0:
          v1 = 1;
          break;
        case 1:
          result = set_name();
          break;
        case 2:
          result = set_attack();
          break;
        case 3:
          result = set_defense();
          break;
        case 4:
          result = set_speed();
          break;
        case 5:
          result = set_precision();
          break;
        default:
          puts("Invalid choice");
          result = fflush(stdout);
          break;
      }
    }
  }
  else
  {
    puts("No player selected!!");
    result = fflush(stdout);
  }
  return result;
}
// 603170: using guessed type __int64 selected;

//----- (00000000004020B4) ----------------------------------------------------
unsigned __int64 show_player()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  if ( selected )
  {
    show_player_func(selected);
  }
  else
  {
    puts("No player selected index");
    fflush(stdout);
  }
  return __readfsqword(0x28u) ^ v1;
}
// 603170: using guessed type __int64 selected;

//----- (0000000000402117) ----------------------------------------------------
int show_team()
{
  __int64 v0; // rax
  unsigned int v1; // eax
  unsigned int v3; // [rsp+8h] [rbp-8h]
  unsigned int v4; // [rsp+Ch] [rbp-4h]

  puts("Your team: ");
  LODWORD(v0) = fflush(stdout);
  v3 = 0;
  v4 = 0;
  while ( v3 <= 0xA )
  {
    v0 = players[v3];
    if ( v0 )
    {
      v1 = v4++;
      printf("Player %d\n", v1);
      fflush(stdout);
      LODWORD(v0) = show_player_func(players[v3]);
    }
    ++v3;
  }
  return v0;
}

//----- (00000000004021A1) ----------------------------------------------------
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // ST08_4
  int v4; // ST0C_4
  bool v6; // [rsp+7h] [rbp-9h]

  v6 = 0;
  background_process("pwn");
  v3 = serve_forever(0x539u);
  set_io(v3);
  setbuf(stdout, 0LL);
  puts("Welcome to your TeamManager (TM)!");
  fflush(stdout);
  while ( !v6 )
  {
    v4 = menu();
    v6 = v4 == 0;
    switch ( v4 )
    {
      case 0:
        v6 = 1;
        break;
      case 1:
        add_player();
        break;
      case 2:
        delete_player();
        break;
      case 3:
        select_player();
        break;
      case 4:
        edit_player();
        break;
      case 5:
        show_player();
        break;
      case 6:
        show_team();
        break;
      default:
        puts("Invalid option!!");
        fflush(stdout);
        break;
    }
  }
  puts("Sayonara!");
  fflush(stdout);
  return 0;
}

//----- (00000000004022C0) ----------------------------------------------------
void __fastcall _libc_csu_init(unsigned int a1, __int64 a2, __int64 a3)
{
  __int64 v3; // r13
  signed __int64 v4; // rbp
  __int64 v5; // rbx

  v3 = a3;
  v4 = &_do_global_dtors_aux_fini_array_entry - _frame_dummy_init_array_entry;
  init_proc();
  if ( v4 )
  {
    v5 = 0LL;
    do
      ((void (__fastcall *)(_QWORD, __int64, __int64))_frame_dummy_init_array_entry[v5++])(a1, a2, v3);
    while ( v5 != v4 );
  }
}
// 602E10: using guessed type __int64 (__fastcall *_frame_dummy_init_array_entry[2])();
// 602E18: using guessed type __int64 (__fastcall *_do_global_dtors_aux_fini_array_entry)();

//----- (0000000000402334) ----------------------------------------------------
void term_proc()
{
  ;
}

#error "There were 1 decompilation failure(s) on 31 function(s)"