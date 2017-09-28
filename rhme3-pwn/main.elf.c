/* This file has been generated by the Hex-Rays decompiler.
   Copyright (c) 2007-2015 Hex-Rays <info@hex-rays.com>

   Detected compiler: GNU C++
*/

#include <defs.h>


//-------------------------------------------------------------------------
// Function declarations

int init_proc();
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
// int _gmon_start__(void); weak
signed int deregister_tm_clones();
int register_tm_clones();
signed int _do_global_dtors_aux();
int frame_dummy();
__pid_t __fastcall daemonize(const char *a1);
__int64 __fastcall background_process(const char *a1);
__int64 __fastcall serve_forever(uint16_t a1);
int __fastcall set_io(int a1);
__int64 __fastcall read_until_n(int a1, __int64 a2, char a3, unsigned int a4);
__int64 __fastcall read_until(int a1, __int64 a2, char a3);
__int64 seed();
__int64 __fastcall readline(__int64 a1, int a2);
__int64 menu();
__int64 edit_menu();
int __fastcall show_player_func(__int64 a1);
__int64 add_player();
__int64 delete_player();
__int64 select_player();
__int64 set_name();
__int64 set_attack();
__int64 set_defense();
__int64 set_speed();
__int64 set_precision();
int edit_player();
__int64 show_player();
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
__int64 players[]; // weak
// extern _UNKNOWN __gmon_start__; weak


//----- (0000000000400C20) ----------------------------------------------------
int init_proc()
{
  void *v0; // rax@1

  v0 = &__gmon_start__;
  if ( &__gmon_start__ )
    LODWORD(v0) = _gmon_start__();
  return (unsigned __int64)v0;
}
// 400EB0: using guessed type int _gmon_start__(void);

//----- (0000000000400EC0) ----------------------------------------------------
#error "400EC6: positive sp value has been found (funcsize=3)"

//----- (0000000000400EF0) ----------------------------------------------------
signed int deregister_tm_clones()
{
  return 7;
}

//----- (0000000000400F30) ----------------------------------------------------
int register_tm_clones()
{
  return 0;
}

//----- (0000000000400F70) ----------------------------------------------------
signed int _do_global_dtors_aux()
{
  signed int result; // eax@2

  if ( !completed_7585 )
  {
    result = deregister_tm_clones();
    completed_7585 = 1;
  }
  return result;
}
// 603168: using guessed type char completed_7585;

//----- (0000000000400F90) ----------------------------------------------------
int frame_dummy()
{
  return register_tm_clones();
}
// 400F90: could not find valid save-restore pair for rbp

//----- (0000000000400FB6) ----------------------------------------------------
__pid_t __fastcall daemonize(const char *a1)
{
  __pid_t result; // eax@1
  __pid_t v2; // [sp+18h] [bp-8h]@2

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
__int64 __fastcall background_process(const char *a1)
{
  struct passwd *v2; // [sp+18h] [bp-118h]@1
  char s; // [sp+20h] [bp-110h]@3
  __int64 v4; // [sp+128h] [bp-8h]@1

  v4 = *MK_FP(__FS__, 40LL);
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
  return *MK_FP(__FS__, 40LL) ^ v4;
}

//----- (000000000040111F) ----------------------------------------------------
__int64 __fastcall serve_forever(uint16_t a1)
{
  int optval; // [sp+10h] [bp-30h]@1
  int fd; // [sp+14h] [bp-2Ch]@1
  int v4; // [sp+18h] [bp-28h]@1
  int v5; // [sp+1Ch] [bp-24h]@9
  __int16 s; // [sp+20h] [bp-20h]@5
  uint16_t v7; // [sp+22h] [bp-1Eh]@5
  uint32_t v8; // [sp+24h] [bp-1Ch]@5
  __int64 v9; // [sp+38h] [bp-8h]@1

  v9 = *MK_FP(__FS__, 40LL);
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
  unsigned int v5; // [sp+Ch] [bp-24h]@1
  char v6; // [sp+18h] [bp-18h]@1
  unsigned int v7; // [sp+2Ch] [bp-4h]@1

  v5 = a4;
  v6 = a3;
  v7 = 0;
  do
  {
    if ( read(a1, (void *)((signed int)v7 + a2), 1uLL) <= 0 )
      exit(1);
    ++v7;
  }
  while ( v7 < v5 && *(_BYTE *)((signed int)v7 - 1LL + a2) != v6 );
  *(_BYTE *)((signed int)v7 - 1LL + a2) = 0;
  return v7;
}

//----- (00000000004013A0) ----------------------------------------------------
__int64 __fastcall read_until(int a1, __int64 a2, char a3)
{
  char v4; // [sp+8h] [bp-18h]@1
  unsigned int v5; // [sp+1Ch] [bp-4h]@1

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
__int64 seed()
{
  int buf; // [sp+8h] [bp-18h]@4
  int i; // [sp+Ch] [bp-14h]@3
  unsigned int seed; // [sp+10h] [bp-10h]@1
  int fd; // [sp+14h] [bp-Ch]@1
  __int64 v5; // [sp+18h] [bp-8h]@1

  v5 = *MK_FP(__FS__, 40LL);
  seed = 0;
  fd = open("/dev/urandom", 0);
  if ( fd < 0 )
    exit(1);
  for ( i = 0; i <= 8; ++i )
  {
    if ( read(fd, &buf, 4uLL) <= 3 )
      exit(1);
    seed ^= buf;
  }
  srandom(seed);
  return *MK_FP(__FS__, 40LL) ^ v5;
}

//----- (00000000004014C3) ----------------------------------------------------
__int64 __fastcall readline(__int64 a1, int a2)
{
  char buf; // [sp+13h] [bp-Dh]@2
  unsigned int i; // [sp+14h] [bp-Ch]@1
  __int64 v5; // [sp+18h] [bp-8h]@1

  v5 = *MK_FP(__FS__, 40LL);
  for ( i = 0; a2 - 1 > i; ++i )
  {
    read(0, &buf, 1uLL);
    if ( buf == 10 )
      break;
    *(_BYTE *)(i + a1) = buf;
  }
  *(_BYTE *)(i + a1) = 0;
  return *MK_FP(__FS__, 40LL) ^ v5;
}

//----- (000000000040154E) ----------------------------------------------------
__int64 menu()
{
  __int64 result; // rax@1
  __int64 v1; // rdx@1
  char nptr[4]; // [sp+10h] [bp-10h]@1
  __int64 v3; // [sp+18h] [bp-8h]@1

  v3 = *MK_FP(__FS__, 40LL);
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
  result = (unsigned int)atoi(nptr);
  v1 = *MK_FP(__FS__, 40LL) ^ v3;
  return result;
}

//----- (0000000000401679) ----------------------------------------------------
__int64 edit_menu()
{
  __int64 result; // rax@1
  __int64 v1; // rdx@1
  char nptr[4]; // [sp+10h] [bp-10h]@1
  __int64 v3; // [sp+18h] [bp-8h]@1

  v3 = *MK_FP(__FS__, 40LL);
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
  result = (unsigned int)atoi(nptr);
  v1 = *MK_FP(__FS__, 40LL) ^ v3;
  return result;
}

//----- (000000000040178B) ----------------------------------------------------
int __fastcall show_player_func(__int64 a1)
{
  printf("\tName: %s\n", *(_QWORD *)(a1 + 16));
  fflush(stdout);
  printf("\tA/D/S/P: %d,%d,%d,%d\n", *(_DWORD *)a1, *(_DWORD *)(a1 + 4), *(_DWORD *)(a1 + 8), *(_DWORD *)(a1 + 12));
  return fflush(stdout);
}

//----- (0000000000401801) ----------------------------------------------------
__int64 add_player()
{
  size_t v0; // rax@9
  unsigned int i; // [sp+4h] [bp-11Ch]@1
  void *s; // [sp+8h] [bp-118h]@7
  char src; // [sp+10h] [bp-110h]@9
  __int64 v5; // [sp+118h] [bp-8h]@1

  v5 = *MK_FP(__FS__, 40LL);
  for ( i = 0; i <= 0xA && players[(unsigned __int64)i]; ++i )
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
    s = malloc(0x18uLL);
    if ( s )
    {
      memset(s, 0, 0x18uLL);
      printf("Enter player name: ", 0LL);
      fflush(stdout);
      memset(&src, 0, 0x100uLL);
      readline((__int64)&src, 256);
      v0 = strlen(&src);
      *((_QWORD *)s + 2) = malloc(v0 + 1);
      if ( *((_QWORD *)s + 2) )
      {
        strcpy(*((char **)s + 2), &src);
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
        players[(unsigned __int64)i] = (__int64)s;
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
  return *MK_FP(__FS__, 40LL) ^ v5;
}
// 603180: using guessed type __int64 players[];

//----- (0000000000401B16) ----------------------------------------------------
__int64 delete_player()
{
  void *ptr; // ST08_8@4
  int v2; // [sp+4h] [bp-1Ch]@1
  char nptr; // [sp+10h] [bp-10h]@1
  __int64 v4; // [sp+18h] [bp-8h]@1

  v4 = *MK_FP(__FS__, 40LL);
  printf("Enter index: ");
  fflush(stdout);
  readline((__int64)&nptr, 4);
  v2 = atoi(&nptr);
  if ( (unsigned int)v2 <= 0xA && players[(unsigned __int64)(unsigned int)v2] )
  {
    ptr = (void *)players[(unsigned __int64)(unsigned int)v2];
    players[(unsigned __int64)(unsigned int)v2] = 0LL;
    free(*((void **)ptr + 2));
    free(ptr);
    puts("She's gone!");
    fflush(stdout);
  }
  else
  {
    puts("Invalid index");
    fflush(stdout);
  }
  return *MK_FP(__FS__, 40LL) ^ v4;
}
// 603180: using guessed type __int64 players[];

//----- (0000000000401C05) ----------------------------------------------------
__int64 select_player()
{
  int v1; // [sp+Ch] [bp-14h]@1
  char nptr; // [sp+10h] [bp-10h]@1
  __int64 v3; // [sp+18h] [bp-8h]@1

  v3 = *MK_FP(__FS__, 40LL);
  printf("Enter index: ");
  fflush(stdout);
  readline((__int64)&nptr, 4);
  v1 = atoi(&nptr);
  if ( (unsigned int)v1 <= 0xA && players[(unsigned __int64)(unsigned int)v1] )
  {
    selected = players[(unsigned __int64)(unsigned int)v1];
    puts("Player selected!");
    fflush(stdout);
    show_player_func(selected);
  }
  else
  {
    puts("Invalid index");
    fflush(stdout);
  }
  return *MK_FP(__FS__, 40LL) ^ v3;
}
// 603170: using guessed type __int64 selected;
// 603180: using guessed type __int64 players[];

//----- (0000000000401CDB) ----------------------------------------------------
__int64 set_name()
{
  size_t v0; // rbx@1
  size_t v1; // rax@2
  void *v3; // [sp+8h] [bp-128h]@2
  char s; // [sp+10h] [bp-120h]@1
  __int64 v5; // [sp+118h] [bp-18h]@1

  v5 = *MK_FP(__FS__, 40LL);
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
    return *MK_FP(__FS__, 40LL) ^ v5;
  }
  puts("Could not realloc :(");
  fflush(stdout);
  return *MK_FP(__FS__, 40LL) ^ v5;
}
// 603170: using guessed type __int64 selected;

//----- (0000000000401DF4) ----------------------------------------------------
__int64 set_attack()
{
  int *v0; // rbx@1
  int nptr; // [sp+0h] [bp-20h]@1
  __int64 v3; // [sp+8h] [bp-18h]@1

  v3 = *MK_FP(__FS__, 40LL);
  nptr = 0;
  printf("Enter attack points: ", *(_QWORD *)&nptr);
  fflush(stdout);
  readline((__int64)&nptr, 4);
  v0 = (int *)selected;
  *v0 = atoi((const char *)&nptr);
  return *MK_FP(__FS__, 40LL) ^ v3;
}
// 603170: using guessed type __int64 selected;

//----- (0000000000401E73) ----------------------------------------------------
__int64 set_defense()
{
  __int64 v0; // rbx@1
  int nptr; // [sp+0h] [bp-20h]@1
  __int64 v3; // [sp+8h] [bp-18h]@1

  v3 = *MK_FP(__FS__, 40LL);
  nptr = 0;
  printf("Enter defense points: ", *(_QWORD *)&nptr);
  fflush(stdout);
  readline((__int64)&nptr, 4);
  v0 = selected;
  *(_DWORD *)(v0 + 4) = atoi((const char *)&nptr);
  return *MK_FP(__FS__, 40LL) ^ v3;
}
// 603170: using guessed type __int64 selected;

//----- (0000000000401EF3) ----------------------------------------------------
__int64 set_speed()
{
  __int64 v0; // rbx@1
  int nptr; // [sp+0h] [bp-20h]@1
  __int64 v3; // [sp+8h] [bp-18h]@1

  v3 = *MK_FP(__FS__, 40LL);
  nptr = 0;
  printf("Enter speed: ", *(_QWORD *)&nptr);
  fflush(stdout);
  readline((__int64)&nptr, 4);
  v0 = selected;
  *(_DWORD *)(v0 + 8) = atoi((const char *)&nptr);
  return *MK_FP(__FS__, 40LL) ^ v3;
}
// 603170: using guessed type __int64 selected;

//----- (0000000000401F73) ----------------------------------------------------
__int64 set_precision()
{
  __int64 v0; // rbx@1
  int nptr; // [sp+0h] [bp-20h]@1
  __int64 v3; // [sp+8h] [bp-18h]@1

  v3 = *MK_FP(__FS__, 40LL);
  nptr = 0;
  printf("Enter precision: ", *(_QWORD *)&nptr);
  fflush(stdout);
  readline((__int64)&nptr, 4);
  v0 = selected;
  *(_DWORD *)(v0 + 12) = atoi((const char *)&nptr);
  return *MK_FP(__FS__, 40LL) ^ v3;
}
// 603170: using guessed type __int64 selected;

//----- (0000000000401FF3) ----------------------------------------------------
int edit_player()
{
  int result; // eax@1
  char v1; // [sp+Bh] [bp-5h]@1

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
__int64 show_player()
{
  __int64 v1; // [sp+8h] [bp-8h]@1

  v1 = *MK_FP(__FS__, 40LL);
  if ( selected )
  {
    show_player_func(selected);
  }
  else
  {
    puts("No player selected index");
    fflush(stdout);
  }
  return *MK_FP(__FS__, 40LL) ^ v1;
}
// 603170: using guessed type __int64 selected;

//----- (0000000000402117) ----------------------------------------------------
int show_team()
{
  __int64 v0; // rax@1
  unsigned int v1; // eax@3
  unsigned int v3; // [sp+8h] [bp-8h]@1
  unsigned int v4; // [sp+Ch] [bp-4h]@1

  puts("Your team: ");
  LODWORD(v0) = fflush(stdout);
  v3 = 0;
  v4 = 0;
  while ( v3 <= 0xA )
  {
    v0 = players[(unsigned __int64)v3];
    if ( v0 )
    {
      v1 = v4++;
      printf("Player %d\n", v1);
      fflush(stdout);
      LODWORD(v0) = show_player_func(players[(unsigned __int64)v3]);
    }
    ++v3;
  }
  return v0;
}
// 603180: using guessed type __int64 players[];

//----- (00000000004021A1) ----------------------------------------------------
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // ST08_4@1
  int v4; // ST0C_4@2
  bool v6; // [sp+7h] [bp-9h]@1

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
  __int64 v3; // r13@1
  signed __int64 v4; // rbp@1
  __int64 v5; // rbx@2

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
