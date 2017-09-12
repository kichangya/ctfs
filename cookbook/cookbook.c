/* This file has been generated by the Hex-Rays decompiler.
   Copyright (c) 2007-2015 Hex-Rays <info@hex-rays.com>

   Detected compiler: GNU C++
*/

#include <defs.h>


//-------------------------------------------------------------------------
// Function declarations

void *init_proc();
// int strcmp(const char *s1, const char *s2);
// int printf(const char *format, ...);
// size_t strcspn(const char *s, const char *reject);
// void free(void *ptr);
// void *memcpy(void *dest, const void *src, size_t n);
// char *fgets(char *s, int n, FILE *stream);
// unsigned int alarm(unsigned int seconds);
// void *malloc(size_t size);
// int puts(const char *s);
// int __gmon_start__(void); weak
// unsigned __int32 strtoul(const char *nptr, char **endptr, int base);
// int setvbuf(FILE *stream, char *buf, int modes, size_t n);
// int atoi(const char *nptr);
// void *calloc(size_t nmemb, size_t size);
void sub_8048630();
signed int sub_8048640();
signed int sub_80486B0();
int sub_80486D0();
void __cdecl free_list(int *a1);
_DWORD *__cdecl list_add(_DWORD *a1, int a2);
void __cdecl remove_at(int *a1, unsigned int a2);
int __cdecl nth_item(int *a1, unsigned int a2);
signed int __cdecl list_length(int *a1);
int main_menu();
void remove_cookbook_name();
int give_cookbook_name();
char *your_name();
int add_ingredient();
int create_recipe();
int __cdecl print_recipe(int a1);
unsigned int recipe_book();
signed int __cdecl contains(int *a1, const char *a2);
void __cdecl exterminate_ingredient(char *s2);
int __cdecl calc_total_cost(int a1);
int __cdecl calc_total_calories(int a1);
void free_structures();
int __cdecl ingredient_idx(char *s2); // idb
int __cdecl recipe_idx(char *s2); // idb
int __cdecl find_ingredient(char *s2); // idb
_DWORD *__cdecl alloc_ingredient(int a1, int a2, void *src, size_t n);
_DWORD *init_ingredients();
int init_recipes();
int __cdecl print_ingredient(int a1);
int list_ingredients();
int initialize();
int print_banner();
int print_bye();
int __cdecl main(int a1, char **a2);
void init(void); // idb
void term_proc();

//-------------------------------------------------------------------------
// Data declarations

int (*off_804CF08[2])() = { &sub_80486D0, &sub_80486B0 }; // weak
int (*off_804CF0C)() = &sub_80486B0; // weak
char *off_804D054 = "main dish"; // weak
char *off_804D058 = "side dish"; // weak
char *off_804D05C = "drink"; // weak
char *off_804D064 = "drink"; // weak
FILE *stdin; // idb
FILE *stdout; // idb
char byte_804D088; // weak
int RECIPE_LIST; // weak
_UNKNOWN unk_804D090; // weak
int INGREDIENT_LIST; // weak
_UNKNOWN unk_804D098; // weak
void *CURRENT_INGREDIENT; // idb
void *CURRENT_RECIPE; // idb
char *ptr; // idb
char *dword_804D0AC; // idb
// extern _UNKNOWN _gmon_start__; weak


//----- (080484CC) --------------------------------------------------------
void *init_proc()
{
  void *result; // eax@1

  result = &_gmon_start__;
  if ( &_gmon_start__ )
    result = (void *)__gmon_start__();
  return result;
}
// 80485A0: using guessed type int __gmon_start__(void);

//----- (08048600) --------------------------------------------------------
#error "8048603: positive sp value has been found (funcsize=2)"

//----- (08048630) --------------------------------------------------------
void sub_8048630()
{
  ;
}

//----- (08048640) --------------------------------------------------------
signed int sub_8048640()
{
  return 3;
}
// 8048640: could not find valid save-restore pair for ebp

//----- (080486B0) --------------------------------------------------------
signed int sub_80486B0()
{
  signed int result; // eax@2

  if ( !byte_804D088 )
  {
    result = sub_8048640();
    byte_804D088 = 1;
  }
  return result;
}
// 80486B0: could not find valid save-restore pair for ebp
// 804D088: using guessed type char byte_804D088;

//----- (080486D0) --------------------------------------------------------
int sub_80486D0()
{
  return 0;
}
// 80486D0: could not find valid save-restore pair for ebp

//----- (080486FB) --------------------------------------------------------
void __cdecl free_list(int *a1)
{
  signed int i; // [sp+Ch] [bp-Ch]@1

  for ( i = list_length(a1); i; i = list_length(a1) )
    remove_at(a1, i - 1);
  free((void *)*a1);
}

//----- (08048754) --------------------------------------------------------
// alloc 8 bytes (ptr to node, ptr to next).
_DWORD *__cdecl list_add(_DWORD *a1, int a2)
{
  _DWORD *result; // eax@2
  int head; // [sp+8h] [bp-10h]@1
  _DWORD *v4; // [sp+Ch] [bp-Ch]@1

  head = *a1;
  v4 = calloc(1u, 8u);
  *v4 = a2;
  v4[1] = 0;
  if ( head )
  {
    while ( *(_DWORD *)(head + 4) )
      head = *(_DWORD *)(head + 4);
    result = (_DWORD *)head;
    *(_DWORD *)(head + 4) = v4;
  }
  else
  {
    result = a1;
    *a1 = v4;
  }
  return result;
}

//----- (080487B5) --------------------------------------------------------
void __cdecl remove_at(int *a1, unsigned int a2)
{
  _DWORD *v2; // ST1C_4@10
  signed int v3; // [sp+0h] [bp-18h]@1
  void *ptr; // [sp+4h] [bp-14h]@1
  unsigned int v5; // [sp+8h] [bp-10h]@1

  v3 = 1;
  v5 = list_length(a1);
  ptr = (void *)*a1;
  if ( v5 )
  {
    if ( a2 )
    {
      if ( v5 > a2 )
      {
        while ( v3 != a2 )
        {
          ptr = (void *)*((_DWORD *)ptr + 1);
          ++v3;
        }
        v2 = (_DWORD *)*((_DWORD *)ptr + 1);
        *((_DWORD *)ptr + 1) = v2[1];
        free((void *)*v2);
        free(v2);
        if ( list_length(a1) == v3 )
          *((_DWORD *)ptr + 1) = 0;
      }
    }
    else if ( v5 == 1 )
    {
      free(*(void **)ptr);
      free(ptr);
      *a1 = 0;
    }
    else
    {
      *a1 = *((_DWORD *)ptr + 1);
      free(*(void **)ptr);
      free(ptr);
    }
  }
}

//----- (080488C2) --------------------------------------------------------
int __cdecl nth_item(int *a1, unsigned int a2)
{
  int result; // eax@2
  int v3; // [sp+8h] [bp-10h]@3
  int v4; // [sp+Ch] [bp-Ch]@3

  if ( list_length(a1) > a2 )
  {
    v3 = 0;
    v4 = *a1;
    while ( v3 != a2 )
    {
      v4 = *(_DWORD *)(v4 + 4);
      ++v3;
    }
    result = *(_DWORD *)v4;
  }
  else
  {
    result = 0;
  }
  return result;
}

//----- (0804890F) --------------------------------------------------------
signed int __cdecl list_length(int *a1)
{
  signed int result; // eax@2
  signed int v2; // [sp+8h] [bp-8h]@1
  int v3; // [sp+Ch] [bp-4h]@1

  v2 = 1;
  v3 = *a1;
  if ( *a1 )
  {
    while ( *(_DWORD *)(v3 + 4) )
    {
      v3 = *(_DWORD *)(v3 + 4);
      ++v2;
    }
    result = v2;
  }
  else
  {
    result = 0;
  }
  return result;
}

//----- (0804894D) --------------------------------------------------------
int main_menu()
{
  char *s2; // ST1C_4@10
  char v2; // [sp+A2h] [bp-16h]@2
  int v3; // [sp+ACh] [bp-Ch]@1

  v3 = *MK_FP(__GS__, 20);
  while ( 1 )
  {
    puts("====================");
    puts("[l]ist ingredients");
    puts("[r]ecipe book");
    puts("[a]dd ingredient");
    puts("[c]reate recipe");
    puts("[e]xterminate ingredient");
    puts("[d]elete recipe");
    puts("[g]ive your cookbook a name!");
    puts("[R]emove cookbook name");
    puts("[q]uit");
    fgets(&v2, 10, stdin);
    switch ( v2 )
    {
      case 108:
        list_ingredients();
        break;
      case 114:
        recipe_book();
        break;
      case 97:
        add_ingredient();
        break;
      case 99:
        create_recipe();
        break;
      case 103:
        give_cookbook_name();
        break;
      case 82:
        remove_cookbook_name();
        break;
      case 113:
        puts("goodbye, thanks for cooking with us!");
        return *MK_FP(__GS__, 20) ^ v3;
      case 101:
        s2 = (char *)calloc(0x80u, 1u);
        printf("which ingredient to exterminate? ");
        fgets(s2, 128, stdin);
        s2[strcspn(s2, "\n")] = 0;
        exterminate_ingredient(s2);
        free(s2);
        break;
      default:
        puts("UNKNOWN DIRECTIVE");
        break;
    }
  }
}

//----- (08048B4E) --------------------------------------------------------
void remove_cookbook_name()
{
  free(ptr);
}

//----- (08048B68) --------------------------------------------------------
int give_cookbook_name()
{
  unsigned __int32 size; // ST18_4@1
  char s; // [sp+Ch] [bp-4Ch]@1
  int v3; // [sp+4Ch] [bp-Ch]@1

  v3 = *MK_FP(__GS__, 20);
  printf("how long is the name of your cookbook? (hex because you're both a chef and a hacker!) : ");
  fgets(&s, 64, stdin);
  size = strtoul(&s, 0, 16);
  ptr = (char *)malloc(size);
  fgets(ptr, size, stdin);
  printf("the new name of the cookbook is %s\n", ptr);
  return *MK_FP(__GS__, 20) ^ v3;
}

//----- (08048C0F) --------------------------------------------------------
char *your_name()
{
  char *v0; // ebx@1
  char *result; // eax@1

  puts("what's your name?");
  dword_804D0AC = (char *)calloc(0x40u, 1u);
  fgets(dword_804D0AC, 64, stdin);
  v0 = dword_804D0AC;
  result = &v0[strcspn(dword_804D0AC, "\n")];
  *result = 0;
  return result;
}

//----- (08048C7B) --------------------------------------------------------
int add_ingredient()
{
  char *v1; // [sp+8h] [bp-30h]@9
  char *nptr; // [sp+Ch] [bp-2Ch]@13
  char *v3; // [sp+14h] [bp-24h]@17
  char v4[10]; // [sp+22h] [bp-16h]@2
  int v5; // [sp+2Ch] [bp-Ch]@1

  v5 = *MK_FP(__GS__, 20);
  while ( 1 )
  {
    puts("====================");
    puts("[l]ist current stats?");
    puts("[n]ew ingredient?");
    puts("[c]ontinue editing ingredient?");
    puts("[d]iscard current ingredient?");
    puts("[g]ive name to ingredient?");
    puts("[p]rice ingredient?");
    puts("[s]et calories?");
    puts("[q]uit (doesn't save)?");
    puts("[e]xport saving changes (doesn't quit)?");
    fgets(v4, 10, stdin);
    v4[strcspn(v4, "\n")] = 0;
    switch ( v4[0] )
    {
      case 108:
        if ( CURRENT_INGREDIENT )
          print_ingredient((int)CURRENT_INGREDIENT);
        else
          puts("can't print NULL!");
        break;
      case 110:
        CURRENT_INGREDIENT = malloc(0x90u);
        *((_DWORD *)CURRENT_INGREDIENT + 35) = CURRENT_INGREDIENT;
        break;
      case 99:
        puts("still editing this guy");
        break;
      case 100:
        free(CURRENT_INGREDIENT);
        CURRENT_INGREDIENT = 0;
        break;
      case 103:
        v1 = (char *)calloc(0x80u, 1u);
        if ( CURRENT_INGREDIENT )
        {
          fgets(v1, 128, stdin);
          v1[strcspn(v1, "\n")] = 0;
          memcpy((char *)CURRENT_INGREDIENT + 8, v1, 0x80u);
        }
        else
        {
          puts("can't do it on a null guy");
        }
        free(v1);
        break;
      case 112:
        nptr = (char *)calloc(0x80u, 1u);
        if ( CURRENT_INGREDIENT )
        {
          fgets(nptr, 128, stdin);
          nptr[strcspn(nptr, "\n")] = 0;
          *((_DWORD *)CURRENT_INGREDIENT + 1) = atoi(nptr);
        }
        else
        {
          puts("can't do it on a null guy");
        }
        free(nptr);
        break;
      case 115:
        v3 = (char *)calloc(0x80u, 1u);
        if ( CURRENT_INGREDIENT )
        {
          fgets(v3, 128, stdin);
          v3[strcspn(v3, "\n")] = 0;
          *(_DWORD *)CURRENT_INGREDIENT = atoi(v3);
        }
        else
        {
          puts("can't do it on a null guy");
        }
        free(v3);
        break;
      case 101:
        if ( CURRENT_INGREDIENT )
        {
          if ( ingredient_idx((char *)CURRENT_INGREDIENT + 8) == -1 && *((_BYTE *)CURRENT_INGREDIENT + 8) )
          {
            list_add(&INGREDIENT_LIST, (int)CURRENT_INGREDIENT);
            CURRENT_INGREDIENT = 0;
            puts("saved!");
          }
          else
          {
            puts("can't save because this is bad.");
          }
        }
        else
        {
          puts("can't do it on a null guy");
        }
        break;
      default:
        puts("UNKNOWN DIRECTIVE");
        break;
      case 113:
        return *MK_FP(__GS__, 20) ^ v5;
    }
  }
}
// 804D094: using guessed type int INGREDIENT_LIST;
// 8048C7B: using guessed type char var_16[10];

//----- (08049092) --------------------------------------------------------
int create_recipe()
{
  int v0; // ST2C_4@9
  unsigned int v2; // [sp+Ch] [bp-CCh]@12
  int v3; // [sp+10h] [bp-C8h]@12
  int v4; // [sp+18h] [bp-C0h]@7
  int v5; // [sp+20h] [bp-B8h]@13
  char s[10]; // [sp+32h] [bp-A6h]@2
  char nptr[144]; // [sp+3Ch] [bp-9Ch]@7
  int v8; // [sp+CCh] [bp-Ch]@1

  v8 = *MK_FP(__GS__, 20);
  while ( 1 )
  {
LABEL_2:
    puts("[n]ew recipe");
    puts("[d]iscard recipe");
    puts("[a]dd ingredient");
    puts("[r]emove ingredient");
    puts("[g]ive recipe a name");
    puts("[i]nclude instructions");
    puts("[s]ave recipe");
    puts("[p]rint current recipe");
    puts("[q]uit");
    fgets(s, 10, stdin);
    s[strcspn(s, "\n")] = 0;
    switch ( s[0] )
    {
      case 110:
        CURRENT_RECIPE = calloc(1u, 0x40Cu);
        continue;
      case 100:
        free(CURRENT_RECIPE);
        continue;
      case 97:
        if ( !CURRENT_RECIPE )
          puts("can't do it on a null guy");
        printf("which ingredient to add? ");
        fgets(nptr, 144, stdin);
        nptr[strcspn(nptr, "\n")] = 0;
        v4 = find_ingredient(nptr);
        if ( v4 )
        {
          printf("how many? (hex): ");
          fgets(nptr, 144, stdin);
          nptr[strcspn(nptr, "\n")] = 0;
          v0 = strtoul(nptr, 0, 16);
          list_add(CURRENT_RECIPE, v4);
          list_add((_DWORD *)CURRENT_RECIPE + 1, v0);
          puts("nice");
        }
        else
        {
          printf("I dont know about, %s!, please add it to the ingredient list!\n", nptr);
        }
        continue;
      case 114:
        if ( !CURRENT_RECIPE )
        {
          puts("can't do it on a null guy");
          continue;
        }
        printf("which ingredient to remove? ");
        fgets(nptr, 144, stdin);
        v2 = 0;
        v3 = *(_DWORD *)CURRENT_RECIPE;
        break;
      case 103:
        if ( CURRENT_RECIPE )
          fgets((char *)CURRENT_RECIPE + 140, 1036, stdin);
        else
          puts("can't do it on a null guy");
        continue;
      case 105:
        if ( CURRENT_RECIPE )
        {
          fgets((char *)CURRENT_RECIPE + 140, 1036, stdin);
          s[strcspn(s, "\n")] = 0;
        }
        else
        {
          puts("can't do it on a null guy");
        }
        continue;
      case 115:
        if ( CURRENT_RECIPE )
        {
          if ( recipe_idx((char *)CURRENT_RECIPE + 8) == -1 && *((_BYTE *)CURRENT_RECIPE + 8) )
          {
            *((_DWORD *)CURRENT_RECIPE + 31) = off_804D064;
            list_add(&RECIPE_LIST, (int)CURRENT_RECIPE);
            CURRENT_RECIPE = 0;
            puts("saved!");
          }
          else
          {
            puts("can't save because this is bad.");
          }
        }
        else
        {
          puts("can't do it on a null guy");
        }
        continue;
      case 112:
        if ( CURRENT_RECIPE )
          print_recipe((int)CURRENT_RECIPE);
        continue;
      default:
        puts("UNKNOWN DIRECTIVE");
        continue;
      case 113:
        return *MK_FP(__GS__, 20) ^ v8;
    }
    while ( v3 )
    {
      v5 = *(_DWORD *)v3;
      if ( !strcmp((const char *)(*(_DWORD *)v3 + 8), nptr) )
      {
        remove_at((int *)CURRENT_RECIPE, v2);
        remove_at((int *)CURRENT_RECIPE + 1, v2);
        printf("deleted %s from the recipe!\n", v5 + 8);
        goto LABEL_2;
      }
      ++v2;
      v3 = *(_DWORD *)(v3 + 4);
    }
  }
}
// 804D064: using guessed type char *off_804D064;
// 804D08C: using guessed type int RECIPE_LIST;
// 8049092: using guessed type char s[10];
// 8049092: using guessed type char nptr[144];

//----- (080495D6) --------------------------------------------------------
int __cdecl print_recipe(int a1)
{
  int v1; // eax@4
  int v2; // eax@4
  int v4; // [sp+14h] [bp-24h]@1
  int v5; // [sp+18h] [bp-20h]@1
  unsigned int i; // [sp+1Ch] [bp-1Ch]@1
  unsigned int v7; // [sp+20h] [bp-18h]@1
  int v8; // [sp+24h] [bp-14h]@2
  int v9; // [sp+28h] [bp-10h]@2
  int v10; // [sp+2Ch] [bp-Ch]@1

  v10 = *MK_FP(__GS__, 20);
  v4 = *(_DWORD *)a1;
  v5 = *(_DWORD *)(a1 + 4);
  v7 = list_length(&v4);
  printf("[---%s---]\n", a1 + 8);
  printf("recipe type: %s\n", *(_DWORD *)(a1 + 124));
  puts((const char *)(a1 + 140));
  for ( i = 0; i < v7; ++i )
  {
    v8 = nth_item(&v5, i);
    v9 = nth_item(&v4, i);
    printf("%zd - %s\n", v8, v9 + 8);
  }
  v1 = calc_total_cost(a1);
  printf("total cost : $%zu\n", v1);
  v2 = calc_total_calories(a1);
  printf("total cals : %zu\n", v2);
  return *MK_FP(__GS__, 20) ^ v10;
}

//----- (080496FA) --------------------------------------------------------
unsigned int recipe_book()
{
  int v0; // ST1C_4@2
  unsigned int result; // eax@3
  unsigned int i; // [sp+4h] [bp-14h]@1
  unsigned int v3; // [sp+8h] [bp-10h]@1

  v3 = list_length(&RECIPE_LIST);
  printf("%s's cookbook", dword_804D0AC);
  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= v3 )
      break;
    v0 = nth_item(&RECIPE_LIST, i);
    print_recipe(v0);
  }
  return result;
}
// 804D08C: using guessed type int RECIPE_LIST;

//----- (08049762) --------------------------------------------------------
signed int __cdecl contains(int *a1, const char *a2)
{
  signed int result; // eax@3
  int v3; // edx@7
  int v4; // [sp+1Ch] [bp-1Ch]@1
  unsigned int i; // [sp+20h] [bp-18h]@1
  unsigned int v6; // [sp+24h] [bp-14h]@1
  int v7; // [sp+28h] [bp-10h]@2
  int v8; // [sp+2Ch] [bp-Ch]@1

  v8 = *MK_FP(__GS__, 20);
  v4 = *a1;
  v6 = list_length(&v4);
  for ( i = 0; i < v6; ++i )
  {
    v7 = nth_item(&v4, i);
    if ( !strcmp((const char *)(v7 + 8), a2) )
    {
      result = 1;
      goto LABEL_7;
    }
  }
  result = 0;
LABEL_7:
  v3 = *MK_FP(__GS__, 20) ^ v8;
  return result;
}

//----- (080497F9) --------------------------------------------------------
void __cdecl exterminate_ingredient(char *s2)
{
  int v1; // ST2C_4@3
  int *v2; // ST34_4@8
  int *v3; // ST3C_4@13
  signed int i; // [sp+8h] [bp-30h]@2
  signed int j; // [sp+Ch] [bp-2Ch]@7
  signed int k; // [sp+10h] [bp-28h]@12
  unsigned int v7; // [sp+14h] [bp-24h]@1

  v7 = ingredient_idx(s2);
  if ( v7 != -1 )
  {
    remove_at(&INGREDIENT_LIST, v7);
    for ( i = list_length((int *)&unk_804D098) - 1; i >= 0; --i )
    {
      v1 = nth_item((int *)&unk_804D098, i);
      if ( !strcmp((const char *)(v1 + 8), s2) )
        remove_at((int *)&unk_804D098, i);
    }
    for ( j = list_length(&RECIPE_LIST) - 1; j >= 0; --j )
    {
      v2 = (int *)nth_item(&RECIPE_LIST, j);
      if ( contains(v2, s2) )
        remove_at(&RECIPE_LIST, j);
    }
    for ( k = list_length((int *)&unk_804D090) - 1; k >= 0; --k )
    {
      v3 = (int *)nth_item((int *)&unk_804D090, k);
      if ( contains(v3, s2) )
        remove_at((int *)&unk_804D090, k);
    }
  }
}
// 804D08C: using guessed type int RECIPE_LIST;
// 804D094: using guessed type int INGREDIENT_LIST;

//----- (08049AA6) --------------------------------------------------------
int __cdecl calc_total_cost(int a1)
{
  int result; // eax@4
  int v2; // ecx@4
  int v3; // [sp+10h] [bp-28h]@1
  int v4; // [sp+14h] [bp-24h]@1
  int v5; // [sp+18h] [bp-20h]@1
  unsigned int i; // [sp+1Ch] [bp-1Ch]@1
  unsigned int v7; // [sp+20h] [bp-18h]@1
  int v8; // [sp+24h] [bp-14h]@2
  int v9; // [sp+28h] [bp-10h]@2
  int v10; // [sp+2Ch] [bp-Ch]@1

  v10 = *MK_FP(__GS__, 20);
  v3 = *(_DWORD *)a1;
  v4 = *(_DWORD *)(a1 + 4);
  v5 = 0;
  v7 = list_length(&v3);
  for ( i = 0; i < v7; ++i )
  {
    v8 = nth_item(&v4, i);
    v9 = nth_item(&v3, i);
    v5 += *(_DWORD *)(v9 + 4) * v8;
  }
  result = v5;
  v2 = *MK_FP(__GS__, 20) ^ v10;
  return result;
}

//----- (08049B4A) --------------------------------------------------------
int __cdecl calc_total_calories(int a1)
{
  int result; // eax@4
  int v2; // ecx@4
  int v3; // [sp+10h] [bp-28h]@1
  int v4; // [sp+14h] [bp-24h]@1
  int v5; // [sp+18h] [bp-20h]@1
  unsigned int i; // [sp+1Ch] [bp-1Ch]@1
  unsigned int v7; // [sp+20h] [bp-18h]@1
  int v8; // [sp+24h] [bp-14h]@2
  _DWORD *v9; // [sp+28h] [bp-10h]@2
  int v10; // [sp+2Ch] [bp-Ch]@1

  v10 = *MK_FP(__GS__, 20);
  v3 = *(_DWORD *)a1;
  v4 = *(_DWORD *)(a1 + 4);
  v5 = 0;
  v7 = list_length(&v3);
  for ( i = 0; i < v7; ++i )
  {
    v8 = nth_item(&v4, i);
    v9 = (_DWORD *)nth_item(&v3, i);
    v5 += *v9 * v8;
  }
  result = v5;
  v2 = *MK_FP(__GS__, 20) ^ v10;
  return result;
}

//----- (08049BED) --------------------------------------------------------
void free_structures()
{
  free(dword_804D0AC);
  free(ptr);
  free_list(&RECIPE_LIST);
  free_list((int *)&unk_804D090);
  free_list(&INGREDIENT_LIST);
  free_list((int *)&unk_804D098);
}
// 804D08C: using guessed type int RECIPE_LIST;
// 804D094: using guessed type int INGREDIENT_LIST;

//----- (08049C58) --------------------------------------------------------
int __cdecl ingredient_idx(char *s2)
{
  int v2; // [sp+4h] [bp-14h]@1
  int i; // [sp+8h] [bp-10h]@1

  v2 = 0;
  for ( i = INGREDIENT_LIST; i && *(_DWORD *)i; i = *(_DWORD *)(i + 4) )
  {
    if ( !strcmp((const char *)(*(_DWORD *)i + 8), s2) )
      return v2;
    ++v2;
  }
  return -1;
}
// 804D094: using guessed type int INGREDIENT_LIST;

//----- (08049CB8) --------------------------------------------------------
int __cdecl recipe_idx(char *s2)
{
  int v2; // [sp+4h] [bp-14h]@1
  int i; // [sp+8h] [bp-10h]@1

  v2 = 0;
  for ( i = RECIPE_LIST; i && *(_DWORD *)i; i = *(_DWORD *)(i + 4) )
  {
    if ( !strcmp((const char *)(*(_DWORD *)i + 8), s2) )
      return v2;
    ++v2;
  }
  return -1;
}
// 804D08C: using guessed type int RECIPE_LIST;

//----- (08049D44) --------------------------------------------------------
int __cdecl find_ingredient(char *s2)
{
  unsigned int idx; // ST1C_4@1

  idx = ingredient_idx(s2);
  return nth_item(&INGREDIENT_LIST, idx);
}
// 804D094: using guessed type int INGREDIENT_LIST;

//----- (08049D70) --------------------------------------------------------
_DWORD *__cdecl alloc_ingredient(int a1, int a2, void *src, size_t n)
{
  void *v4; // eax@1
  _DWORD *v5; // ST1C_4@1

  v4 = calloc(1u, 0x90u);
  v5 = v4;
  *(_DWORD *)v4 = a1;
  *((_DWORD *)v4 + 1) = a2;
  memcpy((char *)v4 + 8, src, n);
  v5[35] = v5;
  return v5;
}

//----- (08049DC5) --------------------------------------------------------
_DWORD *init_ingredients()
{
  _DWORD *v0; // ST10_4@1
  _DWORD *v1; // ST14_4@1
  _DWORD *v2; // ST18_4@1
  _DWORD *v3; // ST1C_4@1
  _DWORD *v4; // ST20_4@1
  _DWORD *v5; // ST24_4@1
  _DWORD *v6; // ST28_4@1
  _DWORD *v7; // ST2C_4@1

  v0 = alloc_ingredient(0, 6, "water", 5u);
  v1 = alloc_ingredient(1, 5, "tomato", 6u);
  v2 = alloc_ingredient(2, 4, "basil", 5u);
  v3 = alloc_ingredient(3, 3, "garlic", 6u);
  v4 = alloc_ingredient(4, 2, "onion", 5u);
  v5 = alloc_ingredient(5, 1, "lemon", 5u);
  v6 = alloc_ingredient(6, 10, "corn", 4u);
  v7 = alloc_ingredient(2, 3, "olive oil", 9u);
  list_add(&INGREDIENT_LIST, (int)v0);
  list_add(&INGREDIENT_LIST, (int)v1);
  list_add(&INGREDIENT_LIST, (int)v2);
  list_add(&INGREDIENT_LIST, (int)v3);
  list_add(&INGREDIENT_LIST, (int)v4);
  list_add(&INGREDIENT_LIST, (int)v5);
  list_add(&INGREDIENT_LIST, (int)v6);
  return list_add(&INGREDIENT_LIST, (int)v7);
}
// 804D094: using guessed type int INGREDIENT_LIST;

//----- (08049F16) --------------------------------------------------------
int init_recipes()
{
  int v1; // [sp+0h] [bp-48h]@1
  int v2; // [sp+4h] [bp-44h]@1
  int v3; // [sp+8h] [bp-40h]@1
  int v4; // [sp+Ch] [bp-3Ch]@1
  int v5; // [sp+10h] [bp-38h]@1
  int v6; // [sp+14h] [bp-34h]@1
  void *v7; // [sp+18h] [bp-30h]@1
  int v8; // [sp+1Ch] [bp-2Ch]@1
  void *v9; // [sp+20h] [bp-28h]@1
  int v10; // [sp+24h] [bp-24h]@1
  int v11; // [sp+28h] [bp-20h]@1
  int v12; // [sp+2Ch] [bp-1Ch]@1
  int v13; // [sp+30h] [bp-18h]@1
  void *v14; // [sp+34h] [bp-14h]@1
  int v15; // [sp+38h] [bp-10h]@1
  int v16; // [sp+3Ch] [bp-Ch]@1

  v16 = *MK_FP(__GS__, 20);
  v7 = calloc(1u, 0x40Cu);
  v1 = 0;
  v8 = find_ingredient("corn");
  list_add(&v1, v8);
  *(_DWORD *)v7 = v1;
  v2 = 0;
  memcpy((char *)v7 + 8, "grilled corn", 0xCu);
  memcpy((char *)v7 + 140, "just grill it on a tiny .vn grill", 0x21u);
  list_add(&v2, 4);
  *((_DWORD *)v7 + 1) = v2;
  *((_DWORD *)v7 + 31) = off_804D054;
  list_add(&RECIPE_LIST, (int)v7);
  v9 = calloc(1u, 0x40Cu);
  memcpy((char *)v9 + 8, "roasted tomato with basil and garlic", 0x24u);
  memcpy(
    (char *)v9 + 140,
    "first quarter the tomatoes, then mix with garlic and olive oil, top with chopped basil, bake at 275f for 2 hours.",
    0x71u);
  v3 = 0;
  v10 = find_ingredient("tomato");
  v11 = find_ingredient("basil");
  v12 = find_ingredient("garlic");
  v13 = find_ingredient("olive oil");
  list_add(&v3, v10);
  list_add(&v3, v11);
  list_add(&v3, v12);
  list_add(&v3, v13);
  v4 = 0;
  list_add(&v4, 16);
  list_add(&v4, 5);
  list_add(&v4, 8);
  list_add(&v4, 2);
  *(_DWORD *)v9 = v3;
  *((_DWORD *)v9 + 1) = v4;
  *((_DWORD *)v9 + 31) = off_804D058;
  list_add(&RECIPE_LIST, (int)v9);
  v14 = calloc(1u, 0x40Cu);
  v5 = 0;
  v15 = find_ingredient("water");
  list_add(&v5, v15);
  *(_DWORD *)v14 = v5;
  v6 = 0;
  memcpy((char *)v14 + 8, "water", 5u);
  memcpy((char *)v14 + 140, "pour it in a glass", 0x12u);
  list_add(&v6, 1);
  *((_DWORD *)v14 + 1) = v6;
  *((_DWORD *)v14 + 31) = off_804D05C;
  list_add(&RECIPE_LIST, (int)v14);
  return *MK_FP(__GS__, 20) ^ v16;
}
// 804D054: using guessed type char *off_804D054;
// 804D058: using guessed type char *off_804D058;
// 804D05C: using guessed type char *off_804D05C;
// 804D08C: using guessed type int RECIPE_LIST;

//----- (0804A214) --------------------------------------------------------
int __cdecl print_ingredient(int a1)
{
  printf("name: %s\n", a1 + 8);
  printf("calories: %zd\n", *(_DWORD *)a1);
  return printf("price: %zd\n", *(_DWORD *)(a1 + 4));
}

//----- (0804A261) --------------------------------------------------------
int list_ingredients()
{
  int result; // eax@1
  int v1; // [sp+8h] [bp-10h]@1

  result = INGREDIENT_LIST;
  v1 = INGREDIENT_LIST;
  while ( v1 )
  {
    puts("------");
    print_ingredient(*(_DWORD *)v1);
    result = *(_DWORD *)(v1 + 4);
    v1 = *(_DWORD *)(v1 + 4);
    if ( !v1 )
      result = puts("------");
  }
  return result;
}
// 804D094: using guessed type int INGREDIENT_LIST;

//----- (0804A2BF) --------------------------------------------------------
int initialize()
{
  init_ingredients();
  return init_recipes();
}

//----- (0804A2D2) --------------------------------------------------------
int print_banner()
{
  puts("+-----------------------------+");
  puts("|          .--,--.            |");
  puts("|          `.  ,.'            |");
  puts("|           |___|             |");
  puts("|           :o o:             |");
  puts("|          _`~^~'             |");
  puts("|        /'   ^   `\\          |");
  puts("| cooking manager pro v6.1... |");
  return puts("+-----------------------------+");
}

//----- (0804A36B) --------------------------------------------------------
int print_bye()
{
  puts("   emmmmmm~~~~~~~~~~oT");
  puts("          |          |");
  puts("          |          |");
  return puts("          `----------'");
}

//----- (0804A3B4) --------------------------------------------------------
int __cdecl main(int a1, char **a2)
{
  int v2; // eax@2

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  if ( a1 > 1 )
  {
    v2 = atoi(a2[1]);
    alarm(v2);
  }
  your_name();
  print_banner();
  initialize();
  main_menu();
  free_structures();
  print_bye();
  return 0;
}

//----- (0804A440) --------------------------------------------------------
void init(void)
{
  int v0; // edi@1
  signed int v1; // esi@1

  v0 = 0;
  init_proc();
  v1 = &off_804CF0C - off_804CF08;
  if ( v1 )
  {
    do
      off_804CF08[v0++]();
    while ( v0 != v1 );
  }
}
// 804CF08: using guessed type int (*off_804CF08[2])();
// 804CF0C: using guessed type int (*off_804CF0C)();

//----- (0804A4A4) --------------------------------------------------------
void term_proc()
{
  ;
}

#error "There were 1 decompilation failure(s) on 38 function(s)"