#
# 33C3 CTF 2016 pwn babyfengshui
#

from pwn import *
import re

b = ELF('./babyfengshui')
clib = ELF('/lib/i386-linux-gnu/libc.so.6')

r = process('./babyfengshui')

def recv_all():
    b = ""
    last_recv = True
    while last_recv:
        try:
            last_recv = r.recv(1024)
        except socket.timeout:
            last_recv = None
        if last_recv:
            b += last_recv
    return b

def snd(s):
    r.send(s)

def add(size_desc, desc, size_text, text):
    snd('0\n')
    r.recvuntil('size of description: ')
    snd(str(size_desc) + '\n')
    r.recvuntil('name: ')
    snd(desc + '\n')
    r.recvuntil('text length: ')
    snd(str(size_text) + '\n')
    r.recvuntil('text: ')
    snd(text + '\n')
    r.recvuntil('Action: ')

def delete(idx):
    snd('1\n')
    r.recvuntil('index: ')
    snd(str(idx) + '\n')
    r.recvuntil('Action: ')

def display(idx):
    snd('2\n')
    r.recvuntil('index: ')
    snd(str(idx) + '\n')
    resp = recv_all()
    print resp
    name = re.findall(r"name: (.+)", resp)[0]
    desc = re.findall(r"description: (.+)", resp)[0]
    return (name, desc)

def update(idx, size_text, text):
    snd('3\n')
    r.recvuntil('index: ')
    snd(str(idx) + '\n')
    r.recvuntil('text length: ')
    snd(str(size_text) + '\n')
    r.recvuntil('text: ')
    snd(text + '\n')
    r.recvuntil('Action: ')

if __name__ == "__main__":

    r.recvuntil('Action: ')

    r.settimeout(0.5)

    add(100,'babo',50,'haha')
    print display(0)

    update(0,10,'haha2')
    print display(0)

    r.interactive()
