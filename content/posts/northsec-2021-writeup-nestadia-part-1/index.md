---
title: "NorthSec 2021 Writeup: Nestadia Part 1"
date: 2021-05-26T07:05:00-04:00
tags: 
  - CTF
  - Reverse
  - Writeup
---

*This blog post outlines flags 1 and 2 of the Nestadia reverse engineering track. Nestadia is a cloud-based gaming platform for the NES inspired by Google stadia.*

Another year, another totally awesome Northsec CTF. This year I spent
most of my time on a single track: Nestadia. I started the CTF on
friday night with absolutely no knowledge of the [original Nintendo
(NES)][nes] and I finished the weekend with a very good knowledge of
both the NES computer and its architecture, the [6502
processor][6502], which I will cover in part 2 of this mini-series. If
you like reverse engineering, assembler listings, emulation and
interpreted languages, this writeup should tick all the boxes.

Nestadia is a tailor-built cloud-based gaming platform inspired by
[Google Stadia][stadia] which lets the users play classic Nintendo
games over the internet right in their browsers. The challenge is a
reverse engineering track which contains 4 flags, worth respectively
1, 3, 6 and 10 points, for a grand total of 20 points (a lot of points
for NorthSec). Let's get started, then.


## Reconaissance

First things first, Let's visit the website, `nestadia.ctf` and see what Nestadia is about... a simple landing page which contains the Nestadia logo, and three menus:

![Nestadia Landing Page](landing.png)


The **Dev Login** button is begging to be clicked on, but upon doing
so, the user is asked for a password to log in to the developer
dashboard. Let's keep that in mind for now and finish exploring the
remaining functionality.

The first of the two other options lets us play one of three available
games in Nestadia: Flappy Bird, Alter Ego, and Nesert Bus. This turns
out to be very difficult over a browser connected to the CTF
environment over VPN. Inputs are laggy and the FPS is very unstable.
It looks like we weren't meant to play the games directly on the
platform... or at least on the server.

![Alter Ego's splash screen in Nestadia](game.png)

The last option is to upload our own game (a Nintendo ROM) to try it
on the Nestadia platform. Unfortunately, we don't have any ROMs to
upload right now, but this will definitely come in handy later.


## Flag 1: Gaining Developer Access

Great, our first goal is fairly obvious: We should try to get access
to the development dashboard.

Since this is a web page, let's open the developer tools and... oh,
what? It looks like the frontend is a ReactJS application and it also
looks like the source maps (the web equivalent of debug symbols) were
published to production. This means we can get access to all of the
minified source code in its original glory.

Looking through the sources, there are various files that seem to drive the emulator, and there is one file in particular which stands out, called `login.tsx`. Let's Open it up and...

![The base64 encoded password in the login validation routine](client-side-passwd.png)

Oh, it looks like someone hardcoded the development password into the
frontend. How nice of them. One `atob` later and we have the password
to login to the development portal. Let's login...

![The first flag!](flag1.png)

Here's flag 1, handed to us on a silver platter. Hopefully the next
few flags are just as easy (hint: they are not.)

As an authenticated developer, we are also allowed to download a deubg
build of Nestadia and try out the new game that is currently being
developed:

![A brand new thrilling game! Sign me up!](dev-rom.png)

Unfortunately, it doesn't look like we can do much with the
development game. Let's focus on the debug build instead.

## Setting up Nestadia locally

Alright, this should be interesting... If anything, we can run the
engine on localhost and hopefully get less input lag. Unpacking the
archive, we get the following file structure:


```bash
alex@artesia re/nestadia/www $ tree
.
├── client_build
│   ├── index.html
│   ├── logo192.png
│   └── static
│       ├── css
│       │   └── main.284736cd.chunk.css
│       ├── js
│       │   ├── 2.cb624325.chunk.js
│       │   ├── 2.cb624325.chunk.js.map
│       │   ├── appstate.ts
│       │   ├── App.tsx
│       │   ├── devdashboard
│       │   │   └── devdashboard.tsx
│       │   ├── emulator
│       │   │   ├── emulatorMode.ts
│       │   │   ├── emulator.tsx
│       │   │   └── RGB_VALUES_TABLE.ts
│       │   ├── index.tsx
│       │   ├── login
│       │   │   └── login.tsx
│       │   ├── main.53868cfd.chunk.js
│       │   ├── main.53868cfd.chunk.js.map
│       │   ├── mainpage
│       │   │   └── mainpage.tsx
│       │   └── reportWebVitals.ts
│       └── media
│           └── logo-nestadia-background.99c448be.png
├── nestadia_debug
└── saves
```

This looks good... running a bit of recon on `nestadia_debug` we get:


```sh
alex@artesia re/nestadia/www $ file nestadia_debug
nestadia_debug: ELF 64-bit LSB shared object, x86-64,
version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=5783ad35bf101d9582e2344eead0247f0ea6cbeb, for GNU/Linux 3.2.0,
with debug_info, not stripped
```

Great, so this is a binary with symbols and debug information. That
should help with the reverse engineering... but right now what's more
interesting is trying to run the server locally:

```sh
alex@artesia re/nestadia/www $ ./nestadia_debug -h
nestadia-server 0.1.0

USAGE:
    nestadia_debug [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -b, --bind-addr <bind-addr>     [default: 127.0.0.1]
    -l, --log-level <log-level>     [default: info]
    -p, --port <port>               [default: 8080]
```

Welp, I didn't expect that to work. At least now we know how to start
this thing, and we can even change the vebrosity level, neat. Time to
give it a spin:

```sh
alex@artesia re/nestadia/www $ ./nestadia_debug -b 0.0.0.0
INFO [actix_server::builder] Starting 16 workers
INFO [actix_server::builder] Starting "actix-web-service-0.0.0.0:8080" service on 0.0.0.0:8080
```

Great, it works, but what we see is relatively scary for those who
know what `actix` is. Yep, it's a web server... written in
[Rust][rust], a language praised for its memory safety and speed,
among others, but also a language known to have poor tooling for
reverse engineering. More things to look forward to, certainly.

Now then, it should be time to try those games... but it's still
pretty tough to play, even locally. But what if we were to extract the
ROMs from the server binary? Then certainly we could throw them into a
NES emulator like [FCEUX][fceux] and run them fully offline. Surely,
there must be a flag in one of those ROMs. 


## Carving out the ROMs

A quick run of `binwalk` doesn't appear to identify the ROMs, even
though they are definitey in there.

If the ROMs are in the binary, surely we can carve them out... all we
need to do is know the file structure of NES ROMs and scan the memory
to find them. Time for a dive into the [iNES 1.0 format][ines]! After
a bit of internet search, it becomes clear that the format is called
iNES 1.0 and that the gist of it goes something like this (see link
above for a full explanation):

```plain
iNES 1.0 File Format (All numbers in decimal)
  HEADER (16 bytes) 
    +000 magic     ;  'N' 'E' 'S' '\x1A' 
    +004 prg_size  ; Program ROM size in 16KB units)
    +005 chr_size  ; Character ROM size in 8KB units)
    +006 flag6     ; various flags
    +007 flag7     ;
    +008 flag8     ;
    +009 flag9     ;
    +010 flag10    ;
    +011 padding   ; padded to 16 bytes.
  PROGRAM ROM
    +016  prg_rom  ; <prg_size * 16KB> bytes
  CHR ROM
    +prg chr_rom   ; <chr_size * 8KB> bytes
```

Well, this should be enough information to write a simple python
script that takes a binary blob and scans for ROMs and tries to parse
them. If the ROM can be parsed successfully (that is, `prg_size` and
`chr_size` make sense, and enough bytes are available) we can then
write it to the disk. The script looks like this:

```py
#!/usr/bin/env python
import os
import sys
from pwn import *
from io import BytesIO, SEEK_CUR

MAGIC = b'NES\x1A'

def read(stream: BytesIO, size: int) -> bytes:
    read = stream.read(size)
    if len(read) != size:
        raise Exception('Unexpected EOF')
    return read

class NesHeader(object):
    def parse(stream: BytesIO) -> 'NesHeader':
        hdr = NesHeader()

        s = read(stream, 16)

        magic = s[0:4]
        if magic != MAGIC:
            raise Exception('Invalid magic')

        hdr.prgsz = s[4]

        hdr.chrsz = s[5]

        if hdr.prgsz > 10 or hdr.chrsz > 10:
            raise Exception('ROM too big??')

        hdr.flag6 = s[6]
        hdr.flag7 = s[7]
        hdr.flag8 = s[8]
        hdr.flag9 = s[9]
        hdr.flag10 = s[10]
        hdr.padding = s[11:]
        hdr.raw = s
        return hdr

    def __str__(self):
        return hexdump(self.raw)

    @property
    def prg_size(self):
        return self.prgsz * 16384

    @property
    def chr_size(self):
        return self.chrsz * 8192

    @property
    def has_trainer(self):
        return self.flag6 & 0b00000100

    @property
    def has_inst(self):
        return self.flag7 & 0b00000010

class NesRom(object):
    def parse(stream: BytesIO) -> 'NesRom':
        rom = NesRom()
        rom.start = stream.tell()
        rom.header = NesHeader.parse(stream)

        rom.trainer = read(stream, 512) if rom.header.has_trainer else b''
        rom.prg_data = read(stream, rom.header.prg_size)
        rom.chr_data = read(stream, rom.header.chr_size)
        rom.inst_rom = read(stream, 8192) if rom.header.has_inst else b''
        rom.prom = read(stream, 32) if rom.header.has_inst else b''

        rom.size = stream.tell() - rom.start
        stream.seek(rom.start)
        rom.raw = read(stream, rom.size)
        return rom

    def __str__(self):
        return f'<Rom Start={self.start:8x} Size={self.size:8x}\n' + str(self.header)

def main(file):
    with open(file, 'rb') as f:
        pos = 0
        try:
            while f.readable():
                while read(f, 4) != MAGIC:
                    continue
                f.seek(-len(MAGIC), SEEK_CUR)
                try:
                    pos = f.tell()
                    info(f'Attempting to parse a NES Rom @ {pos:8x}')
                    rom = NesRom.parse(f)
                except Exception as e:
                    info(f'Not a valid ROM... skip ({e})')
                    continue
                success('Found at ' + str(pos))
                print(rom)
                with open(f'rom_{pos:08x}.rom', 'wb') as out:
                    out.write(rom.raw)
        except Exception:
            pass  # EOF

main(sys.argv[1])
```

We run the script and...

```sh
dom0@th1nk CTF/NSEC21/nestadia $ ./carve.py www/nestadia_debug
[*] Attempting to parse a NES Rom @   3c3584
[+] Found at 3945860
<Rom Start=  3c3584 Size=    6010
00000000  4e 45 53 1a  01 01 01 00  00 00 00 00  00 00 00 00  │NES·│····│····│····│
00000010
[*] Attempting to parse a NES Rom @   3c9594
[+] Found at 3970452
<Rom Start=  3c9594 Size=    a010
00000000  4e 45 53 1a  02 01 01 00  00 00 00 00  00 00 00 00  │NES·│····│····│····│
00000010
[*] Attempting to parse a NES Rom @   3d35a4
[+] Found at 4011428
<Rom Start=  3d35a4 Size=    6010
00000000  4e 45 53 1a  01 01 01 00  00 00 00 00  00 00 00 00  │NES·│····│····│····│
00000010
[*] Attempting to parse a NES Rom @   3f0c60
[*] Not a valid ROM... skip (ROM too big??)
```

Wait a second, we only got 3 ROMs? Oh well, maybe the development ROM
is loaded somewhere else? In any case, we have some flags to find in
those ROMs, so let's try loading them up in FCEUX and playing with
them a bit.

> **NOTE**: The last "invalid" ROM is actually the code in the `load()` function of the emulator
> which verifies the MAGIC of the ROM. Since the carve script scans for the magic bytes, it
> tried to process the magic check code as a ROM and failed.

## Rabbit Holes: The Name of the Game

Little did I know at the time, there were no flags in those ROMs. A
whole 6 hours went by and it was suddenly three in the morning and I
had beaten Alter Ego using save states and cheats to get infinite
swaps, anticipating a flag at the end, and being incredibly
disappointed.

![Clearing Alter Ego: No flag.](alter-ego.png)

I then naively thought the flag would be in Flappy Bird, so I
"reversed" it enough to understand how to get my bird stuck in a
position where I could let the game run on turbo to get an unlimited
amount of points, Hoping that the screen would go black, or blue, and
grant me a flag for figuring out how to cheat at NES games. 

!['Clearing' Flappy Bird: No flag.](trying-cheats.png)

After more than 8000 points, I was still not rewarded for my effort,
and so I moved on to the next game: Nesert Bus.

![Umm... what?](nesert.png)

...

...


I never understood how to play Nesert Bus.

Right, so if the flag isn't handed to us by completing the ROMs, maybe
it's embedded in a secret function in the ROM itself and we have to
reverse it. Let's search online for a way to load NES ROMs in Ghidra
and benefit from its incredibly powerful decompiler...
[GhidraNes][ghidra-nes]? Sounds good.

And of course, Ghidra refuses to load the plugin... alright, Let's
build Ghidra from source and let's build the plugin from source.

Ghidra still won't load the plugin... umm?

Okay, let's load the plugin project in Eclipse and link it to Ghidra.
Now let's launch it as a debugged program. Yay! ROM loading at last.

![The ROM loaded in Ghidra for static analysis](rom-loaded.png)

The next 4 hours were spent reversing Nesert Bus in search of a hidden
flag. At which point I gave up.

Maybe... just maybe. Could it be that I'm supposed to get my hands on
the development ROM? Is that the reason it wasn't easily carvable? But I
don't want to reverse Rust yet. There's no way flag 2 would require us
to reverse Rust, right? right?


## Enter (pwn)gdb: Carving the Development ROM


Okay wait, let's not panic yet... we have symbols. We know the
emulator has a `load` function. Digging a bit further reveals that
there's also a `start_emulation` function.

Let's try setting a breakpoint on that and loading the dev ROM. Surely
at that point it will be in memory, and we can just dump the bytes to disk.
It's already 10AM on Sunday (CTF ends at 3PM) by then... let's just focus on
running the commands:

```sh
pwndbg> set args -b 0.0.0.0
pwndbg> b start
pwndbg> b nestadia_server::nestadia_ws::start_emulation
Breakpoint 1 at 0x113740
pwndbg> r
[... load the dev rom in the website ...]

Thread 5 "actix-rt:worker" hit Breakpoint 1, 0x0000555555667740 in nestadia_server::nestadia_ws::start_emulation ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──[ REGISTERS ]────────────────────────────────────────────────────
 RAX  0x7fffc802fb03 ◂— 0xffffffffffffffff
 RBX  0x7fffc802fbb0 —▸ 0x7fffc8014570 ◂— 0x2
 RCX  0x6010
 RDX  0x7fffc8029b90 ◂— 0x1011a53454e
 RDI  0x7ffff5dfbc30 ◂— 0x2
 RSI  0x7fffc802fbb0 —▸ 0x7fffc8014570 ◂— 0x2
 R8   0x0
 R9   0x6153203a65746164 ('date: Sa')
 R10  0x614d203232202c74 ('t, 22 Ma')
 R11  0x3120313230322079 ('y 2021 1')
 R12  0x7fffc802fbb0 —▸ 0x7fffc8014570 ◂— 0x2
 R13  0x7fffc802fd78 ◂— 0x1
 R14  0x7ffff5dfbe90 ◂— 0x0
 R15  0x7ffff5dfbd68 ◂— 0x3
 RBP  0x7ffff5dfbdd9 ◂— 0xf000007fffc800ec
 RSP  0x7ffff5dfbc18 —▸ 0x555555657b56 ◂— cmp    dword ptr [rsp + 0x10], 1
 RIP  0x555555667740 (nestadia_server::nestadia_ws::start_emulation) ◂— push   rbp
──[ DISASM ]──────────────────────────────────────────────────────
 ► 0x555555667740 <nestadia_server::nestadia_ws::start_emulation>       push   rbp
   0x555555667741 <nestadia_server::nestadia_ws::start_emulation+1>     push   r15
   0x555555667743 <nestadia_server::nestadia_ws::start_emulation+3>     push   r14
   0x555555667745 <nestadia_server::nestadia_ws::start_emulation+5>     push   r13
   0x555555667747 <nestadia_server::nestadia_ws::start_emulation+7>     push   r12
   0x555555667749 <nestadia_server::nestadia_ws::start_emulation+9>     push   rbx
   0x55555566774a <nestadia_server::nestadia_ws::start_emulation+10>    mov    eax, 0x42858
   0x55555566774f <nestadia_server::nestadia_ws::start_emulation+15>    call   __rust_probestack <0x55555591136a>

   0x555555667754 <nestadia_server::nestadia_ws::start_emulation+20>    sub    rsp, rax
   0x555555667757 <nestadia_server::nestadia_ws::start_emulation+23>    mov    dword ptr [rsp + 0x34], r8d
   0x55555566775c <nestadia_server::nestadia_ws::start_emulation+28>    mov    r15, rcx
──[ STACK ]──────────────────────────────────────────────────────
00:0000│ rsp  0x7ffff5dfbc18 —▸ 0x555555657b56 ◂— cmp    dword ptr [rsp + 0x10], 1
01:0008│      0x7ffff5dfbc20 ◂— 0x0
02:0010│      0x7ffff5dfbc28 ◂— 0x4
03:0018│ rdi  0x7ffff5dfbc30 ◂— 0x2
04:0020│      0x7ffff5dfbc38 —▸ 0x7ffff5dfbfd8 ◂— 0x0
05:0028│      0x7ffff5dfbc40 —▸ 0x7fffc8008210 ◂— 0x0
06:0030│      0x7ffff5dfbc48 —▸ 0x55555577842f (actix_http::h1::payload::Inner::new+95) ◂— mov    qword ptr [rbx], 0
07:0038│      0x7ffff5dfbc50 ◂— 0x0
──[ BACKTRACE ]─────────────────────────────────────────────────
 ► f 0     555555667740 nestadia_server::nestadia_ws::start_emulation
   f 1     555555657b56
   f 2     555555655e2d
   f 3     55555576d03e
   f 4     5555555df8e5 actix_http::h1::dispatcher::InnerDispatcher<T,S,B,X,U>::poll_response+325
   f 5     5555555e7924
   f 6     5555555dd971
   f 7     55555565afa8
   f 8     555555646266 tokio::runtime::task::raw::poll+310
   f 9     5555558b9442 tokio::task::local::LocalSet::tick+738
   f 10     555555899597
```

Great... now, let's see. Logically, one of the arguments to `start_emulation` has to be a pointer to the ROM bytes.
If it's not a register, then surely somewhere nearby on the stack... Thankfully, `rdx` is the answer:


```sh
pwndbg> hexdump 0x7fffc8029b90
+0000 0x7fffc8029b90  4e 45 53 1a  01 01 00 00  00 00 00 00  00 00 00 00  │NES.│....│....│....│
+0010 0x7fffc8029ba0  2c 02 20 10  fb a9 3f 8d  06 20 a9 01  8d 06 20 a9  │,...│..?.│....│....│
+0020 0x7fffc8029bb0  0f 8d 07 20  a9 28 8d 07  20 a9 28 8d  07 20 a9 00  │....│.(..│..(.│....│
+0030 0x7fffc8029bc0  85 21 a9 00  85 20 2c 02  20 10 fb e6  20 a5 20 c9  │.!..│..,.│....│....│
```

Great, so let's just dump a large amount of bytes to make sure we have all of the ROM:


```sh
pwndbg> hexdump 0x7fffc8029b90 800
+0000 0x7fffc8029b90  4e 45 53 1a  01 01 00 00  00 00 00 00  00 00 00 00  │NES.│....│....│....│
+0010 0x7fffc8029ba0  2c 02 20 10  fb a9 3f 8d  06 20 a9 01  8d 06 20 a9  │,...│..?.│....│....│
+0020 0x7fffc8029bb0  0f 8d 07 20  a9 28 8d 07  20 a9 28 8d  07 20 a9 00  │....│.(..│..(.│....│
+0030 0x7fffc8029bc0  85 21 a9 00  85 20 2c 02  20 10 fb e6  20 a5 20 c9  │.!..│..,.│....│....│
[... snip ...]
+0210 0x7fffc8029da0  46 4c 41 47  2d 7b 64 62  35 34 39 34  35 63 66 62  │FLAG│-{db│5494│5cfb│
+0220 0x7fffc8029db0  65 65 35 31  38 32 39 39  39 36 33 64  66 30 39 32  │ee51│8299│963d│f092│
+0230 0x7fffc8029dc0  66 37 65 39  38 66 32 36  61 63 34 37  35 34 7d 00  │f7e9│8f26│ac47│54}.│
+0240 0x7fffc8029dd0  ff ff ff ff  ff ff ff ff  ff ff ff ff  ff ff ff ff  │....│....│....│....│
...
```

Hey, that's our flag 2! Wee! 3 points for us. Before going any
further, let's just also dump this ROM to the disk:

```sh
pwndbg> dump binary memory rom.bin 0x7fffc8029b90 0x7fffc8029b90+40000

alex@artesia nsec21/re/nestadia ! ./carve.py rom.bin
[*] Attempting to parse a NES Rom @        0
[+] Found at 0
<Rom Start=       0 Size=    6010
00000000  4e 45 53 1a  01 01 00 00  00 00 00 00  00 00 00 00  │NES·│····│····│····│
00000010
```


## The End...? Or not.

This post only covered the first two flags out of a total of four for
the Nestadia track. So far I've dabbled in the iNES file format,
gotten a decent understanding of the NES CPU internals and managed to
avoid having to learn/read 6502 by relying on Ghidra's decompiler.
Little did I know things were about to get a lot more intense. Stay
tuned for part 2, in which I will go over the 3rd flag, become very
familiar with the NES, and get caught up by 6502.

------

### References

- [iNES 1.0 file format][ines]
- [6502 Instruction Set][6502]
- [GhidraNes Loader][ghidra-nes]
- [FCEUX Emulator][fceux]


[nes]: https://en.wikipedia.org/wiki/Nintendo_Entertainment_System "The Nintendo Entertanment System"
[6502]: www.obelisk.me.uk/6502/reference.html "6502 Assembler Instruction Set Reference"
[stadia]: https://en.wikipedia.org/wiki/Google_Stadia "Google Stadia"
[fceux]: http://fceux.com/web/home.html "The FCEUX NES emulator"
[ines]: https://wiki.nesdev.com/w/index.php/INES
[ghidra-nes]: https://github.com/kylewlacy/GhidraNes/ "GhidraNes by @kylewlacy"
[rust]: https://rust-lang.org "The Rust Programming Language"
