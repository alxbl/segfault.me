---
title: 'NorthSec 2020 Writeup: Essay'
date: 2020-05-22T19:55:44-04:00
tags:
  - CTF
  - Writeup
  - Reverse
description: 'Write-up for the NorthSec 2020 CTF challenge "Essay", a crackme written in the Shakespeare Programming Language (SPL)'
---

*This post outlines the solution to NorthSec 2020's Essay challenge, it presents the side-channel that I used to retrieve the flag without actually reversing the code*


# Act I: The Context

You are given a rather large text file called `essay.txt` which looks like the beginning of a Shakespeare play. A bit of googling around reveals that it's actually some esoteric language that some genius (or mad?) students procrastinating their assignments came up with.

Nice, now I have to learn this for virtual points in a virtual competition? challenge accepted.


## Scene I: A Most Fitting Interpreter

The thing to understand about Shakespeare is that it's old. Like 2004 old. And because of its verbose nature, it understandingly does not have as large a cult following as say, Golang or Rust.

Thankfully, some very determined people have written SPL [interpreters][2] and [transpilers][3] (a fancy word for compilers that compile to a different high level language) that can be leveraged.

Another member of my team had attempted the challenge before me, and it turns out that the challenge designer had also (purposefully?) made typographical mistakes and syntax errors that caused the existing tools to crash. Thankfully, my teammate had figured those out and sent me the C-translated source code along with a pre-compiled version.

The translating compiler he used was [Kyle Cartmell's Marlowe][1] which has actual decent error reporting, unlike all the other projects that we tried.

[1]: https://bitbucket.org/kcartmell/marlowe/
[2]: https://github.com/zmbc/shakespearelang
[3]: https://github.com/redleek/spl2c


## Scene II: To Instrument, or not to Instrument?

Initially I was going to instrument the entire code base to try and understand what was going on, but while doing that and reading through `libspl.c` from the transpiler, I noticed that a lot of debugging code already existed and was simply gated behind an `#ifdef DEBUG` check. I enabled that and ran the program again, dumping `stdout` and `stderr` to a log file, which resulted in a massive quantity of log.

```c
/* libspl.c */
/* ... */

#ifdef DEBUG
void dump_cast_whereabouts(FILE *out)
{
    /* ... */
}

void dump_stack(FILE *out, CHARACTER *character)
{
    /* ... */
}

/* ... */
```

After compiling `libspl` with `-DDEBUG` and then compiling `essay.c` into an executable (mind you, this required a lot of fiddling in the visual studio projects, too), I was able to get the following output (snippet) leading up to the password prompt:

```plain
Hamlet just entered
               Romeo
              Juliet
             Ophelia
              Olivia
              Hamlet on stage

Romeo just entered
               Romeo on stage
              Juliet
             Ophelia
              Olivia
              Hamlet on stage

Hamlet's previous value was 0.
Hamlet's new value is -8.

Computing int_sub(-1, -8) = 7

Hamlet's previous value was -8.
Hamlet's new value is 7.
...
```

and this keeps going... for roughly 300KB of text.

From parsing those logs and sending pre-determined inputs of data, I was able to identify the meaning of each "variable". The important ones being:

- **Juliet** The user input
- **Romeo** The expected password

I also determined that at some point Romeo's stack would need to be popped to perform character comparison. I used a very advanced technique known as `Ctrl+F` to look for stack pops from Romeo, but only found one hit. A theory began to brew inside of my brain. I decided to try to submit `FLAG-` as my input, and promptly found 6 hits.


```plain
Popping Romeo, getting the value 65
Romeo's stack is now:
90 88 66 45 79 51 116 52 105 102 115 116 67 57 97 98 80 112
118 99 114 80 114 73 55 117 114 114 53 110 118
```

# Act II: Enter The Side-Channel

By changing the number of "valid" password characters, I noticed that the number of pop operations on Romeo would change accordingly. What this means is that the crackme is most likely breaking out of its password validation loop early when it encounters a character that doesn't match the expected password.

Taking this one step further, what this means is that it's possible to count the number of pops on **Romeo** to determine if we have found the right password letter at a given position.

Time to turn this into a script!

## Scene I: A Thousand Snakes

I hacked together this script quickly to bruteforce the password. It has a bug for the last character as there will not be an extra comparison once all flag characters are found, but thankfully the flag turned out to be a sentence which made it easy to guess the last character.

```python
from pwn import *
from string import printable, ascii_letters, digits

ALPHA = ascii_letters + digits + '-'
LEN = 32
found = 'FLAG-'
for i in range(LEN - len(found)):
    for a in ALPHA:
        key = found + a + 'A'*(LEN - len(found) - 1)
        print(f'Bruteforce Pos={i} Candidate={key}')
        assert len(key) == LEN

        proc = process(['essay.exe'])
        proc.sendline(key)

        valid = 0
        try:
            while True:
                proc.recvuntil('Popping Romeo', timeout=3)
                valid += 1
        except:
            warning('timeout')
            pass

        proc.recvall()
        proc.close()
        valid -= 1  # Extra pop for failing comparison.
        print(f'Valid: {valid}')
        if valid > len(found):
            found = key[:valid]
        if valid == LEN:
            success(key)
            exit(0)
```
## Scene II: A Flag Appeareth

Running this script is fairly slow as it requires to launch a new instance of the essay.exe binary, input all known values of the password and then receive the debug output, counting the number of occurences of `Popping Romeo`.

Once it has successfuly run, though, we are left with the flag:

`FLAG-S3v3rityH1ghSucksAtS3cur1ty`

**FIN**