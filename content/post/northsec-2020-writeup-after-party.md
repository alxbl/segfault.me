---
title: 'NorthSec 2020 Writeup: After Party'
date: '2020-05-20 08:57:56'
tags:
  - CTF
  - Writeup
  - Reverse
description: 'Write-up for the NorthSec 2020 CTF challenge "After Party", a Java/JNI reverse engineering problem.'
---

*This post outlines the solution to NorthSec 2020's After Party challenge and includes both flags.*


# Context

You are given a zip file, which when unzipped contains the following:

    afterparty.jar
    afterparty.so
    run.sh


Looking into the jar with `unzip -l afterparty.jar`, it contains the following files:

    Archive:  afterparty.jar
    Length     Date       Time    Name
    ---------  ---------- -----   ----
        63     2020-05-03 14:17   META-INF/MANIFEST.MF
        0      2020-05-03 14:17   prom/
        2024   2020-05-03 11:56   prom/Bootstrap.class
        149    2020-05-03 10:17   prom/IValidator.class
        1464   2020-05-03 14:17   prom/Main.class
        1637   2020-05-03 14:17   prom/Validator.class
    ---------                     -------
        5337                     6 files


# Flag 1: Java Decompilation

The next step is to open the Java application in a decompiler to understand what it's doing. I used [jd-gui][1].

![JD-GUI decompiler](jd-gui.png)

The natural starting point is `Main.main` which is the application's entry point. The code looks like the following:

```java
package prom;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Main {
  public static void main(String[] args) throws Exception {
    System.out.print("Password : ");
    BufferedReader buffer = new BufferedReader(
        new InputStreamReader(System.in)
    );
    String pass = buffer.readLine();
    pass = pass.strip();
    if (pass.equals("FLAG-XXXXXXXXXXXXXXXXXXXXX")) {
      System.out.println("You can enter the party !");
      return;
    }
    IValidator validator = Bootstrap.<IValidator>get(
        IValidator.class
    );
    if (validator.validate(pass)) {
      System.out.println("You can enter the secret place !");
    } else {
      System.out.println("You won't get in with that password !");
    }
  }
}
```

[1]: https://java-decompiler.github.io/

Right off the bat, we see on lines `8-16` that the password is being checked against a flag. That's flag 1/2 in the challenge. Beyond that, though there is an extra validation step that checks whether you are allowed to the "secret" place.


# Flag 2: JNI-assisted Validator

In order to understand this one, we need to dive into line 18: `Bootstrap.<IValidator>get(IValidator.class).

```java
package prom;

import java.io.File;

public class Bootstrap extends ClassLoader {
  private static Bootstrap _inst = new Bootstrap();

  static {
    File f = new File(System.getProperty("java.class.path"));
    File dir = f.getAbsoluteFile().getParentFile();
    File mod = new File(dir, "afterparty.so");
    System.load(mod.getAbsolutePath());
  }

  public static <T> T get(Class<T> clazz) throws Exception {
    String name = clazz.getName();
    int pos = name.lastIndexOf(".") + 1;
    String beginning = name.substring(0, pos);
    String last = name.substring(pos);
    last = last.replaceFirst("I", "");
    Class<T> inst = _inst.findClass(String.valueOf(beginning) + last);
    return inst.newInstance();
  }

  public native Class findClass(String paramString) throws ClassNotFoundException;
}
```

We can see that the code is going to load `afterparty.so` and modify the class name to remove the `I` prefix (making it `Validator`) and then calls the Java Native Interface (JNI) function `findClass`. Looking at `Validator.class`, the decompiler is spitting out an internal error, and we can't seem to read the code.

It looks like we have to dive into the shared object and look at what `findClass` is doing. To do that, we pop `afterparty.so` into Ghidra and locate the mangled `findClass` function. According to the JNI spec, the exported function name must be something like `Java_package_class_method`, so we filter the function list by `Java` and find `Java_prom_Bootstrap_findClass`. That looks right.

![Exported JNI function](jni-export.png)

Now looking at the disassembly of this function is a bit messy because JNI exposed native functions to interact with the Java VM. Understanding all the native functions and API is time consuming and not necessary. We can guestimate by looking at the strings being called. Here's the Ghidra decompiler output, with the interesting bits highlighted:

![Reversing the findClass function](jni-reverse.png)


In step `1`, the method `java.io.Inputstream.getResourceAsStream` is retrieving the class name from the `.jar`. Then, in step `2`, the stream is read with `InputStream.read`, which returns the total number of bytes read (`total_size`). Finally, a buffer is allocated and then in step `3` there is a loop which seems to update a key and performs a `XOR` over the `dst` buffer. One of those calls after the `malloc` is likely performing a `memcpy` at the JVM level, so we just take a guess and run with it.

Getting this code to run is quite difficult since the Java Archive needs to be repacked and existing Java tooling makes it difficult to debug a `.jar` without having the original sources. Instead, we re-implement the simple decryption loop in Python and recover the decrypted `.class`:


```python
with open('Validator.class', 'rb') as f:
    data = f.read()

CLASS = 'prom.Validator'
KEY = len(data) + 0x1264ec8
out = []
for i in range(len(data)):
    KEY = (KEY * 0xd + 0xbeb0 + len(CLASS)) & 0xFFFFFFFF
    b = data[i] ^ (KEY & 0xFF)
    out.append(b)

with open('out.class', 'wb') as o:
    o.write(bytes(out))
```

Lastly, we create a new `afterparty.jar` with the `Validator.class` replaced by our decrypted version and open the resulting archive in `jd-gui` to decompile the validation code:

```java
package prom;

import java.util.regex.Pattern;
import prom.IValidator;

public class Validator implements IValidator {
  public boolean validate(String flag) {
    if (!flag.startsWith("FLAG-"))
      return false;
    if (flag.length() != 25)
      return false;
    Pattern pattern = Pattern.compile("^FLAG-[a-f0-9]+$");
    if (!pattern.matcher(flag).matches())
      return false;
    String rest = flag.substring(5);
    int code1 = rest.substring(0, 2).hashCode();
    int code2 = rest.substring(2, 4).hashCode();
    int code3 = rest.substring(4, 6).hashCode();
    int code4 = rest.substring(6, 8).hashCode();
    int code5 = rest.substring(8, 10).hashCode();
    int code6 = rest.substring(10, 12).hashCode();
    int code7 = rest.substring(12, 14).hashCode();
    int code8 = rest.substring(14, 16).hashCode();
    int code9 = rest.substring(16, 18).hashCode();
    int code10 = rest.substring(18, 20).hashCode();
    if (code1 + code2 + code3 + code4 + code5 + code6 + code7 + code8 + code9 + code10 != 22998)
      return false;
    if (code1 != 1821)
      return false;
    if (code2 != 1604)
      return false;
    if (code3 != 1802)
      return false;
    if (code4 != 1691)
      return false;
    if (code5 != 1867)
      return false;
    if (code6 != 3140)
      return false;
    if (code7 != 3186)
      return false;
    if (code8 != 3180)
      return false;
    if (code9 != 1570)
      return false;
    if (code10 != 3137)
      return false;
    return true;
  }
}
```

Oh, so it looks like we have to bruteforce some hashcodes two characters at a time in order to recover the flag. The important point here is to note the regular expression which limits the character set to `a-f0-9`. Failing to notice that will yield a lot of non-sensical flags because of hashcode collisions.

The easiest way to bruteforce this is in Java since there is no need to re-implement `hashCode()`:

```java
package afterp;

import java.util.regex.Pattern;
import java.util.ArrayList;
import java.util.Arrays;

public class AfterParty {
    public static String Good = "0123456789abcdef";
    public static void main(String[] args) {
        ArrayList<Integer> x = new ArrayList<Integer>(
            Arrays.asList(
                1821, 1604, 1802, 1691, 1867,
                3140, 3186, 3180, 1570, 3137
            )
        );

        var flag = "";
        var found = false;
        for (int c = 0; c < 10; ++c) {
            found = false;
            for (
                var b = 0;
                b < AfterParty.Good.length();
                ++b
            ) {
                for (
                    var a = 0;
                    a < AfterParty.Good.length();
                    ++a
                ) {

                    String match = Character.toString(
                        AfterParty.Good.charAt(b)) +
                        Character.toString(
                            AfterParty.Good.charAt(a)
                        )
                    );

                    if (match.hashCode() == x.get(c)) {
                        flag += match;
                        found = true;
                    }
                    if (found) break;
                }
                if (found) break;
            }
        }

        System.out.println("FLAG-" + flag);
        System.out.println(validate("FLAG-" + flag));
    }
}
```

I haven't coded in Java since 2012, so please forgive my non-idiomatic Java. Suffice to say that the code works and we get the last flag of the track.

Cheers!