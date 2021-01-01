---
title: Be wary of C++ Variadic Templates and Side Effects
date: '2018-01-02 22:21:12'
tags:
    - C++
    - 3D Programming
---

I recently started playing with OpenGL as a little side project. In the process,
I was following a very nice tutorial website called [LearnOpenGL][1] and dusting
off my linear algebra books for a while. Eventually I felt comfortable enough to
start writing my own little application.

Of course, I also have not been coding C++ for a number of years, so I decided
that this was a good opportunity to get back into my old habits. Little did I
know that I was about to hit a very hard snag.

[1]: https://learnopengl.com

## Variadic Templates

In a nutshell, these beautiful constructs allow strong typing on a variable
number of arguments, similar to how `C` does it with the ellipsis operator.
They enable very nice language features such as the clean `emplace` call for
containers, which allows for in-place construction of types.

In practice, their declaration looks something like this:

``` C++
template<class... Args>
void do_something(int non_variadic, Args... variable_args)
{
    // ...
}
```

That being said, the point of this post is not to dive into variadic templates,
so if you're not too familiar and would like to read up on them, head over to
[cplusplus][2].

[2]: http://www.cplusplus.com/articles/EhvU7k9E/

## The "Clever" Code

I decided to be a bit clever (always a bad sign!) while parsing a model's
vertices, and wrote the following bit of code:

``` C++
ByteStream fd("path/to/model.bin");

// ... a little bit of parsing later ...

std::vector<vec3> vertices;
vertices.reserve(num_vertices); // `num_vertices` comes from the model file.

for (auto i; i < num_vertices; ++i)
    vertices.emplace_back(fd.read_float(), fd.read_float(), fd.read_float());

// ... continue parsing the model ...
```

This code looks nice enough: We pre-allocate a vector with enough space for all
the model vertices, then we parse them straight from the file's byte stream
straight into the vector through the magic of `emplace` and variadic templates.

... or is that so? If, unlike me, you haven't taken a break from C++, you might
know exactly what the problem is, otherwise, read on.

## The Ugly Models

After the parser was done, I started playing around with model instancing and a
bunch of transformation matrices, and quickly realized that what I thought I was
doing and what OpenGL was showing me were two different things.

A lot of head scratching ensued, and after way too many hours of debugging, I
realized that my X and Z coordinates on vertices were inverted. Being fairly new
to 3D programming, I suspected that I was misusing [GLM][3] or doing my
transformations out of order.

Cue a three day long debugging streak that has me tearing my hair out and
chugging way too much coffee, and I'm desperately running out of leads. I've
gone over the math by hand, inspected the GLM source code, it can't be my
transforms. They're all fine.

But the parser is so straight forward, there's no way it can be that... can it?

[3]: https://glm.g-truc.net

## The Breakthrough

A long time ago, when C++11 was very new, I remember watching a Going Native
talk that discussed Tuple types in C++ and went into a lot of depth on template
metaprogramming. One of the tidbits of trivia that I had found interesting and
promptly forgotten about was that when doing variadic tuples, the technique
involved template recursion, where the internal representation has the
user-value along with a nested tuple type of size `N-1` where `N` is the total
number of arguments the user provides.


Of course this is all hidden from the programmer, and it just works. Until it
does not.

It turns out that because of the recursion, the tuple type is instanciated in
reverse order. As soon as I remembered, I went to my parser and replaced the
`emplace_back` call with a more lengthy

```C++
vec3 v;

v.x = fd.read_float();
v.y = fd.read_float();
v.z = fd.read_float();

vertices.push_back(v);
```

and everything started working.

## Side Effects Are the Problem

What was happening in my code was that the `fd.read_float()` call had a side
effect of moving the byte stream forward. Normally, this wouldn't matter, but in
this case, because of the variadic template recursion, it caused the parser to
read the first float in the file when setting the `Z` component, the second then
went to `Y`, which was unchanged and finally `X` had the value of the Z
coordinate.

So there you have it. Almost four days of debugging, only to recall something I
had learned in 2011 and forgotten about.

---

I guess the bottom line is that side effects are bad, and that we should be very
careful with them, otherwise very subtle little bugs like this can creep up from
nowhere.
