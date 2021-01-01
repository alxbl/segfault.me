---
title: Why I rewrote my blog (yet again) in Hexo
date: '2017-12-11 20:54:46'
tags:
  - Meta
---

Every time I pick up some new technology it always seems like I end up wanting
to rewrite my website in said technology as some sort of futile learning
exercise. What seems to happen instead is that after I reach a semi functional
point and get to reimporting my blog roll, I either understand the technology
well enough that it's time to start using it elsewhere or I get
bored/distracted and never finish the rewrite.

The problem is that I want my website to be my goto medium to share my thoughts
and notes on various things that I'm working on. Over the nearly four years
that segfault has displayed that pesky "Still working on it" which mentioned me
being too busy with life to have time to work on my website, I've had ample
time to think about why it was that I never found time to finish the rewrite.
This article is my attempt to put my personal insight down and hopefully help
another fellow "busy" person get their website out of the way of their
blogging.

# A website as a project is the wrong approach

The biggest conclusion I've come to is that I've always treated my website as a
project as opposed to the platform and identity I have wanted it to be. Let's
face it, though. As software developers we already spend at least 40 hours a
week jumping through hoops and fixing j related problems to make something do
what we want. At the end of the day, having to learn a new stack and APIs to
implement something like a blog roll is just another extra distraction away
from doing what I actually want to be doing, which is writing my blog and
working on my other projects.

I don't need my website to be another project.

# Complexity that Distracts from the Purpose

I have no interest in writing a Content Management System, in dealing with
comment management and moderation, nor do I have any interest in implementing a
blogging engine. Why, then, do I spend so much time on implementing these
arguably complex (here, tedious is a more appropriate word) and yet very basic
features?

All that is truly needed is a dead simple platform to publish content.

# Settling on Hexo

I came across the framework while looking into alternatives to the popular
Jekyll framework written in Ruby.

Lately I've been doing a lot of TypeScript and Angular web development for
work, and in the interest of staying in the same ecosystem, I felt that
sticking to Javascript would lessen the transition time to get something up and
running. Microsoft Azure also supports Nodejs out of the box with their
WebApps, which means I can enjoy the Azure ecosystem while remaining
crossplatform without pulling mono as a dependency.

I picked Azure as a platform because of their monthly developer credits, and
because I have a significant amount of experience with the platform from my
full time work.

It's always good to know that I can switch back to a plain old Linux VPS if my
situation was to change.

# The Good Behind Static Websites

In this day and age of ever growing abstractions and booming software
complexity, I felt the need to keep my personal website as fuss-free as
possible to narrow the focus down specifically to exactly what my needs are: A
platform to publish my blog, projects and notes, as well as establishing my
presence on the internet, similar to analog business cards.

There are other nice to have benefits which are not part of my decision but are
nice to have regardless:

- Can be deployed anywhere where a web server can run
- Benefit greatly from content caching at the browser level without any
  reverse proxy
- No backend code running means a much smaller attack surface
- No frontend Javascript script framework means light pages and faster load times
- Very small code footprint

# Customizing

Hexo provides a very easy to customize theme framework, which lets me design my
own template for the site. This makes it trivial to write a nice custom theme
that looks exactly like what I want and provides nothing more and nothing less
in terms of code.

It is also possible to add generator plugins that extend the capabilities of
the generator. Although I haven't written my own generator plugins at the time
of writing this, I am using the wonderful hexo-generator-feed plugin to
generate the RSS feed.

# Automation

It is trivial to setup git WebHooks to automatically update and regenerate the
content whenever a new commit is pushed to master. To top that off, hexo's
generator is smart enough to only generate files that have changed and leave
the other files alone.

In cases where git hooks are not feasible or Nodejs doesn't exist on the target
server, it is still trivial to duct tape together a "deployment system" that
generates locally and then uses rsync or scp to publish the website. This can
be tied together by a post-push hook to achieve the same effect.

# The Way Ahead

Now that I no longer need to worry about feeling the need to rewrite my website
every time I play with a new technology, I will hopefully start blogging about
those new technologies, issues that I've encountered, tales from debugging and
other software related rambling.

As a little side note, since moving back from Japan, I've picked a rather fun
hobby called triathlon, so expect some related content once in a while.

