---
title: 'Anatomy of a Modern SPA: Part I - Project Setup'
tags:
  - Typescript
  - Vue
  - Express
  - Node
  - Tutorial
date: '2018-02-20 21:33:43'
---


The modern web can be very painful to approach with the seemingly endless
number of technologies and frameworks for solving the same problem. This series
aims to take a technical yet beginner-friendly dive into one possible
implementation of the end-to-end stack that makes up a modern SPA. The series
assumes at least some basic understanding of web development. More
specifically, this tutorial will not teach you how to program, and you should
be comfortable with at least the basics of Javascript, HTML, and CSS. While the
code examples should be fairly self-explanatory, the tutorial will not take you
through them line-by-line.

We will build a simple budgeting and financial goal application that uses Vue.js
for the Frontend (code that runs in your browser), Express.js for the backend
(code that runs on your web-server) and Typescript as the main programming
language for the entire stack. I picked Typescript because it is a superset of
Javascript that provides type safety and is seen more and more in large-scale
applications where many programmers work on the same code-base.

Along the way, we'll try to make our lives as easy as possible by setting up
a powerful development feedback loop with test-driven development, hot code
reloading to minimize the time we spend rebuilding the application and a
powerful packaging pipeline for our eventual production builds.


## Pre-requisites

- A working [node][1] environment along with `npm`.
- A working copy of [git][2].
- Basic knowledge of Javascript, HTML, and CSS.
- A drive to learn and a curiosity for how things work.
- Sufficient time and caffeine to power through.

All the code is versioned on my [github account][3] and it is highly recommended
that you follow the diff for commits labeled with `feat(tutorial)` at the very
least, since the tutorials will not list full file listings due to space
concerns.

[1]: https://nodejs.org/en/
[2]: https://git-scm.com/
[3]: https://github.com/alxbl/vue-express-ts-tutorial

## Before we Start

The tutorial will be split into multiple articles and the publishing schedule
will depend a lot on my free time and motivation.

If you find any issues or would like to complain, please open issues in the
tutorial's repository, as it will be the main way of tracking my backlog and
what people are interesting in reading about.

There is currently no fixed number of parts planned, although I do have a plan
for what I want to cover in the series. Parts will be cross-referenced at the
beginning of each article.

# Onwards!

In this part, we will outline the technologies that we plan to use for the
tutorial and setup the initial project structure and foundation. At the end of
this part, we will have a working backend API that can respond to basic `HTTP
GET` requests.

The next parts will focus on defining the application that we will work on in
the series: A simple financial goal/budgeting application.


## Creating the project

We'll start with the first and most important step of our journey. Find a clean
place on your harddrive and create a directory where we can put all our code. I
called mine `vue-express-ts-tutorial` because that's what I'm making. Now,
inside a terminal, navigate to that directory and initialize a bare git
repository:

```
$ git init
Initialized empty Git repository in /home/alex/dev/vue-express-ts-tutorial/.git/
```

Next, we'll initialize the node project.

```
$ npm init
```

npm will ask you a bunch of question. If you're simply following along, and do
not intend to publish this repository, feel free to mash enter until the very
end. Otherwise you may fill in the details as you see fit.

This creates a `package.json` file which will contains the list of libraries and
frameworks that our application depends on. We will also add some commands to
make testing and development easier.


## Install Project Dependencies

The best part about the web is that it's almost guaranteed that whatever you
need to do, somebody had to do the same thing and published a package to `npm`
that does exactly that. In this part we'll install a bunch of packages that we
will eventually need.

```
$ npm i --save-dev \
    webpack webpack-dev-middleware webpack-hot-middleware \
    webpack-hot-server-middleware \
    typescript \
    ts-loader \
    vuejs \
    express \
    @types/express
```

Here's what each of those packages is for. Don't worry if some of these look
like gibberish to you right now, we'll revisit each package in more detail as we
use it.

- *webpack*:  A tool that takes multiple code files, processes and optimizes
  them into compressed bundles that are faster to send to the browser. It also
  supports loaders which allow it to transform Typescript into Javascript.
- *webpack-middleware*: All of the middlewares will allow us to integrate
  webpack with our backend server in development mode.
- *typescript*: The TypeScript language and compiler.
- *ts-loader*: Allows webpack to load, compile, and bundle typescript code.
- *vuejs*: The frontend framework that we'll use.
- *express*: The backend framework that we'll use.
- *@types/express*: Typescript needs type information for Javascript libraries.

This is not a complete list, and we'll be installing more packages as our
application evolves. For now, these should do.

After the install completes, you'll notice that you have a new file called
`package-lock.json`. The purpose of this file is to keep a snapshot of the
version of each dependency that you installed. This file should be checked in to
source control and is useful to avoid running into versioning hell, which
happens when doing a clean package restore and getting incompatible versions.

If you're quick, you also noticed that `package.json` has now been updated with
a `devDependencies` section, that contains all the packages that we just
installed. These are dev dependencies because in a production environment, we
won't necessarily want any of those dependencies on the production web server,
since they'll have been bundled as part of our `webpack` build. More on this
later.

## Initialize TypeScript

The last thing we have to do before starting on our project's structure is to
initialize the TypeScript configuration file. Most likely, your computer does
not have the TypeScript compiler installed globally, so this can be done by
running the version that you just installed:

```
$ ./node_modules/.bin/tsc --init
message TS6071: Successfully created a tsconfig.json file.
```

And notice the `tsconfig.json` file that was just created. It is very well
commented and explains all the possible options you could want to play with.

## Directory Structure

Our application is going to be made up of three parts:

- The backend that will provide the API and serve the website over the internet.
- The frontend that will run the SPA in the client's browser.
- The common model that both backend and frontend will use.

It makes sense that the project's directory structure should follow that:

```
+-- vue-express-ts-tutorial/
|   |
|   +-- dist/ <-- The webpack bundles will go here.
|   |
|   +-- server/
|   |   |
|   |   +-- server.ts <--- Our server's main file.
|   +-- client/
|   |   |
|   |   +-- client.ts <-- Our client's main file.
|   +-- common/
|       |
|       +-- ...
+-- webpack.config.js <-- The webpack configuration (Next section)
+-- index.js <-- The entry point of the development server.
```

Go ahead and create the directory structure along with the listed empty files.


## Setting up Webpack

[Webpack][4] can be a little complex to approach at first due to its very modular
nature. By itself, webpack doesn't do much: it relies heavily on `plugins` and
`loaders` to do the heavy lifting of loading and processing various file
formats. You can think of webpack as the pipeline that processes and transforms
all of your assets so that they are ready for public consumption. These
transformations include removing comments, reducing the code's size and removing
unused code from your application. webpack also compresses your multiple code
files into one or more bundles that aim to reduce the number of files that need
to be sent from the server to the client. This translates to less connections
and thus faster page load times.

> With the advent of [HTTP2.0][5], bundles are likely to become less necessary due to
> persistent connections and data prefetching.

First and foremost, webpack needs a configuration file to tell it what resources
to process and how to process them. Let's create a simple configuration file in
the root of the project that we can later improve:

``` javascript
// vue-express-ts-tutorial/webpack.config.js

const path = require('path');

const RULES = [ // Configure the loaders.
  { test: /\.tsx?$/, use: 'ts-loader', exclude: /node_modules/ }, // Typescript.
];

const EXTENSIONS = ['.ts', '.tsx', '.js', '.json']; // Extensions to process.

const OUTPUT = path.resolve(__dirname, './dist'); // Webpack output directory.

module.exports = [
  {
    name: 'client',
    entry: './client/client.ts',
    target: 'web', // Client will run in the web browser.

    module: { rules: RULES },

    resolve: { extensions: EXTENSIONS },
    output: {
      filename: 'client.js',
      path: OUTPUT,
      publicPath: '/'
    }
  },
  {
    name: 'server',
    entry: './server/server.ts',
    target: 'node', // server is going to run on node

    module: { rules: RULES },
    // Defines which files to try bundling.
    resolve: { extensions: EXTENSIONS },

    output: {
      filename: 'server.js',
      path: OUTPUT,
      publicPath: '/',
      libraryTarget: 'commonjs2' // Important for webpack-hot-server-middleware.
    }
  }
];

```

This configuration file basically tells webpack that it should use `ts-loader`
to process any Typescript files that it encounters. It also specifies where to
find our frontend and backend's entry points. Lastly, it configures the
destination directory of the processed bundles.

Now it should be possible to run webpack to build our application... except that
we don't have an application to build yet! Let's remedy that in the next
section.

We'll actually take a quick detour to setup a script in `package.json` so that
we can run the command `npm run build` to trigger a build of our application.

Open the `package.json` file and find the `scripts` section, and add the
following [line][6]:

``` javascript
{
  // ... snip
  "scripts": {
    "build": "webpack", // <-- This line.
    "test": "..."
  },
  // ... snip
}
```

Now we are ready to test a build of our very limited (read: non-existant)
application.

```
$ npm run build
> vue-express-ts-tutorial@1.0.0 build ~/dev/vue-express-ts-tutorial
> webpack

Hash: 9565e6fce1806aa9d64343f6960e03778b7eb14d
Version: webpack 3.11.0
Child client:
    Hash: 9565e6fce1806aa9d643
    Time: 902ms
        Asset     Size  Chunks             Chunk Names
    client.js  2.51 kB       0  [emitted]  main
       [0] ./client/client.ts 14 bytes {0} [built]
Child server:
    Hash: 43f6960e03778b7eb14d
    Time: 893ms
        Asset     Size  Chunks             Chunk Names
    server.js  2.53 kB       0  [emitted]  main
       [0] ./server/server.ts 14 bytes {0} [built]
```

You should be seeing this output or similar. It gives you a bunch of information
about what each file webpack processed and how long the process took. If there
are any build errors or warning, you will see those here as well.

> Ideally you should never have warnings or errors, to make sure you don't miss
> important warnings or errors that could lead to problems in the future.
> Unfortunately, some packages will cause warnings that are out of your control
> from time to time, but you should strive to keep your build output as clean as
> possible.

[4]: https://webpack.js.org
[5]: https://en.wikipedia.org/wiki/HTTP/2
[6]: https://github.com/alxbl/vue-express-ts-tutorial/blob/master/package.json#L7

## Setting up the Backend

Now that webpack knows how to build our project, we can wrap things up by setting
up a single route and finally displaying something in the browser.

The way that [expressjs][7] works is through `route handlers` that dictate what
should happen when the browser hits a specific address over HTTP. We'll dive
into a lot more details in the next part of this tutorial, but for now take this
code as a very simple example.

``` typescript
// vue-express-ts-tutorial/server/server.ts
import express from 'express';

const app = express();

app.get("/", (request, response) => {
  response.send("Hello TypeScript + Express!");
  console.log("Client browsed to /!");
});

app.listen(3000, () => {
  console.log("Express is listening on port 3000...");
});
```

And now we can build our application:

```
$ npm run build
```

> You might get a build [warning][8] from express here. We'll live with it for
> now. This happens because express should not be part of your bundle. We will
> revisit this when packaging for production.

You should now be able to run your server manually like this:

```
$ node dist/server.js
```

Navigate to https://localhost:3000/ and you should see "Hello TypeScript +
Express!".

[7]: https://expressjs.com
[8]: https://github.com/webpack/webpack/issues/1576

## Conclusion

This concludes the first part of this series. Congratulation on your first steps
towards the wonderful world of modern web development. Don't worry if things are
still unclear or hazy, everything should start making more sense as we progress
through the series.

While we did not get too much done in terms of our application, we've covered a
lot of ground towards a working development environment.

In the next section, we'll focus on streamlining our development experience with
hot reloading and take our first steps towards the frontend of our application.
We'll set up a server that automatically reloads the code as we modify the files
and lets us see our changes in the application immediately.

Let me know if you ran into any trouble with this tutorial, or if you have any
comments or feedback.
