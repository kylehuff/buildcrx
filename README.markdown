buildcrx
========
buildcrx v0.1 Oct 2010

Copyright (c) 2010 Kyle L. Huff


Description
-----------
Standalone binary for Windows/Linux to RSA sign and pack a zip-file containing chrome extension data.

(this utility does not require the chrome/chromium binary, it can run standalone on a build-system)

Statically includes libssl from the OpenSSL project.


Running/Options
---------------
buildcrx accepts 3 arguments -
* The zipfile (a normal zipfile containing the contents of your extension directory)
* The Private Key file used for signing in PEM format.
* The output path to place the signed .crx packed extension - if the output path is not specified it will create the .crx file in the same directory as the zipfile.

    buildcrx <ZIP file> <PEM file> (optional <OUTPUT PATH/FILE>)


Building
--------
To cross-compile this utility for windows on linux using mingw, simply execute:

    make CC=i586-mingw32msvc-gcc

To build on a windows machine, either modify the makefile to your needs, or in this directory just run:

    gcc -L libs/openssl -I include/openssl/winnt_x86-msvc -g -Wall -o bin/winnt_x86-msvc/buildcrx.exe buildcrx.c -lm -DDEBUG -lcrypto -lgdi32

Then copy bin/winnt_x86-msvc/buildcrx.exe to where you want to use it.


OpenSSL
-------
OpenSSL version 1.0.0a

Compiled linux libraries using gcc with configure flags: "no-idea no-mdc2 no-rc5"

Cross-compiled windows dlls using mingw with configure flags "no-idea no-mdc2 no-rc5 static mingw:i586-mingw32msvc-gcc"
