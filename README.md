Mach-O Prettifier
=================

A Mach-O Load Command deobfuscator.

[Project Site](https://github.com/x43x61x69/Mach-O-Prettifier)

![Screenshot](https://dl.dropboxusercontent.com/s/udr3rh3lcsouvzh/Mach-OPrettifier.png)


Description
-----------

*The source code served as an example, it is, by no means, a commercial 
grade product. It might contain errors or flaws, and it was created for 
demonstration purpose only.*

Apple allows it's binary to run with incorrect load command names in the 
header, which is a great thing to prevent unnecessary error for the end 
users. However, this will break most of the debugging tools currently 
available on OS X. (IDA Pro, Hopper, gdb...etc.) Some malware might use this 
an anti-debugging trick. This tool will analyze the load command structures 
and try to restore it's original names so it can be debugged.

The following architectures are supported by Mach-O Prettifier:

* i386
* x86_64
* Fat (i386 + x86_64)

*PowerPC (PPC) is not support by this tool.*

To compile:

`clang mpfr.c -O2 -o mpfr`


Changelog
---------

v0.1:
* Initial release.


License
-------

Copyright (C) 2014  Cai, Zhi-Wei.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
