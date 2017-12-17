Assembler Shell(asmshell)
==============

Assembler([Keystone-Engine](http://www.keystone-engine.org/)) + Emulator([Unicorn-Engine](http://www.unicorn-engine.org/)) + interactive cli library([ishell](https://github.com/abiosoft/ishell)) = Text-base Assembler Emulator

Assembler Shell(asmshell) is a Text-base assembler emulator.

You can easily check the execution result of the assembler.

Enjoy! :)

## Feature
Multi-architecture support(depends on unicorn/keystone-engine)

	Assemble & emulation          : i8086, x86, x64, arm-thumb(be), arm(be), arm64, mips(be), mips64(be), sparc, sparc64
	Assemble only                 : powerpc, powerpc64(le), sparcle, systemZ
	Future support                : arm64be, m68k

Useful functions

	Shell like commands           : fragments, run linux commands...etc
	Handled like a shell          : Ctrl-P/Ctrl-N, Ctrl-A/Ctrl-E, Ctrl-H/Ctr-D...etc
	Cross Platform(depends on go) : *NIX, OSX, Windows
	APIs                          : see go/examples

## Install
Needs Go language and unicorn-engine and keystone-engine. 

<!-- If you are windows user, you can use [pre-compiled binary](https://github.com/poppycompass/asmshell/prebuild). -->

### Dependencies

1. Install [Go(version 1.6 or later)](https://golang.org/dl/) and [CMake](https://cmake.org/download/)

2. Install unicorn-engine

	`$ git clone https://github.com/unicorn-engine/unicorn`  
	`$ cd unicorn && ./make.sh`  
	`$ sudo make install`  

3. Install keystone-engine

	`$ git clone https://github.com/keystone-engine/beta/bindings/go/keystone`  
	`$ mkdir build && cd build`  
	`$ ../make-share.sh`  
	`$ sudo make install`  
	`$ sudo ldconfig # if you use OSX, "sudo update_dyld_shared_cache"`  

4. Build asmshell

	`$ git clone https://github.com/poppycompass/asmshell`  
	`$ cd asmshell && make`  
	`$ ./asmshell.exe -h`  


## Usage

### Help
	$ ./asmshell.exe [-h/--help]

### x86
	$ ./asmshell.exe
![x86 mode](https://github.com/poppycompass/asmshell/blob/master/images/x86.jpg)

### x64
	$ ./asmshell.exe -a x64
![x64 mode](https://github.com/poppycompass/asmshell/blob/master/images/x64.jpg)


## Tutorial

### Fragment Commands(Example: Symbol, encrypt)
You can register mnemonic fragments.

	$ ./asmshell.exe
	(x86)> fragment symbol # register from input
	in> mov ecx, 0x20
	... l1:
	... inc eax
	... dec ecx
	... jnz l1; # ';' is end the register
	'symbol` is registered
	(x86)> fragment show # show registered fragments. If you want show specify fragments, run this -> 'fragment show <name1> <name2>...'
	'symbol'
	    l1:
	    inc eax
	    dec ecx
	    jnz l1
	(x86)> fragment run symbol

If you have these codes.

	$ cat xor.txt
	xor ax, cx
	$ ./asmshell.exe
	(x86)> f encrypt encrypt.txt # register from file. 'f' is alias of fragment
	(x86)> f s encrypt           # 'f s' is alias of 'fragment show'
	(x86)> f r encrypt           # fragment run encrypt


### Change Architecture

	$ ./asmshell.exe
	(x86)> set # show available architecture
	Usage: set <arch>
	Supported: i8086, x86, x64, arm-thumb(be), arm(be), arm64, mips(be), mips64(be), sparc(le), sparc64, [ppc|powerpc], [ppc64(le)|powerpc64(le)], [sysz|systemz|systemZ]
	(x86)> set arm
	(arm)>

### Run shell command(now linux & mac only)
	$ ./asmshell.exe
	(x86)> !ls -lga

## Available Shell Commands
	help                       : display help
	fragment [run/show/delete] : register/run/show/delete fragment
	!<cmd>                     : run shell commands
	set <arch>                 : set architecture and mode
	exit/quit/q                : exit the program


## Contribution
I am not an architectual expert. Therefore, I think there are many bugs and strangeness in this program.
If you want to contribute, please pick up something from our [Github issues](https://github.com/poppycompass/asmshell/issues).
We also maintain a list of more challenged problems in a TODO.txt.


## License

The software in this repository is covered by [the MIT license](LICENSE).


## Author

poppycompass (t0g0v31dk at gmail dot com)
