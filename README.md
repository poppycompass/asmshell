Assemblar Shell(asmshell)
==============

Assemblar Shell(asmshell) is a command line assembler emulator. 

You can easily check the execution result of the assembler.

Emulate all architecture implemented in unicorn engine.(Now x86/64 only)


Enjoy! :)

## Install

### Ubuntu
	$ ./install.sh

### Other Linux
NEED [Unicorn](https://github.com/unicorn-engine/unicorn) and [radare2](https://github.com/radare/radare2).

	$ git clone https://github.com/unicorn-engine/unicorn
	$ cd unicorn && ./make.sh
	$ sudo make install
	$ git clone https://github.com/radare/radare2
	$ cd radare2 && sys/install.sh

## Usage

### x86
	$ python ./asmshell.py
![x86 mode](https://github.com/poppycompass/asmshell/images/x86.jpg)


### diff mode(output changed register only)
	$ python ./asmshell.py -d
![x86 diff mode](https://github.com/poppycompass/asmshell/images/diff.jpg)

### x64
	$ python ./asmshell.py -a x64
![x64 mode](https://github.com/poppycompass/asmshell/images/x64.jpg)

### Support Function

- Input History(Ctrl-P/N)

- Clear line(Ctrl-U)

- Backspace(Ctrl-H/Backspace key)

## License

This tool is released under the [GPL license](COPYING)


## Author

poppycompass (t0g0v31dk at gmail dot com)
