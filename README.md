Assembler Shell(asmshell)
==============

Assembler Shell(asmshell) is a command line assembler emulator. 

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
	$ sudo python unicorn/bindings/python/setup.py install
	$ git clone https://github.com/radare/radare2
	$ cd radare2 && sys/install.sh

## Usage

### x86
	$ python ./asmshell.py
![x86 mode](https://github.com/poppycompass/asmshell/blob/master/images/x86.jpg)


### diff mode(output changed register only)
	$ python ./asmshell.py -d
![x86 diff mode](https://github.com/poppycompass/asmshell/blob/master/images/diff.jpg)

### x64
	$ python ./asmshell.py -a x64
![x64 mode](https://github.com/poppycompass/asmshell/blob/master/images/x64.jpg)

### Support Function

- Input History(Ctrl-P/N)

- Clear line(Ctrl-U)

- Backspace(Ctrl-H/Backspace key)

## Trouble Shooting

### UserWarning: .python-eggs is writable
If you have warnings such as 
```
/usr/lib/python2.7/dist-packages/pkg_resources.py:1031: UserWarning: /home/vagrant/.python-eggs is writable by group/others and vulnerable to attack when used with get_resource_filename. Consider a more secure location (set with .set_extraction_path or the PYTHON_EGG_CACHE environment variable).
```
, run this command.
```
$ chmod g-wx,o-wx ~/.python-eggs
```

## Contribution


## License

The software in this repository is covered by the MIT license[the MIT license](LICENSE).


## Author

poppycompass (t0g0v31dk at gmail dot com)
