# Assemblar Shell
Command line assembler emulator. NEED UNICORN(https://github.com/unicorn-engine/unicorn) and radare2(https://github.com/radare/radare2)
Emulate all architecture implemented in unicorn engine.(Now x86/64 only)

## Install
  ./install.sh
## Usage

### x86
$ python ./asmshell.py
> xor eax,eax

### diff mode(output changed register only)
$ python ./asmshell.py -d

### x64
$ python ./asmshell.py -a x64
> mov rax, 0x4142434445464748  
> push rax

### command history
Use Ctrl-P/N
