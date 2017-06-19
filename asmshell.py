#!/usr/bin/env python
#-*- conding: utf-8 -*-
# register reference: include/unicorn/x86.h, qemu/target-i386/unicorn.c
from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
import os
import sys
import subprocess
import binascii
import argparse
import struct
import signal

CONFIG = os.path.abspath(os.path.expanduser(__file__))
if os.path.islink(CONFIG):
    print os.readlink(CONFIG)
    CONFIG = os.readlink(CONFIG)
sys.path.insert(0, os.path.dirname(CONFIG) + "/lib/")

# TODO: use arguments
parser = argparse.ArgumentParser(description='Assemblar Shell', formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('--arch', '-a', dest='arch', required=False, help='target architecture', default='x86')
args = parser.parse_args()

VERSION='0.01'
ADDRESS = 0x1000000
MEM_SIZE = 2 * 1024 * 1024 # 2MB
STACK_SIZE = 64
# from include/unicorn/x86.h
X86_REGS = [UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ECX,UC_X86_REG_EDX,UC_X86_REG_ESI,UC_X86_REG_EDI,UC_X86_REG_EIP, UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_EFLAGS,UC_X86_REG_CS,UC_X86_REG_SS,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_FS,UC_X86_REG_GS]

saved_state = [0] * 255 # 255 is random big value than number of registers
ESP_OFFSET=0x300000
saved_state[UC_X86_REG_ESP] = ADDRESS + ESP_OFFSET
saved_stack = [0] * STACK_SIZE

# change output color
def red(s,e="\n")         : print("\033[91m{}\033[00m".format(s), end=e)
def green(s,e="\n")       : print("\033[92m{}\033[00m".format(s), end=e)


def yellow(s,e="\n")      : print("\033[93m{}\033[00m".format(s), end=e)
def lightPurple(s,e="\n") : print("\033[94m{}\033[00m".format(s), end=e)

def purple(s,e="\n")      : print("\033[95m{}\033[00m".format(s), end=e)
def cyan(s,e="\n")        : print("\033[96m{}\033[00m".format(s), end=e)
def lightGray(s,e="\n")   : print("\033[97m{}\033[00m".format(s), end=e)
def black(s,e="\n")       : print("\033[98m{}\033[00m".format(s), end=e)
def white(s,e="\n")       : print("\033[00m", end=e)
def bold_green(s,e="\n")  : print("\033[92m\033[1m{}\033[00m".format(s), end=e)
def bold_yellow(s,e="\n")  : print("\033[93m\033[1m{}\033[00m".format(s), end=e)

def i386_emu(mode, code):
     # Initialize emulator
     mu = Uc(UC_ARCH_X86, mode)
     # map 2MB memory for this emulation
     mu.mem_map(ADDRESS, 2 * 1024 * 1024)
     # write machine code to be emulated to memory
     mu.mem_write(ADDRESS, code)
     # initialize stack
     mu.mem_map(ADDRESS+0x200000, 2 * 1024 * 1024) # if not call, "mem unmapped error" is rasied
     # recover saved state
     recover_saved_state(mu)
 
     # emulate machine code in infinite time
     mu.emu_start(ADDRESS, ADDRESS + len(code))

     # save registers value
     global saved_state, saved_stack
     for reg in X86_REGS:
         saved_state[reg] = mu.reg_read(reg)
     saved_stack = mu.mem_read(saved_state[UC_X86_REG_ESP], STACK_SIZE)

# assemble user input
def asm(intr):
    cmd = "rasm2 '%s'" %(intr)
    out = binascii.a2b_hex(
            subprocess.Popen(
              cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
              shell=True).communicate()[0].strip('\n')
             )
    return out

def help():
    print("output help")

def recover_saved_state(mu):
    for reg in X86_REGS:
        mu.reg_write(reg, saved_state[reg])
    mu.mem_write(saved_state[UC_X86_REG_ESP], struct.pack('d'*len(saved_stack), *saved_stack))

def print_saved_state():
    cyan("eax:    0x%08x" %saved_state[UC_X86_REG_EAX], "    ")
    cyan("eip:    0x%08x" %saved_state[UC_X86_REG_EIP])
    cyan("ebx:    0x%08x" %saved_state[UC_X86_REG_EBX], "    ")
    cyan("eflags: 0x%08x [ CF(%d) ZF(%d) SF(%d) ]" %(saved_state[UC_X86_REG_EFLAGS], 
        (saved_state[UC_X86_REG_EFLAGS]&0x1),
        (saved_state[UC_X86_REG_EFLAGS]>>6&0x1),
        (saved_state[UC_X86_REG_EFLAGS]>>7&0x1),
        ))
    cyan("ecx:    0x%08x" %saved_state[UC_X86_REG_ECX], "    ")
    cyan("cs:     0x%08x" %saved_state[UC_X86_REG_CS])
    cyan("edx:    0x%08x" %saved_state[UC_X86_REG_EDX], "    ")
    cyan("ss:     0x%08x" %saved_state[UC_X86_REG_SS])
    cyan("esp:    0x%08x" %saved_state[UC_X86_REG_ESP], "    ")
    cyan("ds:     0x%08x" %saved_state[UC_X86_REG_DS])
    cyan("ebp:    0x%08x" %saved_state[UC_X86_REG_EBP], "    ")
    cyan("es:     0x%08x" %saved_state[UC_X86_REG_ES])
    cyan("esi:    0x%08x" %saved_state[UC_X86_REG_ESI], "    ")
    cyan("fs:     0x%08x" %saved_state[UC_X86_REG_FS])
    cyan("edi:    0x%08x" %saved_state[UC_X86_REG_EDI], "    ")
    cyan("gs:     0x%08x" %saved_state[UC_X86_REG_GS], )
    esp = saved_state[UC_X86_REG_ESP] # tmp value
    bold_yellow("---------------- stack trace ----------------")
    for i in xrange(0, STACK_SIZE, 16):
        yellow("0x%08x: " %(esp+i), "")
        for j in xrange(0, 16, 4):
            yellow("%02x%02x%02x%02x " %(saved_stack[i+j+3], saved_stack[i+j+2], saved_stack[i+j+1], saved_stack[i+j]), "")
        yellow("|", "")
        for i in xrange(0, 16):
            if 0x20 <= saved_stack[i] and 0x7E >= saved_stack[i]:
                yellow("%c" %saved_stack[i], "")
            else:
                yellow(".", "")
        yellow("|")

def finish(signal, handler):
    print("\ngood bye:)")
    exit(1)

def main():
    signal.signal(signal.SIGTERM, finish)
    signal.signal(signal.SIGINT, finish)
    yellow("Emulate i386 code")

    arch="x86"
    while True:
        try: # catch Ctrl+d(input EOF)
            print("(%s)> " %(arch), end="")
            intr = raw_input().strip('\n')
            if "q" == intr or "quit" == intr or "exit" == intr:
                break
            user_code = asm(intr)
            if str(user_code) in "invalid":
                print("[!] invalid code")
                continue
            i386_emu(UC_MODE_32, user_code)

            print_saved_state()
        except EOFError:
            break
    finish(0, 0) # arguments are dummy

if __name__ == '__main__':
    main()
