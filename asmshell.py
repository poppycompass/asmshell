#!/usr/bin/env python
#-*- conding: utf-8 -*-
# register reference: include/unicorn/x86.h, qemu/target-i386/unicorn.c
# TODO: impl context diff(for output changed register only)
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

LIB = os.path.abspath(os.path.expanduser(__file__))
if os.path.islink(LIB):
    CONFIG = os.readlink(LIB)
sys.path.insert(0, os.path.dirname(LIB) + "/lib/")
from config import *
from utils import *

# TODO: use arguments
parser = argparse.ArgumentParser(description='Assemblar Shell', formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('--arch', '-a', dest='arch', required=False, help='target architecture(default: x86)', default='x86')
args = parser.parse_args()

if args.arch == 'x86':
    ARCH = UC_ARCH_X86
else:
    ARCH = UC_ARCH_X86
MODE = UC_MODE_32
# UNUSED, from include/unicorn/x86.h
regs = X86_REGS

saved_stack = [255] * STACK_SIZE

# retrun dummy context
def init_saved_context():
     mu = Uc(ARCH, MODE)
     mu.mem_map(ADDRESS, 2 * 1024 * 1024)
     mu.reg_write(UC_X86_REG_ESP, ADDRESS + ESP_OFFSET)
     return mu.context_save()

def i386_emu(code, saved_context):
    # Initialize emulator
    mu = Uc(ARCH, MODE)
    # map 2MB memory for this emulation
    mu.mem_map(ADDRESS, 2 * 1024 * 1024)
    # write machine code to be emulated to memory
    mu.mem_write(ADDRESS, code)
    # initialize stack
    mu.mem_map(ADDRESS+0x200000, 2 * 1024 * 1024) # if not call, "mem unmapped error" is rasied

    # recover saved state
    mu.context_restore(saved_context)

    global saved_stack
    #stack_addr = mu.reg_read(UC_X86_REG_ESP)-MERGIN_OFFSET
    stack_addr = ADDRESS + ESP_OFFSET - MERGIN_OFFSET
    mu.mem_write(stack_addr, struct.pack('B'*len(saved_stack), *saved_stack))
    # emulate machine code in infinite time
    mu.emu_start(ADDRESS, ADDRESS + len(code))

    # save context(regs, stack)
    saved_stack = mu.mem_read(stack_addr, STACK_SIZE)
    return mu.context_save()

# assemble user input
def asm(intr):
    cmd = "rasm2 '%s'" %(intr)
    out = binascii.a2b_hex(
            subprocess.Popen(
              cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
              shell=True).communicate()[0].strip('\n')
             )
    return out

def print_context(saved_context):
    saved_mu = Uc(ARCH, MODE)
    saved_mu.mem_map(ADDRESS, 2 * 1024 * 1024)
    saved_mu.mem_map(ADDRESS+0x200000, 2 * 1024 * 1024) # if not call, "mem unmapped error" is rasied
    saved_mu.context_restore(saved_context)
    bold_cyan("---------------- cpu context ----------------")
    cyan("eax:    0x%08x" %saved_mu.reg_read(UC_X86_REG_EAX), "    ")
    cyan("eip:    0x%08x" %saved_mu.reg_read(UC_X86_REG_EIP))
    cyan("ebx:    0x%08x" %saved_mu.reg_read(UC_X86_REG_EBX), "    ")
    cyan("eflags: 0x%08x [ CF(%d) ZF(%d) SF(%d) ]" %(saved_mu.reg_read(UC_X86_REG_EFLAGS),
        (saved_mu.reg_read(UC_X86_REG_EFLAGS)&0x1),
        (saved_mu.reg_read(UC_X86_REG_EFLAGS)>>6&0x1),
        (saved_mu.reg_read(UC_X86_REG_EFLAGS)>>7&0x1),
        ))
    cyan("ecx:    0x%08x" %saved_mu.reg_read(UC_X86_REG_ECX), "    ")
    cyan("cs:     0x%08x" %saved_mu.reg_read(UC_X86_REG_CS))
    cyan("edx:    0x%08x" %saved_mu.reg_read(UC_X86_REG_EDX), "    ")
    cyan("ss:     0x%08x" %saved_mu.reg_read(UC_X86_REG_SS))
    cyan("esp:    0x%08x" %saved_mu.reg_read(UC_X86_REG_ESP), "    ")
    cyan("ds:     0x%08x" %saved_mu.reg_read(UC_X86_REG_DS))
    cyan("ebp:    0x%08x" %saved_mu.reg_read(UC_X86_REG_EBP), "    ")
    cyan("es:     0x%08x" %saved_mu.reg_read(UC_X86_REG_ES))
    cyan("esi:    0x%08x" %saved_mu.reg_read(UC_X86_REG_ESI), "    ")
    cyan("fs:     0x%08x" %saved_mu.reg_read(UC_X86_REG_FS))
    cyan("edi:    0x%08x" %saved_mu.reg_read(UC_X86_REG_EDI), "    ")
    cyan("gs:     0x%08x" %saved_mu.reg_read(UC_X86_REG_GS), )
    esp = saved_mu.reg_read(UC_X86_REG_ESP) # tmp value
    #stack_addr = esp-MERGIN_OFFSET
    stack_addr = ADDRESS + ESP_OFFSET - MERGIN_OFFSET
    bold_yellow("---------------- stack trace ----------------")
    global saved_stack
    for i in xrange(0, STACK_SIZE, 16):
        yellow("0x%08x: " %(stack_addr+i), "")
        for j in xrange(0, 16, 4):
            if (stack_addr+i+j) == esp:
                red("%02x%02x%02x%02x " % \
                        (saved_stack[i+j+3], \
                         saved_stack[i+j+2], \
                         saved_stack[i+j+1], \
                         saved_stack[i+j],   \
                        ), "")
            else:
                yellow("%02x%02x%02x%02x " % \
                        (saved_stack[i+j+3], \
                         saved_stack[i+j+2], \
                         saved_stack[i+j+1], \
                         saved_stack[i+j],   \
                        ), "")
        yellow("|", "")
        for i in xrange(0, 16):
            c  = saved_stack[i]
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
    saved_context = init_saved_context()
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
            saved_context = i386_emu(user_code, saved_context)

            print_context(saved_context)
        except EOFError:
            break
    finish(0, 0) # arguments are dummy

if __name__ == '__main__':
    main()
