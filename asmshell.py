#!/usr/bin/env python
#-*- conding: utf-8 -*-
# register reference: include/unicorn/x86.h, qemu/target-i386/unicorn.c
# TODO: exe func, restrict history size, add unittest, too slow?(start up)
from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
import os
import sys
import argparse
import signal

LIB = os.path.abspath(os.path.expanduser(__file__))
if os.path.islink(LIB):
    CONFIG = os.readlink(LIB)
sys.path.insert(0, os.path.dirname(LIB) + "/lib/")
from config import *
from utils import *
import cmd
# currently supported architecture
import arch.x86
import arch.x64

parser = argparse.ArgumentParser(description='Assemblar Shell', formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('--arch', '-a', dest='arch', required=False, help='target architecture(default: x86). support(x86/64)', default='x86')
parser.add_argument('--diff', '-d', action='store_true', help='run diff mode(output changed register only)')
args = parser.parse_args()

def prompt_msg(str_arch, diff=False):
    prompt = "(" + str_arch
    if diff:
        prompt += ":diff"
    prompt += ")> "
    return prompt

def finish(signal, handler):
    print("\ngood bye:)")
    sys.exit(0)

def set_signal_handler():
    signal.signal(signal.SIGTERM, finish)
    signal.signal(signal.SIGINT, finish)

def main():
    set_signal_handler()

    if args.arch == 'x86':
        emu_arch = arch.x86.emu()
    elif args.arch == 'x64':
        emu_arch = arch.x64.emu()
    else:
        emu_arch = arch.x86.emu()
    emu_arch.banner()
    prompt = prompt_msg(emu_arch.get_arch_type(), args.diff)
    saved_context = emu_arch.init_saved_context()
    old_context   = emu_arch.init_saved_context()

    hist = ['']
    while True:
        try:
            print("{}".format(prompt), end="")
            intr, hist = cmd.parse_input(hist, prompt)
            if "q" == intr or "quit" == intr or "exit" == intr:
                break
            user_code = emu_arch.asm(intr)
            if str(user_code) in "invalid":
                print("[!] invalid code")
                continue
            saved_context = emu_arch.run(user_code, saved_context)

            if args.diff:
                emu_arch.print_diff_context(saved_context, old_context)
                old_context = saved_context
            else:
                emu_arch.print_context(saved_context)
        except EOFError:
            break
    finish(0, 0) # arguments are dummy

if __name__ == '__main__':
    main()
