#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
import subprocess
import binascii
import struct
import sys

# user library
sys.path.append("../")
from config import *
from utils import *

class emu():
    def __init__(self):
        self._arch = UC_ARCH_X86
        self._mode = UC_MODE_64
        self._stack_size = 128 + 32
        self._stack_mergin_offset = 64
        self._stack_addr = ADDRESS + ESP_START_OFFSET - self._stack_mergin_offset
        self._saved_stack = [255] * self._stack_size
        self._str_arch = "x64"
    def banner(self):
        yellow("Assembar Shell(v {})".format(VERSION))
        yellow("Emulate x86_64 code")
    def get_arch_type(self):
        return self._str_arch
    # assemble user input
    def asm(self, intr):
        cmd = "rasm2 -a x86 -b 64 '%s'" %(intr)
        out = binascii.a2b_hex(
                subprocess.Popen(
                  cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                  shell=True).communicate()[0].strip('\n')
                 )
        return out
    # return dummy context
    def init_saved_context(self):
        mu = Uc(self._arch, self._mode)
        mu.mem_map(ADDRESS, MEM_SIZE)
        mu.reg_write(UC_X86_REG_RSP, ADDRESS + ESP_START_OFFSET)
        return mu.context_save()
    def print_context(self, saved_context):
        saved_mu = Uc(self._arch, self._mode)
        saved_mu.mem_map(ADDRESS, MEM_SIZE)
        saved_mu.mem_map(ADDRESS+MAP_OFFSET, MEM_SIZE) # if not call, "mem unmapped error" is rasied
        saved_mu.context_restore(saved_context)
        bold_cyan("---------------- cpu context ----------------")
        cyan("rax:    0x%016x" %saved_mu.reg_read(UC_X86_REG_RAX), "    ")
        cyan("rip:    0x%016x" %saved_mu.reg_read(UC_X86_REG_RIP))
        cyan("rbx:    0x%016x" %saved_mu.reg_read(UC_X86_REG_RBX), "    ")
        cyan("eflags: 0x%016x [ CF(%d) ZF(%d) SF(%d) ]" %(saved_mu.reg_read(UC_X86_REG_EFLAGS),
            (saved_mu.reg_read(UC_X86_REG_EFLAGS)&0x1),
            (saved_mu.reg_read(UC_X86_REG_EFLAGS)>>6&0x1),
            (saved_mu.reg_read(UC_X86_REG_EFLAGS)>>7&0x1),
            ), "")
        cyan("rcx:    0x%016x" %saved_mu.reg_read(UC_X86_REG_RCX), "    ")
        cyan("cs:     0x%016x" %saved_mu.reg_read(UC_X86_REG_CS))
        cyan("rdx:    0x%016x" %saved_mu.reg_read(UC_X86_REG_RDX), "    ")
        cyan("ss:     0x%016x" %saved_mu.reg_read(UC_X86_REG_SS))
        cyan("rsp:    0x%016x" %saved_mu.reg_read(UC_X86_REG_RSP), "    ")
        cyan("ds:     0x%016x" %saved_mu.reg_read(UC_X86_REG_DS))
        cyan("rbp:    0x%016x" %saved_mu.reg_read(UC_X86_REG_RBP), "    ")
        cyan("es:     0x%016x" %saved_mu.reg_read(UC_X86_REG_ES))
        cyan("rsi:    0x%016x" %saved_mu.reg_read(UC_X86_REG_RSI), "    ")
        cyan("fs:     0x%016x" %saved_mu.reg_read(UC_X86_REG_FS))
        cyan("rdi:    0x%016x" %saved_mu.reg_read(UC_X86_REG_RDI), "    ")
        cyan("gs:     0x%016x" %saved_mu.reg_read(UC_X86_REG_GS), )
        rsp = saved_mu.reg_read(UC_X86_REG_RSP) # tmp value
        bold_yellow("---------------- stack trace ----------------")
        for i in xrange(0, self._stack_size, 32):
            yellow("0x%016x: " %(self._stack_addr+i), "")
            for j in xrange(0, 32, 8):
                if (self._stack_addr+i+j) == rsp:
                    red("%02x%02x%02x%02x%02x%02x%02x%02x " % \
                            (self._saved_stack[i+j+7], \
                             self._saved_stack[i+j+6], \
                             self._saved_stack[i+j+5], \
                             self._saved_stack[i+j+4], \
                             self._saved_stack[i+j+3], \
                             self._saved_stack[i+j+2], \
                             self._saved_stack[i+j+1], \
                             self._saved_stack[i+j],   \
                            ), "")
                else:
                    yellow("%02x%02x%02x%02x%02x%02x%02x%02x " % \
                            (self._saved_stack[i+j+7], \
                             self._saved_stack[i+j+6], \
                             self._saved_stack[i+j+5], \
                             self._saved_stack[i+j+4], \
                             self._saved_stack[i+j+3], \
                             self._saved_stack[i+j+2], \
                             self._saved_stack[i+j+1], \
                             self._saved_stack[i+j],   \
                            ), "")
            yellow("|", "")
            for j in xrange(0, 32, 8):
                for k in xrange(7, -1, -1): # [7,6,5,4,3,2,1,0]
                    c  = self._saved_stack[i+j+k]
                    if c >= 0x20 and c <= 0x7E:
                        yellow("%c" %c, "")
                    else:
                        yellow(".", "")
            yellow("|")
    # TODO: fix terrible code!
    def print_diff_context(self, saved_context, old_context):
        now = Uc(self._arch, self._mode)
        old = Uc(self._arch, self._mode)

        now.context_restore(saved_context)
        old.context_restore(old_context)

        bold_cyan("---------------- cpu context ----------------")
        if now.reg_read(UC_X86_REG_RAX) != old.reg_read(UC_X86_REG_RAX):
            cyan("rax: 0x%016x(old: 0x%016x)" %(now.reg_read(UC_X86_REG_RAX), old.reg_read(UC_X86_REG_RAX)))
        if now.reg_read(UC_X86_REG_RBX) != old.reg_read(UC_X86_REG_RBX):
            cyan("rbx: 0x%016x(old: 0x%016x)" %(now.reg_read(UC_X86_REG_RBX), old.reg_read(UC_X86_REG_RBX)))
        if now.reg_read(UC_X86_REG_RCX) != old.reg_read(UC_X86_REG_RCX):
            cyan("rcx: 0x%016x(old: 0x%016x)" %(now.reg_read(UC_X86_REG_RCX), old.reg_read(UC_X86_REG_RCX)))
        if now.reg_read(UC_X86_REG_RDX) != old.reg_read(UC_X86_REG_RDX):
            cyan("rdx: 0x%016x(old: 0x%016x)" %(now.reg_read(UC_X86_REG_RDX), old.reg_read(UC_X86_REG_RDX)))
        if now.reg_read(UC_X86_REG_RBP) != old.reg_read(UC_X86_REG_RBP):
            cyan("rbp: 0x%016x(old: 0x%016x)" %(now.reg_read(UC_X86_REG_RBP), old.reg_read(UC_X86_REG_RBP)))
        if now.reg_read(UC_X86_REG_RSI) != old.reg_read(UC_X86_REG_RSI):
            cyan("rsi: 0x%016x(old: 0x%016x)" %(now.reg_read(UC_X86_REG_RSI), old.reg_read(UC_X86_REG_RSI)))
        if now.reg_read(UC_X86_REG_RIP) != old.reg_read(UC_X86_REG_RIP):
            cyan("rip: 0x%016x(old: 0x%016x)" %(now.reg_read(UC_X86_REG_RIP), old.reg_read(UC_X86_REG_RIP)))
        if now.reg_read(UC_X86_REG_RDI) != old.reg_read(UC_X86_REG_RDI):
            cyan("rdi: 0x%016x(old: 0x%016x)" %(now.reg_read(UC_X86_REG_RDI), old.reg_read(UC_X86_REG_RDI)))
        if now.reg_read(UC_X86_REG_EFLAGS) != old.reg_read(UC_X86_REG_EFLAGS):
            cyan("eflags: 0x%016x [ " %(now.reg_read(UC_X86_REG_EFLAGS)), "")
            if (now.reg_read(UC_X86_REG_EFLAGS)&0x1) != (old.reg_read(UC_X86_REG_EFLAGS)&0x1):
                cyan("CF(%d -> %d)" % (\
                      (old.reg_read(UC_X86_REG_EFLAGS)&0x1), \
                      (now.reg_read(UC_X86_REG_EFLAGS)&0x1))
                    , "")
            if (now.reg_read(UC_X86_REG_EFLAGS)>>6&0x1) != (old.reg_read(UC_X86_REG_EFLAGS)>>6&0x1):
                cyan("ZF(%d -> %d)" % (\
                      (old.reg_read(UC_X86_REG_EFLAGS)>>6&0x1), \
                      (now.reg_read(UC_X86_REG_EFLAGS)>>6&0x1))
                    , "")
            if (now.reg_read(UC_X86_REG_EFLAGS)>>7&0x1) != (old.reg_read(UC_X86_REG_EFLAGS)>>7&0x1):
                cyan("SF(%d -> %d)" % (\
                      (old.reg_read(UC_X86_REG_EFLAGS)>>7&0x1), \
                      (now.reg_read(UC_X86_REG_EFLAGS)>>7&0x1))
                    , "")
            cyan(" ]")
    def run(self, code, saved_context):
        try:
            # Initialize emulator
            mu = Uc(self._arch, self._arch)
            # map 2MB memory for this emulation
            mu.mem_map(ADDRESS, MEM_SIZE)
            # write machine code to be emulated to memory
            mu.mem_write(ADDRESS, code)
            # initialize stack
            mu.mem_map(ADDRESS+MAP_OFFSET, MEM_SIZE) # if not call, "mem unmapped error" is rasied

            # recover saved state
            mu.context_restore(saved_context)

            mu.mem_write(self._stack_addr, struct.pack('B'*len(self._saved_stack), *self._saved_stack))
            try:
                # emulate machine code in infinite time
                mu.emu_start(ADDRESS, ADDRESS + len(code))
            except UcError as e:
                print("ERROR: %s" % e)

            # save context(regs, stack)
            self._saved_stack = mu.mem_read(self._stack_addr, self._stack_size)
            return mu.context_save()
        except UcError as e:
            print("ERROR: %s" % e)
