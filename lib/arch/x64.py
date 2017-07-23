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
        self.arch = UC_ARCH_X86
        self.mode = UC_MODE_64
        self.stack_size = 128 + 32
        self.stack_mergin_offset = 64
        self.stack_addr = ADDRESS + ESP_START_OFFSET - self.stack_mergin_offset
        self.saved_stack = [255] * self.stack_size
        self.str_arch = "x64"
    def banner(self):
        yellow("Assembar Shell(v {})".format(VERSION))
        yellow("Emulate x86_64 code")
    def get_arch_type(self):
        return self.str_arch
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
        mu = Uc(self.arch, self.mode)
        mu.mem_map(ADDRESS, MEM_SIZE)
        mu.reg_write(UC_X86_REG_RSP, ADDRESS + ESP_START_OFFSET)
        return mu.context_save()
    def print_context(self, saved_context):
        saved_mu = Uc(self.arch, self.mode)
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
            ))
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
        for i in xrange(0, self.stack_size, 32):
            yellow("0x%016x: " %(self.stack_addr+i), "")
            for j in xrange(0, 32, 8):
                if (self.stack_addr+i+j) == rsp:
                    red("%02x%02x%02x%02x%02x%02x%02x%02x " % \
                            (self.saved_stack[i+j+7], \
                             self.saved_stack[i+j+6], \
                             self.saved_stack[i+j+5], \
                             self.saved_stack[i+j+4], \
                             self.saved_stack[i+j+3], \
                             self.saved_stack[i+j+2], \
                             self.saved_stack[i+j+1], \
                             self.saved_stack[i+j],   \
                            ), "")
                else:
                    yellow("%02x%02x%02x%02x%02x%02x%02x%02x " % \
                            (self.saved_stack[i+j+7], \
                             self.saved_stack[i+j+6], \
                             self.saved_stack[i+j+5], \
                             self.saved_stack[i+j+4], \
                             self.saved_stack[i+j+3], \
                             self.saved_stack[i+j+2], \
                             self.saved_stack[i+j+1], \
                             self.saved_stack[i+j],   \
                            ), "")
            yellow("|", "")
            for j in xrange(0, 32, 8):
                for k in xrange(7, -1, -1): # [7,6,5,4,3,2,1,0]
                    c  = self.saved_stack[i+j+k]
                    if c >= 0x20 and c <= 0x7E:
                        yellow("%c" %c, "")
                    else:
                        yellow(".", "")
            yellow("|")
    # TODO: fix terrible code!
    def print_diff_context(self, saved_context, old_context):
        now = Uc(self.arch, self.mode)
        old = Uc(self.arch, self.mode)

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
                    ,)
            cyan(" ]")
    def run(self, code, saved_context):
        try:
            # Initialize emulator
            mu = Uc(self.arch, self.arch)
            # map 2MB memory for this emulation
            mu.mem_map(ADDRESS, MEM_SIZE)
            # write machine code to be emulated to memory
            mu.mem_write(ADDRESS, code)
            # initialize stack
            mu.mem_map(ADDRESS+MAP_OFFSET, MEM_SIZE) # if not call, "mem unmapped error" is rasied

            # recover saved state
            mu.context_restore(saved_context)

            mu.mem_write(self.stack_addr, struct.pack('B'*len(self.saved_stack), *self.saved_stack))
            try:
                # emulate machine code in infinite time
                mu.emu_start(ADDRESS, ADDRESS + len(code))
            except UcError as e:
                print("ERROR: %s" % e)

            # save context(regs, stack)
            self.saved_stack = mu.mem_read(self.stack_addr, self.stack_size)
            return mu.context_save()
        except UcError as e:
            print("ERROR: %s" % e)
