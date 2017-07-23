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

# UNUSED, copy from include/unicorn/x86.h
regs = X86_REGS
class x86():
    def __init__(self):
        self.arch = UC_ARCH_X86
        self.mode = UC_MODE_32
        self.stack_size = 64 + 16
        self.stack_addr = ADDRESS + ESP_START_OFFSET - STACK_MERGIN_OFFSET
        self.saved_stack = [255] * self.stack_size
        self.str_arch = "x86"
    def banner(self):
        yellow("Assembar Shell(v {})".format(VERSION))
        yellow("Emulate i386 code")
    def get_arch_type(self):
        return self.str_arch
    # assemble user input
    def asm(self, intr):
        cmd = "rasm2 -a x86 -b 32 '%s'" %(intr)
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
        mu.reg_write(UC_X86_REG_ESP, ADDRESS + ESP_START_OFFSET)
        return mu.context_save()
    def print_context(self, saved_context):
        saved_mu = Uc(self.arch, self.mode)
        saved_mu.mem_map(ADDRESS, MEM_SIZE)
        saved_mu.mem_map(ADDRESS+MAP_OFFSET, MEM_SIZE) # if not call, "mem unmapped error" is rasied
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
        bold_yellow("---------------- stack trace ----------------")
        for i in xrange(0, self.stack_size, 16):
            yellow("0x%08x: " %(self.stack_addr+i), "")
            for j in xrange(0, 16, 4):
                if (self.stack_addr+i+j) == esp:
                    red("%02x%02x%02x%02x " % \
                            (self.saved_stack[i+j+3], \
                             self.saved_stack[i+j+2], \
                             self.saved_stack[i+j+1], \
                             self.saved_stack[i+j],   \
                            ), "")
                else:
                    yellow("%02x%02x%02x%02x " % \
                            (self.saved_stack[i+j+3], \
                             self.saved_stack[i+j+2], \
                             self.saved_stack[i+j+1], \
                             self.saved_stack[i+j],   \
                            ), "")
            yellow("|", "")
            for i in xrange(0, 16):
                c  = self.saved_stack[i]
                if 0x20 <= self.saved_stack[i] and 0x7E >= self.saved_stack[i]:
                    yellow("%c" %self.saved_stack[i], "")
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
        if now.reg_read(UC_X86_REG_EAX) != old.reg_read(UC_X86_REG_EAX):
            cyan("eax: 0x%08x(old: 0x%08x)" %(now.reg_read(UC_X86_REG_EAX), old.reg_read(UC_X86_REG_EAX)))
        if now.reg_read(UC_X86_REG_EBX) != old.reg_read(UC_X86_REG_EBX):
            cyan("ebx: 0x%08x(old: 0x%08x)" %(now.reg_read(UC_X86_REG_EBX), old.reg_read(UC_X86_REG_EBX)))
        if now.reg_read(UC_X86_REG_ECX) != old.reg_read(UC_X86_REG_ECX):
            cyan("ecx: 0x%08x(old: 0x%08x)" %(now.reg_read(UC_X86_REG_ECX), old.reg_read(UC_X86_REG_ECX)))
        if now.reg_read(UC_X86_REG_EDX) != old.reg_read(UC_X86_REG_EDX):
            cyan("edx: 0x%08x(old: 0x%08x)" %(now.reg_read(UC_X86_REG_EDX), old.reg_read(UC_X86_REG_EDX)))
        if now.reg_read(UC_X86_REG_EBP) != old.reg_read(UC_X86_REG_EBP):
            cyan("ebp: 0x%08x(old: 0x%08x)" %(now.reg_read(UC_X86_REG_EBP), old.reg_read(UC_X86_REG_EBP)))
        if now.reg_read(UC_X86_REG_ESI) != old.reg_read(UC_X86_REG_ESI):
            cyan("esi: 0x%08x(old: 0x%08x)" %(now.reg_read(UC_X86_REG_ESI), old.reg_read(UC_X86_REG_ESI)))
        if now.reg_read(UC_X86_REG_EIP) != old.reg_read(UC_X86_REG_EIP):
            cyan("eip: 0x%08x(old: 0x%08x)" %(now.reg_read(UC_X86_REG_EIP), old.reg_read(UC_X86_REG_EIP)))
        if now.reg_read(UC_X86_REG_EDI) != old.reg_read(UC_X86_REG_EDI):
            cyan("edi: 0x%08x(old: 0x%08x)" %(now.reg_read(UC_X86_REG_EDI), old.reg_read(UC_X86_REG_EDI)))
        if now.reg_read(UC_X86_REG_EFLAGS) != old.reg_read(UC_X86_REG_EFLAGS):
            cyan("eflags: 0x%08x [ " %(now.reg_read(UC_X86_REG_EFLAGS)), "")
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
