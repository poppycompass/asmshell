package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
    as "github.com/poppycompass/asmshell/go"
)

func InitX64(asmsh *as.AsmShell) {
    asmsh.CodeAddr  = 0x100000
    asmsh.PrintSize = 128 + 32
    asmsh.PrintMergin = 64
    asmsh.StackStart = 0x300000
    asmsh.StackSize   = 2 * 1024 * 1024
    asmsh.StackAddr = asmsh.StackStart + (asmsh.StackSize / 2)

    asmsh.KeystoneArch = keystone.ARCH_X86
    asmsh.KeystoneMode = keystone.MODE_64
    asmsh.KeystoneOPTType = keystone.OPT_SYNTAX
    asmsh.KeystoneOPTVal = keystone.OPT_SYNTAX_INTEL
    asmsh.UnicornArch = uc.ARCH_X86
    asmsh.UnicornMode = uc.MODE_64
    asmsh.SavedCtx = nil
    asmsh.SavedStackSize = 256
    asmsh.SavedStack = make([]byte, asmsh.SavedStackSize)
    for i := uint64(0); i < asmsh.SavedStackSize; i++ {
        asmsh.SavedStack[i] = 0xFF
    }
    asmsh.Prompt = "(x64)> "
    // if you want R8-15 register, add X86_REG_R8-15
    asmsh.RegOrder = []string{"rax", "rip", "rbx", "eflags", "rcx", " cs", "rdx", " ss", "rsp", " ds", "rbp", " es", "rsi", " fs", "rdi", " gs"}
    asmsh.Regs = map[string]int{
        "rax"    : uc.X86_REG_RAX,
        "rbx"    : uc.X86_REG_RBX,
        "rcx"    : uc.X86_REG_RCX,
        "rdx"    : uc.X86_REG_RDX,
        "rip"    : uc.X86_REG_RIP,
        "rsp"    : uc.X86_REG_RSP,
        "rbp"    : uc.X86_REG_RBP,
        "rsi"    : uc.X86_REG_RSI,
        "rdi"    : uc.X86_REG_RDI,
        "eflags" : uc.X86_REG_EFLAGS,
        " cs"    : uc.X86_REG_CS,
        " ss"    : uc.X86_REG_SS,
        " ds"    : uc.X86_REG_DS,
        " es"    : uc.X86_REG_ES,
        " fs"    : uc.X86_REG_FS,
        " gs"    : uc.X86_REG_GS,
    }
    asmsh.SP  = uc.X86_REG_RSP
    asmsh.PrintCtx = asmsh.PrintCtx64
}

