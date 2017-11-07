package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
    as "github.com/poppycompass/asmshell/go"
)

func SetI8086(asmsh *as.AsmShell) {
    asmsh.CodeAddr  = 0x1000
    asmsh.PrintSize = 32 + 8
    asmsh.PrintMergin = 16
    asmsh.StackStart = 0x3000
    asmsh.StackSize   = 8 * 1024
    asmsh.StackAddr = asmsh.StackStart + (asmsh.StackSize / 2)

    asmsh.KeystoneArch = keystone.ARCH_X86
    asmsh.KeystoneMode = keystone.MODE_16
    asmsh.KeystoneOPTType = keystone.OPT_SYNTAX
    asmsh.KeystoneOPTVal = keystone.OPT_SYNTAX_INTEL
    asmsh.UnicornArch = uc.ARCH_X86
    asmsh.UnicornMode = uc.MODE_16
    asmsh.SavedCtx = nil
    asmsh.SavedStackSize = 256
    asmsh.SavedStack = make([]byte, asmsh.SavedStackSize)
    for i := uint64(0); i < asmsh.SavedStackSize; i++ {
        asmsh.SavedStack[i] = 0xFF
    }
    asmsh.Prompt = "(i8086)> "
    asmsh.RegOrder = []string{"ax", "ip", "bx", "eflags", "cx", " cs", "dx", " ss", "sp", " ds", "bp", " es", "si", " fs", "di", " gs"}
    asmsh.Regs = map[string]int{
        "ax"    : uc.X86_REG_AX,
        "bx"    : uc.X86_REG_BX,
        "cx"    : uc.X86_REG_CX,
        "dx"    : uc.X86_REG_DX,
        "ip"    : uc.X86_REG_IP,
        "sp"    : uc.X86_REG_SP,
        "bp"    : uc.X86_REG_BP,
        "si"    : uc.X86_REG_SI,
        "di"    : uc.X86_REG_DI,
        "eflags" : uc.X86_REG_EFLAGS,
        " cs"    : uc.X86_REG_CS,
        " ss"    : uc.X86_REG_SS,
        " ds"    : uc.X86_REG_DS,
        " es"    : uc.X86_REG_ES,
        " fs"    : uc.X86_REG_FS,
        " gs"    : uc.X86_REG_GS,
    }
    asmsh.SP = uc.X86_REG_SP
    asmsh.PrintCtx = asmsh.PrintCtx16
}
