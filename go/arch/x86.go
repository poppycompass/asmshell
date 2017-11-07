package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
    as "github.com/poppycompass/asmshell/go"
)

func SetX86(asmsh *as.AsmShell) {
    asmsh.CodeAddr  = 0x100000
    asmsh.PrintSize = 64 + 16
    asmsh.PrintMergin = 32
    asmsh.StackStart = 0x300000
    asmsh.StackSize   = 2 * 1024 * 1024
    asmsh.StackAddr = asmsh.StackStart + (asmsh.StackSize / 2)

    asmsh.KeystoneArch = keystone.ARCH_X86
    asmsh.KeystoneMode = keystone.MODE_32
    asmsh.KeystoneOPTType = keystone.OPT_SYNTAX
    asmsh.KeystoneOPTVal = keystone.OPT_SYNTAX_INTEL
    asmsh.UnicornArch = uc.ARCH_X86
    asmsh.UnicornMode = uc.MODE_32
    asmsh.SavedCtx = nil
    asmsh.SavedStackSize = 256
    asmsh.SavedStack = make([]byte, asmsh.SavedStackSize)
    for i := uint64(0); i < asmsh.SavedStackSize; i++ {
        asmsh.SavedStack[i] = 0xFF
    }
    asmsh.Prompt = "(x86)> "
    asmsh.RegOrder = []string{"eax", "eip", "ebx", "eflags", "ecx", " cs", "edx", " ss", "esp", " ds", "ebp", " es", "esi", " fs", "edi", " gs"}
    asmsh.Regs = map[string]int{
        "eax"    : uc.X86_REG_EAX,
        "ebx"    : uc.X86_REG_EBX,
        "ecx"    : uc.X86_REG_ECX,
        "edx"    : uc.X86_REG_EDX,
        "eip"    : uc.X86_REG_EIP,
        "esp"    : uc.X86_REG_ESP,
        "ebp"    : uc.X86_REG_EBP,
        "esi"    : uc.X86_REG_ESI,
        "edi"    : uc.X86_REG_EDI,
        "eflags" : uc.X86_REG_EFLAGS,
        " cs"    : uc.X86_REG_CS,
        " ss"    : uc.X86_REG_SS,
        " ds"    : uc.X86_REG_DS,
        " es"    : uc.X86_REG_ES,
        " fs"    : uc.X86_REG_FS,
        " gs"    : uc.X86_REG_GS,
    }
    asmsh.SP = uc.X86_REG_ESP
    asmsh.PrintCtx = asmsh.PrintCtx32
}
