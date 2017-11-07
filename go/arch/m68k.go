package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
    as "github.com/poppycompass/asmshell/go"
)

// keystone is not supported, rasm2 supports only disassembler
func SetM68k(asmsh *as.AsmShell) {
    asmsh.CodeAddr  = 0x100000
    asmsh.PrintSize = 64 + 16
    asmsh.PrintMergin = 32
    asmsh.StackStart = 0x300000
    asmsh.StackSize   = 2 * 1024 * 1024
    asmsh.StackAddr = asmsh.StackStart + (asmsh.StackSize / 2)

    //asmsh.KeystoneArch = keystone.ARCH_X86
    //asmsh.KeystoneMode = keystone.MODE_32
    //asmsh.KeystoneOPTType = keystone.OPT_SYNTAX
    //asmsh.KeystoneOPTVal = keystone.OPT_SYNTAX_INTEL
    asmsh.UnicornArch = uc.ARCH_M68K
    asmsh.UnicornMode = uc.MODE_BIG_ENDIAN
    asmsh.SavedCtx = nil
    asmsh.SavedStackSize = 256
    asmsh.SavedStack = make([]byte, asmsh.SavedStackSize)
    for i := uint64(0); i < asmsh.SavedStackSize; i++ {
        asmsh.SavedStack[i] = 0xFF
    }
    asmsh.Prompt = "(m68k)> "
    asmsh.RegOrder = []string{"d0", "a0", "d1", "a1", "d2", " a2", "d3", "a3", "d4", "a4", "d5", "a5", "d6", "a6", "d7", "a7/sp", "pc", "sr"}
    asmsh.Regs = map[string]int{
        "d0"    : uc.M68K_REG_D0,
        "d1"    : uc.M68K_REG_D1,
        "d2"    : uc.M68K_REG_D2,
        "d3"    : uc.M68K_REG_D3,
        "d4"    : uc.M68K_REG_D4,
        "d5"    : uc.M68K_REG_D5,
        "d6"    : uc.M68K_REG_D6,
        "d7"    : uc.M68K_REG_D7,
        "a0"    : uc.M68K_REG_A0,
        "a1"    : uc.M68K_REG_A1,
        "a2"    : uc.M68K_REG_A2,
        "a3"    : uc.M68K_REG_A3,
        "a4"    : uc.M68K_REG_A4,
        "a5"    : uc.M68K_REG_A5,
        "a6"    : uc.M68K_REG_A6,
        "a7/sp" : uc.M68K_REG_A7,
        "pc"    : uc.M68K_REG_PC,
        "sr"    : uc.M68K_REG_SR,
    }
    asmsh.SP = uc.M68K_REG_A7
    asmsh.PrintCtx = asmsh.PrintCtx32
}
