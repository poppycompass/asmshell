package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
    as "github.com/poppycompass/asmshell/go"
)

// TODO: comfirm the list of registers is correct
func SetMips64(asmsh *as.AsmShell, bigEndian bool) {
    asmsh.CodeAddr  = 0x100000
    asmsh.PrintSize = 128 + 32
    asmsh.PrintMergin = 64
    asmsh.StackStart = 0x300000
    asmsh.StackSize   = 2 * 1024 * 1024
    asmsh.StackAddr = asmsh.StackStart + (asmsh.StackSize / 2)

    asmsh.KeystoneArch = keystone.ARCH_MIPS
    asmsh.UnicornArch = uc.ARCH_MIPS
    if bigEndian {
        asmsh.KeystoneMode = keystone.MODE_MIPS64 + keystone.MODE_BIG_ENDIAN
        asmsh.UnicornMode = uc.MODE_MIPS64 + uc.MODE_BIG_ENDIAN
        asmsh.Prompt = "(mips64eb)> "
    } else {
        asmsh.KeystoneMode = keystone.MODE_MIPS64
        asmsh.UnicornMode = uc.MODE_MIPS64 + uc.MODE_LITTLE_ENDIAN
        asmsh.Prompt = "(mips64)> "
    }
    asmsh.SavedCtx = nil
    asmsh.SavedStackSize = 256
    asmsh.SavedStack = make([]byte, asmsh.SavedStackSize)
    for i := uint64(0); i < asmsh.SavedStackSize; i++ {
        asmsh.SavedStack[i] = 0xFF
    }
    asmsh.RegOrder = []string{ "zr", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra", "pc"}
    asmsh.Regs = map[string]int{
        "pc"    : uc.MIPS_REG_PC,
        "zr"    : uc.MIPS_REG_0,
        "at"    : uc.MIPS_REG_1,
        "v0"    : uc.MIPS_REG_2,
        "v1"    : uc.MIPS_REG_3,
        "a0"    : uc.MIPS_REG_4,
        "a1"    : uc.MIPS_REG_5,
        "a2"    : uc.MIPS_REG_6,
        "a3"    : uc.MIPS_REG_7,
        "t0"    : uc.MIPS_REG_8,
        "t1"    : uc.MIPS_REG_9,
        "t2"    : uc.MIPS_REG_10,
        "t3"    : uc.MIPS_REG_11,
        "t4"    : uc.MIPS_REG_12,
        "t5"    : uc.MIPS_REG_13,
        "t6"    : uc.MIPS_REG_14,
        "t7"    : uc.MIPS_REG_15,
        "s0"    : uc.MIPS_REG_16,
        "s1"    : uc.MIPS_REG_17,
        "s2"    : uc.MIPS_REG_18,
        "s3"    : uc.MIPS_REG_19,
        "s4"    : uc.MIPS_REG_20,
        "s5"    : uc.MIPS_REG_21,
        "s6"    : uc.MIPS_REG_22,
        "s7"    : uc.MIPS_REG_23,
        "t8"    : uc.MIPS_REG_24,
        "t9"    : uc.MIPS_REG_25,
        "k0"    : uc.MIPS_REG_26,
        "k1"    : uc.MIPS_REG_27,
        "gp"    : uc.MIPS_REG_28,
        "sp"    : uc.MIPS_REG_29,
        "fp"    : uc.MIPS_REG_30,
        "ra"    : uc.MIPS_REG_31,
        "hi"    : uc.MIPS_REG_HI,
        "lo"    : uc.MIPS_REG_LO,
    }
    asmsh.SP = uc.MIPS_REG_29
    asmsh.PrintCtx = asmsh.PrintCtx64
}
