package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
    as "github.com/poppycompass/asmshell/go"
)

func InitArm64(asmsh *as.AsmShell) {
    asmsh.CodeAddr  = 0x100000
    asmsh.PrintSize = 128 + 32
    asmsh.PrintMergin = 64
    asmsh.StackStart = 0x300000
    asmsh.StackSize   = 2 * 1024 * 1024
    asmsh.StackAddr = asmsh.StackStart + (asmsh.StackSize / 2)

    asmsh.KeystoneArch = keystone.ARCH_ARM64
    asmsh.KeystoneMode = keystone.MODE_LITTLE_ENDIAN
/*     asmsh.KeystoneOPTType = keystone.OPT_SYNTAX */
/*     asmsh.KeystoneOPTVal = keystone.OPT_SYNTAX_INTEL */
    asmsh.UnicornArch = uc.ARCH_ARM64
    asmsh.UnicornMode = uc.MODE_ARM
    asmsh.SavedCtx = nil
    asmsh.SavedStackSize = 256
    asmsh.SavedStack = make([]byte, asmsh.SavedStackSize)
    for i := uint64(0); i < asmsh.SavedStackSize; i++ {
        asmsh.SavedStack[i] = 0xFF
    }
    asmsh.Prompt = "(arm64)> "
    asmsh.RegOrder = []string{"x0", " x8", "x1", " x9", "x2", "x10", "x3", "x11", "x4", "x12", "x5", "x13", "x6", " sp", "x7", " pc", "nzcv"}
    asmsh.Regs = map[string]int{
        "x0"    : uc.ARM64_REG_X0,
        "x1"    : uc.ARM64_REG_X1,
        "x2"    : uc.ARM64_REG_X2,
        "x3"    : uc.ARM64_REG_X3,
        "x4"    : uc.ARM64_REG_X4,
        "x5"    : uc.ARM64_REG_X5,
        "x6"    : uc.ARM64_REG_X6,
        "x7"    : uc.ARM64_REG_X7,
        " x8"    : uc.ARM64_REG_X8,
        " x9"    : uc.ARM64_REG_X9,
        "x10"   : uc.ARM64_REG_X10,
        "x11"   : uc.ARM64_REG_X11,
        "x12"   : uc.ARM64_REG_X12,
        "x13"   : uc.ARM64_REG_X13,
        "x14"   : uc.ARM64_REG_X14,
        "x15"   : uc.ARM64_REG_X15,
        "x16"   : uc.ARM64_REG_X16,
        "x17"   : uc.ARM64_REG_X17,
        "x18"   : uc.ARM64_REG_X18,
        "x19"   : uc.ARM64_REG_X19,
        "x20"   : uc.ARM64_REG_X20,
        "x21"   : uc.ARM64_REG_X21,
        "x22"   : uc.ARM64_REG_X22,
        "x23"   : uc.ARM64_REG_X23,
        "x24"   : uc.ARM64_REG_X24,
        "x25"   : uc.ARM64_REG_X25,
        "x26"   : uc.ARM64_REG_X26,
        "x27"   : uc.ARM64_REG_X27,
        "x28"   : uc.ARM64_REG_X28,
        "x29"   : uc.ARM64_REG_X29,
        "x30"   : uc.ARM64_REG_X30,
        " sp"    : uc.ARM64_REG_SP,
        " pc"    : uc.ARM64_REG_PC,
        "nzcv"  : uc.ARM64_REG_NZCV,
    }
    asmsh.SP = uc.ARM64_REG_SP
    asmsh.PrintCtx = asmsh.PrintCtx64
}
