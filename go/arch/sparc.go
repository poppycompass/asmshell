package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
    as "github.com/poppycompass/asmshell/go"
)

// 32bit only
// sample: add %g1, %g2, %g3
func InitSparc(asmsh *as.AsmShell, bigEndian bool) {
    asmsh.CodeAddr  = 0x100000
    asmsh.PrintSize = 64 + 16
    asmsh.PrintMergin = 32
    asmsh.StackStart = 0x300000
    asmsh.StackSize   = 2 * 1024 * 1024
    asmsh.StackAddr = asmsh.StackStart + (asmsh.StackSize / 2)

    asmsh.KeystoneArch = keystone.ARCH_SPARC
    asmsh.UnicornArch = uc.ARCH_SPARC
    if bigEndian {
        asmsh.KeystoneMode = keystone.MODE_SPARC32 + keystone.MODE_BIG_ENDIAN
        asmsh.UnicornMode = uc.MODE_SPARC32 | uc.MODE_BIG_ENDIAN
        asmsh.Prompt = "(sparc)> "
    } else {
        asmsh.KeystoneMode = keystone.MODE_SPARC32 + keystone.MODE_LITTLE_ENDIAN
        asmsh.UnicornMode = uc.MODE_SPARC32 | uc.MODE_LITTLE_ENDIAN
        asmsh.Prompt = "(sparcel)> "
    }
    asmsh.SavedCtx = nil
    asmsh.SavedStackSize = 256
    asmsh.SavedStack = make([]byte, asmsh.SavedStackSize)
    for i := uint64(0); i < asmsh.SavedStackSize; i++ {
        asmsh.SavedStack[i] = 0xFF
    }
    asmsh.RegOrder = []string{ "g0", "g1", "g2", "g3", "g4", "g5", "g6", "g7", "i0", "i1", "i2", "i3", "i4", "i5", "i7", "l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7", "o0", "o1", "o2", "o3", "o4", "o5", "o7", "fp", "sp", "pc"}
    asmsh.Regs = map[string]int{
        "g0"    : uc.SPARC_REG_G0,
        "g1"    : uc.SPARC_REG_G1,
        "g2"    : uc.SPARC_REG_G2,
        "g3"    : uc.SPARC_REG_G3,
        "g4"    : uc.SPARC_REG_G4,
        "g5"    : uc.SPARC_REG_G5,
        "g6"    : uc.SPARC_REG_G6,
        "g7"    : uc.SPARC_REG_G7,

        "i0"    : uc.SPARC_REG_I0,
        "i1"    : uc.SPARC_REG_I1,
        "i2"    : uc.SPARC_REG_I2,
        "i3"    : uc.SPARC_REG_I3,
        "i4"    : uc.SPARC_REG_I4,
        "i5"    : uc.SPARC_REG_I5,
        "fp"    : uc.SPARC_REG_FP, // i6 == fp
        "i7"    : uc.SPARC_REG_I7,

        "l0"    : uc.SPARC_REG_L0,
        "l1"    : uc.SPARC_REG_L1,
        "l2"    : uc.SPARC_REG_L2,
        "l3"    : uc.SPARC_REG_L3,
        "l4"    : uc.SPARC_REG_L4,
        "l5"    : uc.SPARC_REG_L5,
        "l6"    : uc.SPARC_REG_L6,
        "l7"    : uc.SPARC_REG_L7,

        "o0"    : uc.SPARC_REG_O0,
        "o1"    : uc.SPARC_REG_O1,
        "o2"    : uc.SPARC_REG_O2,
        "o3"    : uc.SPARC_REG_O3,
        "o4"    : uc.SPARC_REG_O4,
        "o5"    : uc.SPARC_REG_O5,
        "sp"    : uc.SPARC_REG_SP, // o6 == sp
        "o7"    : uc.SPARC_REG_O7,
        "pc"    : uc.SPARC_REG_PC,
    }
    asmsh.SP = uc.SPARC_REG_SP
    asmsh.PrintCtx = asmsh.PrintCtx32
}
