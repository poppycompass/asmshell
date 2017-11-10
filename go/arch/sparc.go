package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

// 32bit only
// sample: add %g1, %g2, %g3
func SetSparc(bigEndian bool) Machine {
    var mc Machine
    mc.bit = 32
    mc.sp = uc.SPARC_REG_SP
    mc.bp = uc.SPARC_REG_FP
    mc.start = 0x0000

    if bigEndian {
        mc.ks, _ = keystone.New(keystone.ARCH_SPARC, keystone.MODE_SPARC32 + keystone.MODE_BIG_ENDIAN)
        mc.mu, _ = uc.NewUnicorn(uc.ARCH_SPARC, uc.MODE_SPARC32 | uc.MODE_BIG_ENDIAN)
        mc.oldMu, _ = uc.NewUnicorn(uc.ARCH_SPARC, uc.MODE_SPARC32 | uc.MODE_BIG_ENDIAN)
        mc.Prompt = "(sparc)> "

        mc.mu.MemMap(0x0000, 0x200000)
        mc.mu.RegWrite(mc.sp, 0x100000)
        mc.mu.RegWrite(mc.bp, 0x80000)
        mc.oldCtx, _ = mc.mu.ContextSave(nil)
    } else {
        mc.ks, _ = keystone.New(keystone.ARCH_SPARC, keystone.MODE_SPARC32 + keystone.MODE_LITTLE_ENDIAN)
        mc.mu = nil
        mc.oldMu = nil
        mc.Prompt = "(sparcel)> "
    }

    mc.regOrder = []string{
        "g0", "g1", "g2", "g3", "g4", "g5", "g6", "g7",
        "i0", "i1", "i2", "i3", "i4", "i5", "i7",
        "l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7",
        "o0", "o1", "o2", "o3", "o4", "o5", "o7",
        "fp", "sp", "pc",
    }
    mc.regs = map[string]int{
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
    return mc
}
