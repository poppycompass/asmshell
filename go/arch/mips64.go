package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
    "github.com/bnagy/gapstone"
)

// TODO: comfirm the list of registers is correct
// sample code: ori $at, $at, 0x3456
func SetMips64(strArch string, bigEndian bool) Machine {
    var mc Machine
    mc.bit = 64
    mc.sp = uc.MIPS_REG_29
    mc.bp = uc.MIPS_REG_30
    mc.start = 0x0000

    if bigEndian {
        mc.ks, _ = keystone.New(keystone.ARCH_MIPS, keystone.MODE_MIPS64 + keystone.MODE_BIG_ENDIAN)
        mc.mu, _ = uc.NewUnicorn(uc.ARCH_MIPS, uc.MODE_MIPS64 + uc.MODE_BIG_ENDIAN)
        mc.oldMu, _ = uc.NewUnicorn(uc.ARCH_MIPS, uc.MODE_MIPS64 + uc.MODE_BIG_ENDIAN)
        mc.cs, _ = gapstone.New(
            gapstone.CS_ARCH_MIPS,
            gapstone.CS_MODE_MIPS64 + gapstone.CS_MODE_BIG_ENDIAN,
        )
    } else {
        mc.ks, _ = keystone.New(keystone.ARCH_MIPS, keystone.MODE_MIPS64)
        mc.mu, _ = uc.NewUnicorn(uc.ARCH_MIPS, uc.MODE_MIPS64 + uc.MODE_LITTLE_ENDIAN)
        mc.oldMu, _ = uc.NewUnicorn(uc.ARCH_MIPS, uc.MODE_MIPS64 + uc.MODE_LITTLE_ENDIAN)
        mc.cs, _ = gapstone.New(
            gapstone.CS_ARCH_MIPS,
            gapstone.CS_MODE_MIPS64 + gapstone.CS_MODE_LITTLE_ENDIAN,
        )
    }
    mc.Prompt = "(" + strArch + ")> "

    mc.mu.MemMap(0x0000, 0x200000)
    mc.mu.RegWrite(mc.sp, 0x100000)
    mc.mu.RegWrite(mc.bp, 0x80000)
    mc.oldCtx, _ = mc.mu.ContextSave(nil)

    mc.regOrder = []string{
        "zr", "at", "v0", "v1",
        "a0", "a1", "a2", "a3",
        "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
        "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
        "t8", "t9", "k0", "k1",
        "gp", "sp", "fp", "ra", "pc",
    }
    mc.regs = map[string]int{
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
    return mc
}
