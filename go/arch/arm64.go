package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

// 'AArch64'? ref: bindings/vb6/mKeystone.bas:ARM-64, also called AArch64
// sample: str w11, [x13], 0; ldrb w15, [x13], 0; mov x0, 0x37; sub x0,x1,x2
func SetArm64(strArch string, bigEndian bool) Machine {
    var mc Machine
    mc.bit = 64
    mc.sp = uc.ARM64_REG_SP
    mc.bp = uc.ARM64_REG_X29
    mc.start = 0x0000

    if bigEndian {
        // fixme: arm64be assemble mode with keystone
//        mc.ks, _ = keystone.New(keystone.ARCH_ARM, keystone.MODE_BIG_ENDIAN)
        mc.ks, _ = keystone.New(keystone.ARCH_ARM64, keystone.MODE_LITTLE_ENDIAN)
        mc.mu, _ = uc.NewUnicorn(uc.ARCH_ARM64, uc.MODE_ARM + uc.MODE_BIG_ENDIAN)
        mc.oldMu, _ = uc.NewUnicorn(uc.ARCH_ARM64, uc.MODE_ARM + uc.MODE_BIG_ENDIAN)
    } else {
        mc.ks, _ = keystone.New(keystone.ARCH_ARM64, keystone.MODE_LITTLE_ENDIAN)
        mc.mu, _ = uc.NewUnicorn(uc.ARCH_ARM64, uc.MODE_ARM + uc.MODE_LITTLE_ENDIAN)
        mc.oldMu, _ = uc.NewUnicorn(uc.ARCH_ARM64, uc.MODE_ARM + uc.MODE_LITTLE_ENDIAN)
    }
    mc.Prompt = "(" + strArch + ")> "

    mc.mu.MemMap(0x0000, 0x2000)
    mc.mu.RegWrite(mc.sp, 0x1000)
    mc.mu.RegWrite(mc.bp, 0x8000)

    mc.oldCtx, _ = mc.mu.ContextSave(nil)

    mc.regOrder = []string{
        "x0", " x8", "x1", " x9",
        "x2", "x10", "x3", "x11",
        "x4", "x12", "x5", "x13",
        "x6", " sp", "x7", " pc",
        "nzcv",
    }
    mc.regs = map[string]int{
        "x0"    : uc.ARM64_REG_X0,
        "x1"    : uc.ARM64_REG_X1,
        "x2"    : uc.ARM64_REG_X2,
        "x3"    : uc.ARM64_REG_X3,
        "x4"    : uc.ARM64_REG_X4,
        "x5"    : uc.ARM64_REG_X5,
        "x6"    : uc.ARM64_REG_X6,
        "x7"    : uc.ARM64_REG_X7,
        " x8"   : uc.ARM64_REG_X8,
        " x9"   : uc.ARM64_REG_X9,
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
        "x29"   : uc.ARM64_REG_X29, // fix: frame(base) pointer?
        "x30"   : uc.ARM64_REG_X30,
        " sp"   : uc.ARM64_REG_SP,
        " pc"   : uc.ARM64_REG_PC,
        "nzcv"  : uc.ARM64_REG_NZCV,
    }
    return mc
}
