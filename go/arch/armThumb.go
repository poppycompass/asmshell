package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

// sample: sub sp, 0xc; mov r0, 0x37; sub r1, r2, r3 
func SetArmThumb(bigEndian bool) Machine {
    var mc Machine
    mc.bit = 16
    mc.sp = uc.ARM_REG_R13
    mc.bp = uc.ARM_REG_R11
    mc.start = 0x0001 // addr | 0x1 to indicate ARM THUMB Mode

    if bigEndian {
        mc.ks, _ = keystone.New(keystone.ARCH_ARM, keystone.MODE_THUMB + keystone.MODE_BIG_ENDIAN)
        mc.mu, _ = uc.NewUnicorn(uc.ARCH_ARM, uc.MODE_THUMB + uc.MODE_BIG_ENDIAN)
        mc.oldMu, _ = uc.NewUnicorn(uc.ARCH_ARM, uc.MODE_THUMB + uc.MODE_BIG_ENDIAN)
        mc.Prompt = "(thumbbe)> "
    } else {
        mc.ks, _ = keystone.New(keystone.ARCH_ARM, keystone.MODE_THUMB)
        mc.mu, _ = uc.NewUnicorn(uc.ARCH_ARM, uc.MODE_THUMB + uc.MODE_LITTLE_ENDIAN)
        mc.oldMu, _ = uc.NewUnicorn(uc.ARCH_ARM, uc.MODE_THUMB+ uc.MODE_LITTLE_ENDIAN)
        mc.Prompt = "(thumb)> "
    }

    mc.mu.MemMap(0x0000, 0x8000)
    mc.mu.RegWrite(mc.sp, 0x1000)
    mc.mu.RegWrite(mc.bp, 0x2000)

    mc.oldCtx, _ = mc.mu.ContextSave(nil)

    mc.regOrder = []string{
        "r0", "    r6", "r1", " r7/fp",
        "r2", "r13/sp", "r3", "r14/lr",
        "r4", "r15/pc", "r5", "cpsr",
    }
    mc.regs = map[string]int{
        "r0"        : uc.ARM_REG_R0,
        "r1"        : uc.ARM_REG_R1,
        "r2"        : uc.ARM_REG_R2,
        "r3"        : uc.ARM_REG_R3,
        "r4"        : uc.ARM_REG_R4,
        "r5"        : uc.ARM_REG_R5,
        "    r6"    : uc.ARM_REG_R6,
        " r7/fp"    : uc.ARM_REG_R7,

        "    r8"    : uc.ARM_REG_R8,
        "    r9"    : uc.ARM_REG_R9,
        "   r10"    : uc.ARM_REG_R10,
        "r11/fp"    : uc.ARM_REG_R11, // frame pointer(fp, like 'ebp')
        "r12/ip"    : uc.ARM_REG_R12, // intra-procedure call scratch register
        "r13/sp"    : uc.ARM_REG_R13, // stack pointer
        "r14/lr"    : uc.ARM_REG_R14, // link register
        "r15/pc"    : uc.ARM_REG_R15, // program counter
        "cpsr"      : uc.ARM_REG_CPSR,// current program status register
    }
    return mc
}
