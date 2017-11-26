package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)
// mov r0, 0x37; sub r1, r2, r3;
// mov r0, 0x3344; movt r0, 0x1122; str r0, [sp]
func SetArm(strArch string, bigEndian bool) Machine {
    var mc Machine
    mc.bit = 32
    mc.sp = uc.ARM_REG_R13
    mc.bp = uc.ARM_REG_R11
    mc.start = 0x0000

    if bigEndian {
        mc.ks, _ = keystone.New(keystone.ARCH_ARM, keystone.MODE_ARM + keystone.MODE_BIG_ENDIAN)
        mc.mu, _ = uc.NewUnicorn(uc.ARCH_ARM, uc.MODE_ARM + uc.MODE_BIG_ENDIAN)
        mc.oldMu, _ = uc.NewUnicorn(uc.ARCH_ARM, uc.MODE_ARM + uc.MODE_BIG_ENDIAN)
    } else {
        mc.ks, _ = keystone.New(keystone.ARCH_ARM, keystone.MODE_ARM + keystone.MODE_LITTLE_ENDIAN)
        mc.mu, _ = uc.NewUnicorn(uc.ARCH_ARM, uc.MODE_ARM)
        mc.oldMu, _ = uc.NewUnicorn(uc.ARCH_ARM, uc.MODE_ARM)
    }
    mc.Prompt = "(" + strArch + ")> "

    mc.mu.MemMap(0x0000, 0x2000)
    mc.mu.RegWrite(mc.sp, 0x1000)
    mc.mu.RegWrite(mc.bp, 0x8000)

    mc.oldCtx, _ = mc.mu.ContextSave(nil)

    mc.regOrder = []string{
        "r0", "    r8", "r1", "    r9",
        "r2", "   r10", "r3", "r11/fp",
        "r4", "r12/ip", "r5", "r13/sp",
        "r6", "r14/lr", "r7", "r15/pc",
        "cpsr",
    }
    mc.regs = map[string]int{
        "r0"        : uc.ARM_REG_R0,
        "r1"        : uc.ARM_REG_R1,
        "r2"        : uc.ARM_REG_R2,
        "r3"        : uc.ARM_REG_R3,
        "r4"        : uc.ARM_REG_R4,
        "r5"        : uc.ARM_REG_R5,
        "r6"        : uc.ARM_REG_R6,
        "r7"        : uc.ARM_REG_R7,
        "    r8"    : uc.ARM_REG_R8,
        "    r9"    : uc.ARM_REG_R9,
        "   r10"    : uc.ARM_REG_R10,
        "r11/fp"    : uc.ARM_REG_R11, // frame pointer(fp, like 'ebp')
        "r12/ip"    : uc.ARM_REG_R12, // intra-procedure call scratch register
        "r13/sp"    : uc.ARM_REG_R13, // stack pointer
        "r14/lr"    : uc.ARM_REG_R14, // link register, return address
        "r15/pc"    : uc.ARM_REG_R15, // program counter
        "cpsr"      : uc.ARM_REG_CPSR,// current program status register
    }
    return mc
}
