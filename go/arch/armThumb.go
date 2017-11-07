package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
    as "github.com/poppycompass/asmshell/go"
)

func SetArmThumb(asmsh *as.AsmShell, bigEndian bool) {
    asmsh.CodeAddr  = 0x1000
    asmsh.PrintSize = 32 + 8
    asmsh.PrintMergin = 16
    asmsh.StackStart = 0x3000
    asmsh.StackSize   = 8 * 1024
    asmsh.StackAddr = asmsh.StackStart + (asmsh.StackSize / 2)

    asmsh.KeystoneArch = keystone.ARCH_ARM
    asmsh.UnicornArch = uc.ARCH_ARM
    if bigEndian {
        asmsh.KeystoneMode = keystone.MODE_THUMB + keystone.MODE_BIG_ENDIAN
        asmsh.UnicornMode = uc.MODE_THUMB + uc.MODE_BIG_ENDIAN
        asmsh.Prompt = "(arm-thumbeb)> "
    } else {
        asmsh.KeystoneMode = keystone.MODE_THUMB
        asmsh.UnicornMode = uc.MODE_THUMB
        asmsh.Prompt = "(arm-thumb)> "
    }
    asmsh.SavedCtx = nil
    asmsh.SavedStackSize = 256
    asmsh.SavedStack = make([]byte, asmsh.SavedStackSize)
    for i := uint64(0); i < asmsh.SavedStackSize; i++ {
        asmsh.SavedStack[i] = 0xFF
    }
    asmsh.RegOrder = []string{"r0", "    r6", "r1", " r7/fp", "r2", "r13/sp", "r3", "r14/lr", "r4", "r15/pc", "r5", "cpsr"}
    asmsh.Regs = map[string]int{
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
        "cpsr"    : uc.ARM_REG_CPSR,// current program status register
    }
    asmsh.SP = uc.ARM_REG_R13
    asmsh.PrintCtx = asmsh.PrintCtx16
}
