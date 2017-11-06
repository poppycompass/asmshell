package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
    as "github.com/poppycompass/asmshell/go"
)

func InitArm(asmsh *as.AsmShell) {
    asmsh.CodeAddr  = 0x100000
    asmsh.PrintSize = 64 + 16
    asmsh.PrintMergin = 32
    asmsh.StackStart = 0x300000
    asmsh.StackSize   = 2 * 1024 * 1024
    asmsh.StackAddr = asmsh.StackStart + (asmsh.StackSize / 2)

    asmsh.KeystoneArch = keystone.ARCH_ARM
    asmsh.KeystoneMode = keystone.MODE_ARM
/*     asmsh.KeystoneOPTType = keystone.OPT_SYNTAX */
/*     asmsh.KeystoneOPTVal = keystone.OPT_SYNTAX_INTEL */
    asmsh.UnicornArch = uc.ARCH_ARM
    asmsh.UnicornMode = uc.MODE_ARM
    asmsh.SavedCtx = nil
    asmsh.SavedStackSize = 256
    asmsh.SavedStack = make([]byte, asmsh.SavedStackSize)
    for i := uint64(0); i < asmsh.SavedStackSize; i++ {
        asmsh.SavedStack[i] = 0xFF
    }
    asmsh.Prompt = "(arm)> "
    asmsh.RegOrder = []string{"r0",  "    r8", "r1", "    r9", "r2", "   r10", "r3", "r11/fp", "r4", "r12/ip", "r5", "r13/sp", "r6", "r14/lr", "r7", "r15/pc", "cpsr"}
    asmsh.Regs = map[string]int{
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
        "r14/lr"    : uc.ARM_REG_R14, // link register
        "r15/pc"    : uc.ARM_REG_R15, // program counter
        "cpsr"      : uc.ARM_REG_CPSR,// current program status register
    }
    asmsh.SP = uc.ARM_REG_R13
    asmsh.PrintCtx = asmsh.PrintCtx32
}
