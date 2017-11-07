package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
    as "github.com/poppycompass/asmshell/go"
)

// sample: a %r0, 4095(%r15,%r1)
func InitSystemZ(asmsh *as.AsmShell) {
    asmsh.CodeAddr  = 0x100000
    asmsh.PrintSize = 64 + 16
    asmsh.PrintMergin = 32
    asmsh.StackStart = 0x300000
    asmsh.StackSize   = 2 * 1024 * 1024
    asmsh.StackAddr = asmsh.StackStart + (asmsh.StackSize / 2)

    asmsh.KeystoneArch = keystone.ARCH_SYSTEMZ
    asmsh.KeystoneMode = keystone.MODE_BIG_ENDIAN
    asmsh.UnicornArch = uc.ARCH_MAX
    //asmsh.UnicornMode = uc.MODE_32
    asmsh.SavedCtx = nil
    asmsh.SavedStackSize = 256
    asmsh.SavedStack = make([]byte, asmsh.SavedStackSize)
    for i := uint64(0); i < asmsh.SavedStackSize; i++ {
        asmsh.SavedStack[i] = 0xFF
    }
    asmsh.Prompt = "(systemZ)> "
    asmsh.RegOrder = []string{}
    asmsh.Regs = map[string]int{}
    asmsh.SP = 0 // dummy
    asmsh.PrintCtx = asmsh.PrintCtx32
}
