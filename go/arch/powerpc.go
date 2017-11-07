package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
    as "github.com/poppycompass/asmshell/go"
)

// sample: add, 1, 2, 3
func SetPowerPC(asmsh *as.AsmShell, bigEndian bool) {
    asmsh.CodeAddr  = 0x100000
    asmsh.PrintSize = 64 + 16
    asmsh.PrintMergin = 32
    asmsh.StackStart = 0x300000
    asmsh.StackSize   = 2 * 1024 * 1024
    asmsh.StackAddr = asmsh.StackStart + (asmsh.StackSize / 2)

    asmsh.KeystoneArch = keystone.ARCH_PPC
    if bigEndian {
        asmsh.UnicornArch = uc.ARCH_MAX
        asmsh.KeystoneMode = keystone.MODE_PPC32 + keystone.MODE_BIG_ENDIAN
        //asmsh.UnicornMode = uc.MODE_PPC32 | uc.MODE_BIG_ENDIAN
        asmsh.Prompt = "(powerpc)> "
    } else {
        asmsh.UnicornArch = uc.ARCH_MAX
        asmsh.KeystoneMode = keystone.MODE_PPC32 + keystone.MODE_LITTLE_ENDIAN
        //asmsh.UnicornMode = uc.MODE_PPC32 | uc.MODE_LITTLE_ENDIAN
        asmsh.Prompt = "(ppcel)> "
    }
    asmsh.SavedCtx = nil
    asmsh.SavedStackSize = 256
    asmsh.SavedStack = make([]byte, asmsh.SavedStackSize)
    for i := uint64(0); i < asmsh.SavedStackSize; i++ {
        asmsh.SavedStack[i] = 0xFF
    }
    asmsh.RegOrder = []string{}
    asmsh.Regs = map[string]int{}
    asmsh.SP = 0 // dummy
    asmsh.PrintCtx = asmsh.PrintCtx32
}
