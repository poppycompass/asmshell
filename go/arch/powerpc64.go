package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
    as "github.com/poppycompass/asmshell/go"
)

// sample: add 1,2,3
func SetPowerPC64(asmsh *as.AsmShell, bigEndian bool) {
    asmsh.CodeAddr  = 0x100000
    asmsh.PrintSize = 128 + 32
    asmsh.PrintMergin = 64
    asmsh.StackStart = 0x300000
    asmsh.StackSize   = 2 * 1024 * 1024
    asmsh.StackAddr = asmsh.StackStart + (asmsh.StackSize / 2)

    asmsh.KeystoneArch = keystone.ARCH_PPC
    asmsh.UnicornArch = uc.ARCH_MAX
    if bigEndian {
        asmsh.KeystoneMode = keystone.MODE_PPC64 + keystone.MODE_BIG_ENDIAN
        //asmsh.UnicornMode = uc.MODE_MIPS64 + uc.MODE_BIG_ENDIAN
        asmsh.Prompt = "(ppc64)> "
    } else {
        asmsh.KeystoneMode = keystone.MODE_PPC64 + uc.MODE_LITTLE_ENDIAN
        //asmsh.UnicornMode = uc.MODE_MIPS64 + uc.MODE_LITTLE_ENDIAN
        asmsh.Prompt = "(ppc64el)> "
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
    asmsh.PrintCtx = asmsh.PrintCtx64
}
