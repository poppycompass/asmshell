package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
//    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
//    "github.com/bnagy/gapstone"
)

// sample: add 1, 2, 3
// MEMO: sparc has status register
func SetPowerPC(strArch string, bigEndian bool) Machine {
    var mc Machine
    if bigEndian {
        mc.ks, _ = keystone.New(keystone.ARCH_PPC, keystone.MODE_PPC32 + keystone.MODE_BIG_ENDIAN)
        mc.mu = nil
        //mc.cs = nil
    } else {
        mc.ks, _ = keystone.New(keystone.ARCH_PPC, keystone.MODE_PPC32 + keystone.MODE_LITTLE_ENDIAN)
        mc.mu = nil
        //mc.cs = nil
    }
    mc.Prompt = "(" + strArch + ")> "
    return mc
}
