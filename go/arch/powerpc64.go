package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
//    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

// sample: add 1,2,3
func SetPowerPC64(bigEndian bool) Machine {
    var mc Machine
    if bigEndian {
        mc.ks, _ = keystone.New(keystone.ARCH_PPC, keystone.MODE_PPC64 + keystone.MODE_BIG_ENDIAN)
        mc.mu = nil
        mc.Prompt = "(ppc64)> "
    } else {
        mc.ks, _ = keystone.New(keystone.ARCH_PPC, keystone.MODE_PPC64 + keystone.MODE_LITTLE_ENDIAN)
        mc.mu = nil
        mc.Prompt = "(ppc64el)> "
    }
    return mc
}
