package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
//    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
    "github.com/bnagy/gapstone"
)

// sample: a %r0, 4095(%r15,%r1)
func SetSystemZ(strArch string) Machine {
    var mc Machine

    mc.ks, _ = keystone.New(keystone.ARCH_SYSTEMZ, keystone.MODE_BIG_ENDIAN)
    mc.mu = nil
    mc.Prompt = "(" + strArch + ")> "

    mc.cs, _ = gapstone.New(
        gapstone.CS_ARCH_SYSZ,
        gapstone.CS_MODE_BIG_ENDIAN,
    )

    return mc
}
