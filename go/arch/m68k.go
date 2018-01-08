package arch

import (
//    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
//    "github.com/bnagy/gapstone"
)

// keystone is not supported, rasm2 supports only disassembler
func SetM68k(strArch string) Machine {
    var mc Machine
    mc.bit = 32
    mc.sp = uc.M68K_REG_A7
    mc.bp = uc.M68K_REG_SR // correct?
    mc.start = 0x0000

    //mc.ks, _ = keystone.New(keystone.ARCH_ARM, keystone.MODE_ARM + keystone.MODE_BIG_ENDIAN)
    mc.mu, _ = uc.NewUnicorn(uc.ARCH_M68K, uc.MODE_BIG_ENDIAN)
    mc.oldMu, _ = uc.NewUnicorn(uc.ARCH_M68K, uc.MODE_BIG_ENDIAN)
    //mc.cs = nil
    mc.Prompt = "(" + strArch + ")> "

    mc.regOrder = []string{
        "d0", "a0", "d1", "a1",
        "d2", " a2", "d3", "a3",
        "d4", "a4", "d5", "a5",
        "d6", "a6", "d7", "a7/sp",
        "pc", "sr",
    }
    mc.regs = map[string]int{
        "d0"    : uc.M68K_REG_D0,
        "d1"    : uc.M68K_REG_D1,
        "d2"    : uc.M68K_REG_D2,
        "d3"    : uc.M68K_REG_D3,
        "d4"    : uc.M68K_REG_D4,
        "d5"    : uc.M68K_REG_D5,
        "d6"    : uc.M68K_REG_D6,
        "d7"    : uc.M68K_REG_D7,
        "a0"    : uc.M68K_REG_A0,
        "a1"    : uc.M68K_REG_A1,
        "a2"    : uc.M68K_REG_A2,
        "a3"    : uc.M68K_REG_A3,
        "a4"    : uc.M68K_REG_A4,
        "a5"    : uc.M68K_REG_A5,
        "a6"    : uc.M68K_REG_A6,
        "a7/sp" : uc.M68K_REG_A7,
        "pc"    : uc.M68K_REG_PC,
        "sr"    : uc.M68K_REG_SR,
    }
    return mc
}
