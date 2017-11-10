package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

// sample: inc ax; push ax; pop dx
func SetI8086() Machine {
    var mc Machine
    mc.Prompt = "(i8086)> "
    mc.bit = 16
    mc.sp = uc.X86_REG_SP
    mc.bp = uc.X86_REG_BP

    mc.ks, _ = keystone.New(keystone.ARCH_X86, keystone.MODE_16)
    mc.ks.Option(keystone.OPT_SYNTAX, keystone.OPT_SYNTAX_INTEL)

    mc.mu, _ = uc.NewUnicorn(uc.ARCH_X86, uc.MODE_16)
    mc.mu.MemMap(0x0000, 0x2000)
    mc.mu.RegWrite(mc.sp, 0x1000)
    mc.mu.RegWrite(mc.bp, 0x8000)

    mc.oldCtx, _ = mc.mu.ContextSave(nil)
    mc.oldMu, _ = uc.NewUnicorn(uc.ARCH_X86, uc.MODE_16)

    mc.regOrder = []string{
        "ax", "ip", "bx", "eflags",
        "cx", "cs", "dx", "ss",
        "sp", "ds", "bp", "es",
        "si", "fs", "di", "gs",
    }
    mc.regs = map[string]int{
        "ax"    : uc.X86_REG_AX,
        "bx"    : uc.X86_REG_BX,
        "cx"    : uc.X86_REG_CX,
        "dx"    : uc.X86_REG_DX,
        "ip"    : uc.X86_REG_IP,
        "sp"    : uc.X86_REG_SP,
        "bp"    : uc.X86_REG_BP,
        "si"    : uc.X86_REG_SI,
        "di"    : uc.X86_REG_DI,
        "eflags" : uc.X86_REG_EFLAGS,
        "cs"    : uc.X86_REG_CS,
        "ss"    : uc.X86_REG_SS,
        "ds"    : uc.X86_REG_DS,
        "es"    : uc.X86_REG_ES,
        "fs"    : uc.X86_REG_FS,
        "gs"    : uc.X86_REG_GS,
    }
    return mc
}
