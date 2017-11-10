package arch

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

// sample: mov ecx, 0x20; j1:; inc eax; dec ecx; jnz j1
func SetX86() Machine {
    var mc Machine
    mc.Prompt = "(x86)> "
    mc.bit = 32
    mc.sp = uc.X86_REG_ESP
    mc.bp = uc.X86_REG_EBP

    mc.ks, _ = keystone.New(keystone.ARCH_X86, keystone.MODE_32)
    mc.ks.Option(keystone.OPT_SYNTAX, keystone.OPT_SYNTAX_INTEL)

    mc.mu, _ = uc.NewUnicorn(uc.ARCH_X86, uc.MODE_32)
    mc.mu.MemMap(0x0000, 0x200000)
    mc.mu.RegWrite(mc.sp, 0x100000)
    mc.mu.RegWrite(mc.bp, 0x80000)

    mc.oldCtx, _ = mc.mu.ContextSave(nil)
    mc.oldMu, _ = uc.NewUnicorn(uc.ARCH_X86, uc.MODE_32)


    mc.regOrder = []string{
        "eax", "eip", "ebx", "eflags",
        "ecx", " cs", "edx", " ss",
        "esp", " ds", "ebp", " es",
        "esi", " fs", "edi", " gs",
    }
    mc.regs = map[string]int{
        "eax"    : uc.X86_REG_EAX,
        "ebx"    : uc.X86_REG_EBX,
        "ecx"    : uc.X86_REG_ECX,
        "edx"    : uc.X86_REG_EDX,
        "eip"    : uc.X86_REG_EIP,
        "esp"    : uc.X86_REG_ESP,
        "ebp"    : uc.X86_REG_EBP,
        "esi"    : uc.X86_REG_ESI,
        "edi"    : uc.X86_REG_EDI,
        "eflags" : uc.X86_REG_EFLAGS,
        " cs"    : uc.X86_REG_CS,
        " ss"    : uc.X86_REG_SS,
        " ds"    : uc.X86_REG_DS,
        " es"    : uc.X86_REG_ES,
        " fs"    : uc.X86_REG_FS,
        " gs"    : uc.X86_REG_GS,
    }
    return mc
}
