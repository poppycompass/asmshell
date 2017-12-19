package arch

import (
    "fmt"
    "strings"
    "github.com/poppycompass/ishell"
    "github.com/poppycompass/asmshell/go/utils"
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

var FMT = []string{"0x%04x", "0x%08x", "0x%016x", "0x%032x"}

type Machine struct {
    Prompt string
    mu unicorn.Unicorn
    oldMu unicorn.Unicorn
    ks *keystone.Keystone

    bit int // 16, 32, 64, maybe 128?
    sp int  // stack pointer
    bp int  // base pointer
    start int // code addr
    regOrder []string
    regs map[string]int
    oldCtx unicorn.Context
}

var pallet utils.Pallet

func SetArch(strArch string) Machine {
    var mc Machine
    switch strArch {
        case "i8086"       : mc = SetI8086(strArch)
        case "x86"         : mc = SetX86(strArch)
        case "x64"         : mc = SetX64(strArch)
        case "thumb"       : mc = SetArmThumb(strArch, false)
        case "thumbbe"     : mc = SetArmThumb(strArch, true)
        case "arm"         : mc = SetArm(strArch, false)
        case "armbe"       : mc = SetArm(strArch, true)
        case "arm64"       : mc = SetArm64(strArch, false)    // TODO: test, fixme: something wrong?
        //case "arm64be"     : mc = SetArm64(strArch, true)     // keystone UNSUPPORTED?, unicorn: supported, fixme: something wrong?

        case "mips"        : mc = SetMips(strArch, false)
        case "mipsbe"      : mc = SetMips(strArch, true)
        case "mips64"      : mc = SetMips64(strArch, false) // fixme: something wrong?
        case "mips64be"    : mc = SetMips64(strArch, true)  // fixme: something wrong?
        case "sparc"       : mc = SetSparc(strArch, true)   // sparc standard is big-endian
        case "sparcle"     : mc = SetSparc(strArch, false)  // assemble only, unicorn: UNSUPPORTED, keystone: supported
        case "sparc64"     : mc = SetSparc64(strArch, true) // fixme: something wrong?, sparc standard is big-endian, keystone sparc64el does not supported
        case "ppc",     // big-endian, assemble only
             "powerpc"     : mc = SetPowerPC(strArch, true)
        case "ppc64",   // assemble only
             "powerpc64"   : mc = SetPowerPC64(strArch, true)
        case "ppc64le", // assemble only
             "powerpc64le" : mc = SetPowerPC64(strArch, false)
        case "sysz",
             "systemz",
             "systemZ"     : mc = SetSystemZ(strArch)
        //case "m68k"        : mc = SetM68k(strArch) // unicorn: supported, keystone: UNSUPPORTED
        default            : mc = SetX86(strArch)
    }
    return mc
}
// assemble and emulate(for ishell)
func (mc Machine) IshellRun(c *ishell.Context, mnemonic string) error {
    pallet = utils.InitPallet()
    code, err := mc.Assemble(mnemonic)
    if err != nil {
        return err
    }

    c.ColorPrintf(pallet.BoldWhite, "mnemonic: %s [ hex: %x ]\n", mnemonic, code)
    if mc.mu == nil { // if unicorn does not supported
        return nil
    }
    if err := mc.Emulate(code); err != nil {
        return err
    }

    mc.showCtx(c)
    mc.oldCtx, _ = mc.mu.ContextSave(nil)
    return nil
}

// assemble and emulate only does not output
func (mc Machine) Run(mnemonic string) error {
    code, err := mc.Assemble(mnemonic)
    if err != nil {
        return err
    }
    if mc.mu == nil { // if unicorn does not supported
        return nil
    }
    if err := mc.Emulate(code); err != nil {
        return err
    }
    mc.oldCtx, _ = mc.mu.ContextSave(nil)
    return nil
}

func (mc Machine) Assemble(mnemonic string) ([]byte, error) {
    // TODO: What is the effect of the second argument(address) of Assemble
    code, cnt, ok := mc.ks.Assemble(mnemonic, 0)
    if !ok || cnt == 0 {
        return nil, fmt.Errorf("Error: assemble instruction(%s)", mnemonic)
    }
    return code, nil
}

func (mc Machine) Emulate(code []byte) error {
    var (
        opts = unicorn.UcOptions{Timeout:60000000, Count:0} // Timeout is microseconds, now: 60 seconds
        codeEnd uint64
    )

    if strings.Contains(mc.Prompt, "thumb") { // arm thumb mode
        codeEnd = uint64(mc.start)+uint64(len(code))-1
        mc.mu.MemWrite(uint64(mc.start-1), code)
    } else {
        codeEnd = uint64(mc.start)+uint64(len(code))
        mc.mu.MemWrite(uint64(mc.start), code)
    }

    if err := mc.mu.StartWithOptions(uint64(mc.start), codeEnd, &opts); err != nil {
        return err
    }

    return nil
}

func (mc Machine) showCtx(c *ishell.Context) error {
    var (
        cpuBannar   = "---------------------------- CPU CONTEXT ----------------------------\n"
        stackBannar = "\n---------------------------- STACK TRACE ----------------------------\n"
    )

    mc.oldMu.ContextRestore(mc.oldCtx)
    // print cpu context
    c.ColorPrintf(pallet.BoldCyan, cpuBannar)
    for idx, key := range mc.regOrder {
        reg, _ := mc.mu.RegRead(mc.regs[key])
        oldReg, _ := mc.oldMu.RegRead(mc.regs[key])

        if idx != 0 && idx % 2 == 0 {
            c.Printf("\n")
        }

        if key == "eflags" || key == "cpsr" || key == "nzcv" { // x86, arm, arm64
            mc.showStatusReg(c, key, reg, oldReg)
        } else {
            if reg != oldReg {
                c.ColorPrintf(pallet.HiRed, "%s:    "+FMT[mc.bit/32]+"   ", key, reg)
            } else {
                c.Printf("%s:    "+FMT[mc.bit/32]+"   ", key, reg)
            }
        }
    }

    // print stack
    c.ColorPrintf(pallet.BoldYellow, stackBannar)
    mc.showStack(c)
    return nil
}
// TODO: simple code
func (mc Machine) showStack(c *ishell.Context) error {
    sp, _ := mc.mu.RegRead(mc.sp)
    data, _ := mc.mu.MemRead(sp-uint64(mc.bit), 256)
    bit := mc.bit

    for i := 0; i < (bit/2*5); i+=(bit/2) {
        c.Printf(FMT[bit/32]+": ", sp-uint64(bit)+uint64(i)) // print stack addr
        for j := 0; j < (bit/2); j+=(bit/8) {
            if bit == (i-j) { // if addr == esp
                for k := (bit/8); k > 0; k-=1 {
                    c.ColorPrintf(pallet.HiRed, "%02x", data[i+j+k-1])
                }
            } else {
                for k := (bit/8); k > 0; k-=1 {
                    c.ColorPrintf(pallet.HiYellow, "%02x", data[i+j+k-1])
                }
            }
            c.ColorPrintf(pallet.Yellow, " ")
        }
        c.ColorPrintf(pallet.Yellow, "|")

        // print ascii dump
        for j := 0; j < (bit/2); j+=(bit/8) {
            for k := (bit/8); k > 0; k-=1 {
                chr := data[i+j+k-1]
                if chr >= 0x20 && chr <= 0x7E {
                    c.ColorPrintf(pallet.Yellow, "%c", chr)
                } else {
                    c.ColorPrintf(pallet.Yellow, ".")
                }
            }
        }
        c.ColorPrintf(pallet.Yellow, "|\n")
    }
    return nil
}

func (mc Machine) showStatusReg(c *ishell.Context, key string, reg uint64, oldReg uint64) {
    var (
        flags map[string]uint
        order []string
    )
    switch key {
        case "eflags": flags = map[string]uint{"CF":0, "PF":2, "AF":4, "ZF":6, "SF":7, "IF":9, "DF":10, "OF":11} // intel
                       order = []string{"CF", "PF", "AF", "ZF", "SF", "IF", "DF", "OF"}
        // T=0/1:Arm/Thumb state, E:Endian, Q: sticky overflow?, V:oVerflow, C:Carry out, Z:Zero, N:Negative
        case "cpsr":   flags = map[string]uint{"T":5, "E":9, "Q":27, "V":28, "C":29, "Z":30, "N":31} // arm
                       order = []string{"T", "E", "Q", "V", "C", "Z", "N"}
        case "nzcv":   flags = map[string]uint{"V":28, "C":29, "Z":30, "N":31} // arm64, oVerflow/Carry out/Zero/Negative
                       order = []string{"V", "C", "Z", "N"}
    }

    c.Printf("%s: 0x%08x [ ", key, reg)
    for _, key := range order {
        if (reg>>flags[key])&0x1 != (oldReg>>flags[key])&0x1 {
            c.ColorPrintf(pallet.HiRed, "%s(%d) ", key, (reg>>flags[key])&0x1)
        } else {
            c.Printf("%s(%d) ", key, (reg>>flags[key])&0x1)
        }
    }
    c.Printf("]")
}

func (mc Machine) RegRead(key string) (uint64, error) {
    return mc.mu.RegRead(mc.regs[key])
}

func (mc Machine) RegWrite(key string, val uint64) error {
    return mc.mu.RegWrite(mc.regs[key], val)
}

func (mc Machine) MemRead(addr uint64, size uint64) ([]byte, error) {
    return mc.mu.MemRead(addr, size)
}

func (mc Machine) MemWrite(addr uint64, data []byte) error {
    return mc.mu.MemWrite(addr, data)
}

func (mc Machine) Finalize() {
    mc.ks.Close()
}
