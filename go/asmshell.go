package asmshell

import (
    "fmt"
    "github.com/poppycompass/ishell"
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
    utils "github.com/poppycompass/asmshell/go/utils"
)
type AsmShell struct {
    CodeAddr uint64
    StackStart uint64
    StackAddr uint64
    StackSize uint64
    PrintSize uint64
    PrintMergin uint64

    KeystoneArch keystone.Architecture
    KeystoneMode keystone.Mode
    KeystoneOPTType keystone.OptionType
    KeystoneOPTVal keystone.OptionValue
    UnicornArch int
    UnicornMode int
    SavedCtx uc.Context
    SavedStack []byte
    SavedStackSize uint64
    Prompt string
    Pallet utils.Pallet
    Regs map[string]int
    RegOrder []string
    PrintCtx func(*ishell.Context, uc.Unicorn, string, []byte) error
}

func (asmsh *AsmShell) Assemble(mnemonic string) ([]byte, error){

    ks, err := keystone.New(asmsh.KeystoneArch, asmsh.KeystoneMode)
    if err != nil {
        return nil, err
    }
    defer ks.Close()

    if err := ks.Option(asmsh.KeystoneOPTType, asmsh.KeystoneOPTVal); err != nil {
        return nil, fmt.Errorf("Error: set syntax option to intel")
    }

    if code, _, ok := ks.Assemble(mnemonic, 0); !ok {
        return nil, fmt.Errorf("Error: assemble instruction")
    } else {
        return code, nil
    }
}
// assemble and run
func (asmsh *AsmShell) Emulate(c *ishell.Context, mnemonic string) error {
    code, err := asmsh.Assemble(mnemonic)
    if err != nil {
        return err
    }
    if err = asmsh.Run(c, mnemonic, code); err != nil {
        return err
    }
    return nil
}

func (asmsh *AsmShell) Run(c *ishell.Context, mnemonic string, code []byte) error {
    var sp uint64
    mu, err := uc.NewUnicorn(asmsh.UnicornArch, asmsh.UnicornMode)
    if err != nil {
        return err
    }
    if err := mu.MemMap(asmsh.CodeAddr, asmsh.StackSize); err != nil {
        return err
    }
    if err := mu.MemWrite(asmsh.CodeAddr, code); err != nil {
        return err
    }
    // create stack
    if err := mu.MemMap(asmsh.StackStart, asmsh.StackSize); err != nil {
        return err
    }

    if asmsh.SavedCtx != nil {
        err = mu.ContextRestore(asmsh.SavedCtx)
        if err != nil {
            return err
        }
    } else {
        if asmsh.UnicornMode == uc.MODE_16 {
            err = mu.RegWrite(asmsh.Regs["sp"], asmsh.StackAddr)
        } else if asmsh.UnicornMode == uc.MODE_32 {
            err = mu.RegWrite(asmsh.Regs["esp"], asmsh.StackAddr)
        } else if asmsh.UnicornMode == uc.MODE_64 {
            err = mu.RegWrite(asmsh.Regs["rsp"], asmsh.StackAddr)
        }
        if err != nil {
            return err
        }
    }
    if asmsh.UnicornMode == uc.MODE_16 {
        sp, err = mu.RegRead(asmsh.Regs["sp"])
    } else if asmsh.UnicornMode == uc.MODE_32 {
        sp, err = mu.RegRead(asmsh.Regs["esp"])
    } else if asmsh.UnicornMode == uc.MODE_64 {
        sp, err = mu.RegRead(asmsh.Regs["rsp"])
    }
    if err != nil {
        return err
    }
    err = mu.MemWrite(sp - (asmsh.SavedStackSize / 2), asmsh.SavedStack)
    if err != nil {
        return err
    }
    if err := mu.Start(asmsh.CodeAddr, asmsh.CodeAddr+uint64(len(code))); err != nil {
        return err
    }
    if asmsh.UnicornMode == uc.MODE_16 {
        sp, err = mu.RegRead(asmsh.Regs["sp"])
    } else if asmsh.UnicornMode == uc.MODE_32 {
        sp, err = mu.RegRead(asmsh.Regs["esp"])
    } else if asmsh.UnicornMode == uc.MODE_64 {
        sp, err = mu.RegRead(asmsh.Regs["rsp"])
    }
    if err != nil {
        return err
    }
    asmsh.SavedStack, err  = mu.MemRead(sp - (asmsh.SavedStackSize / 2), asmsh.SavedStackSize)
    if err != nil {
        return err
    }
    if err = asmsh.PrintCtx(c, mu, mnemonic, code); err != nil {
        return err
    }
    asmsh.SavedCtx, err = mu.ContextSave(nil)
    if err != nil {
        return err
    }
    return nil
}
func (asmsh *AsmShell) PrintCtx32(c *ishell.Context, mu uc.Unicorn, mnemonic string, code []byte) error {
    old, err := uc.NewUnicorn(asmsh.UnicornArch, asmsh.UnicornMode)
    if asmsh.SavedCtx != nil {
        err = old.ContextRestore(asmsh.SavedCtx)
        if err != nil {
            return err
        }
    } else {
        asmsh.SavedCtx, err = mu.ContextSave(nil)
        err = old.ContextRestore(asmsh.SavedCtx)
        if err != nil {
            return err
        }
    }
    c.ColorPrintf(asmsh.Pallet.BoldWhite, "mnemonic: %s [hex: %x]\n", mnemonic, code)
    c.ColorPrintf(asmsh.Pallet.BoldCyan, "---------------------------- CPU CONTEXT ----------------------------\n")
    for idx, key := range asmsh.RegOrder {
        reg, err := mu.RegRead(asmsh.Regs[key])
        if err != nil {
            return err
        }
        oldReg, err := old.RegRead(asmsh.Regs[key])
        if err != nil {
            return err
        }
        if idx != 0 && idx % 2 == 0 {
            c.Println("")
        }
        if key == "eflags" {
            if reg != oldReg {
                c.ColorPrintf(asmsh.Pallet.HiRed, "%s: 0x%08x", key, reg)
                c.ColorPrintf(asmsh.Pallet.HiWhite, " [ ")
                if (reg & 0x1) != (oldReg & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "CF(%d) ", reg&0x1)
                } else {
                    c.Printf("CF(%d) ", reg&0x1)
                }
                if ((reg>>2) & 0x1) != ((oldReg>>2) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "PF(%d) ", (reg>>2)&0x1)
                } else {
                    c.Printf("PF(%d) ", (reg>>2)&0x1)
                }
                if ((reg>>4) & 0x1) != ((oldReg>>4) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "AF(%d) ", (reg>>4)&0x1)
                } else {
                    c.Printf("AF(%d) ", (reg>>4)&0x1)
                }
                if ((reg>>6) & 0x1) != ((oldReg>>6) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "ZF(%d) ", (reg>>6)&0x1)
                } else {
                    c.Printf("ZF(%d) ", (reg>>6)&0x1)
                }
                if ((reg>>7) & 0x1) != ((oldReg>>7) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "SF(%d) ", (reg>>7)&0x1)
                } else {
                    c.Printf("SF(%d) ", (reg>>7)&0x1)
                }
                if ((reg>>9) & 0x1) != ((oldReg>>9) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "IF(%d) ", (reg>>9)&0x1)
                } else {
                    c.Printf("IF(%d) ", (reg>>9)&0x1)
                }
                if ((reg>>10) & 0x1) != ((oldReg>>10) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "DF(%d) ", (reg>>10)&0x1)
                } else {
                    c.Printf("DF(%d) ", (reg>>10)&0x1)
                }
                if ((reg>>11) & 0x1) != ((oldReg>>11) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "OF(%d) ", (reg>>10)&0x1)
                } else {
                    c.Printf("OF(%d) ", (reg>>10)&0x1)
                }
                c.Printf("]")
            } else {
                c.Printf("%s: 0x%08x [ CF(%d) PF(%d) AF(%d) ZF(%d) SF(%d) IF(%d) DF(%d) OF(%d) ]",
                  key, reg, reg & 0x1, (reg>>2)&0x1, (reg>>4)&0x1, (reg>>6)&0x1, (reg>>7)&0x1, (reg>>9)&0x1, (reg>>10)&0x1, (reg>>11)&0x1)
            }
        } else {
            if reg != oldReg {
                //c.ColorPrintf(asmsh.Pallet.HiRed, "%s:    0x%08x(old: %08x)   ", key, reg, oldReg)
                c.ColorPrintf(asmsh.Pallet.HiRed, "%s:    0x%08x   ", key, reg)
            } else {
                c.Printf("%s:    0x%08x   ", key, reg)
            }
        }
    }
    c.ColorPrintf(asmsh.Pallet.BoldYellow, "\n---------------------------- STACK TRACE ----------------------------\n")
    asmsh.HexPrint32(c, mu)
    return nil
}
// TODO: simple code
func (asmsh *AsmShell) HexPrint32(c *ishell.Context, mu uc.Unicorn) error {
    var middle uint64 = 32
    esp, err := mu.RegRead(asmsh.Regs["esp"])
    if err != nil {
        return err
    }
    for i := uint64(0); i < asmsh.PrintSize; i+=16 {
        c.Printf("0x%08x: ", esp-middle+i)
        for j := uint64(0); j < 16; j+=4 {
            if middle == (i-j) {
                c.ColorPrintf(asmsh.Pallet.HiRed, "%02x%02x%02x%02x ",
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+3],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+2],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+1],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j])
            } else {
                c.ColorPrintf(asmsh.Pallet.HiYellow, "%02x%02x%02x%02x ",
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+3],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+2],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+1],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j])
            }
        }
        c.ColorPrintf(asmsh.Pallet.Yellow, "|")
        for j := uint64(0); j < 16; j+=4 {
            for k := uint64(4); k > 0; k-=1 {
                chr := asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+k-1]
                if chr >= 0x20 && chr <= 0x7E {
                    c.ColorPrintf(asmsh.Pallet.Yellow, "%c", chr)
                } else {
                    c.ColorPrintf(asmsh.Pallet.Yellow, ".")
                }
            }
        }
        c.ColorPrintf(asmsh.Pallet.Yellow, "|\n")
    }
    return nil
}


func (asmsh *AsmShell) PrintCtx16(c *ishell.Context, mu uc.Unicorn, mnemonic string, code []byte) error {
    old, err := uc.NewUnicorn(asmsh.UnicornArch, asmsh.UnicornMode)
    if asmsh.SavedCtx != nil {
        err = old.ContextRestore(asmsh.SavedCtx)
        if err != nil {
            return err
        }
    } else {
        asmsh.SavedCtx, err = mu.ContextSave(nil)
        err = old.ContextRestore(asmsh.SavedCtx)
        if err != nil {
            return err
        }
    }
    c.ColorPrintf(asmsh.Pallet.BoldWhite, "mnemonic: %s [hex: %x]\n", mnemonic, code)
    c.ColorPrintf(asmsh.Pallet.BoldCyan, "---------------------------- CPU CONTEXT ----------------------------\n")
    for idx, key := range asmsh.RegOrder {
        reg, err := mu.RegRead(asmsh.Regs[key])
        if err != nil {
            return err
        }
        oldReg, err := old.RegRead(asmsh.Regs[key])
        if err != nil {
            return err
        }
        if idx != 0 && idx % 2 == 0 {
            c.Println("")
        }
        if key == "eflags" {
            if reg != oldReg {
                c.ColorPrintf(asmsh.Pallet.HiRed, "%s: 0x%04x", key, reg)
                c.ColorPrintf(asmsh.Pallet.HiWhite, " [ ")
                if (reg & 0x1) != (oldReg & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "CF(%d) ", reg&0x1)
                } else {
                    c.Printf("CF(%d) ", reg&0x1)
                }
                if ((reg>>2) & 0x1) != ((oldReg>>2) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "PF(%d) ", (reg>>2)&0x1)
                } else {
                    c.Printf("PF(%d) ", (reg>>2)&0x1)
                }
                if ((reg>>4) & 0x1) != ((oldReg>>4) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "AF(%d) ", (reg>>4)&0x1)
                } else {
                    c.Printf("AF(%d) ", (reg>>4)&0x1)
                }
                if ((reg>>6) & 0x1) != ((oldReg>>6) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "ZF(%d) ", (reg>>6)&0x1)
                } else {
                    c.Printf("ZF(%d) ", (reg>>6)&0x1)
                }
                if ((reg>>7) & 0x1) != ((oldReg>>7) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "SF(%d) ", (reg>>7)&0x1)
                } else {
                    c.Printf("SF(%d) ", (reg>>7)&0x1)
                }
                if ((reg>>9) & 0x1) != ((oldReg>>9) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "IF(%d) ", (reg>>9)&0x1)
                } else {
                    c.Printf("IF(%d) ", (reg>>9)&0x1)
                }
                if ((reg>>10) & 0x1) != ((oldReg>>10) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "DF(%d) ", (reg>>10)&0x1)
                } else {
                    c.Printf("DF(%d) ", (reg>>10)&0x1)
                }
                if ((reg>>11) & 0x1) != ((oldReg>>11) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "OF(%d) ", (reg>>10)&0x1)
                } else {
                    c.Printf("OF(%d) ", (reg>>10)&0x1)
                }
                c.Printf("]")
            } else {
                c.Printf("%s: 0x%04x [ CF(%d) PF(%d) AF(%d) ZF(%d) SF(%d) IF(%d) DF(%d) OF(%d) ]",
                  key, reg, reg & 0x1, (reg>>2)&0x1, (reg>>4)&0x1, (reg>>6)&0x1, (reg>>7)&0x1, (reg>>9)&0x1, (reg>>10)&0x1, (reg>>11)&0x1)
            }
        } else {
            if reg != oldReg {
                //c.ColorPrintf(asmsh.Pallet.HiRed, "%s:    0x%04x(old: %04x)   ", key, reg, oldReg)
                c.ColorPrintf(asmsh.Pallet.HiRed, "%s:    0x%04x   ", key, reg)
            } else {
                c.Printf("%s:    0x%04x   ", key, reg)
            }
        }
    }
    c.ColorPrintf(asmsh.Pallet.BoldYellow, "\n---------------------------- STACK TRACE ----------------------------\n")
    asmsh.HexPrint16(c, mu)
    return nil
}
// TODO: simple code
func (asmsh *AsmShell) HexPrint16(c *ishell.Context, mu uc.Unicorn) error {
    var middle uint64 = 16
    sp, err := mu.RegRead(asmsh.Regs["sp"])
    if err != nil {
        return err
    }
    for i := uint64(0); i < asmsh.PrintSize; i+=8 {
        c.Printf("0x%04x: ", sp-middle+i)
        for j := uint64(0); j < 8; j+=2 {
            if middle == (i-j) {
                c.ColorPrintf(asmsh.Pallet.HiRed, "%02x%02x ",
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+1],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j])
            } else {
                c.ColorPrintf(asmsh.Pallet.HiYellow, "%02x%02x ",
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+1],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j])
            }
        }
        c.ColorPrintf(asmsh.Pallet.Yellow, "|")
        for j := uint64(0); j < 8; j+=2 {
            for k := uint64(2); k > 0; k-=1 {
                chr := asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+k-1]
                if chr >= 0x20 && chr <= 0x7E {
                    c.ColorPrintf(asmsh.Pallet.Yellow, "%c", chr)
                } else {
                    c.ColorPrintf(asmsh.Pallet.Yellow, ".")
                }
            }
        }
        c.ColorPrintf(asmsh.Pallet.Yellow, "|\n")
    }
    return nil
}
func (asmsh *AsmShell) PrintCtx64(c *ishell.Context, mu uc.Unicorn, mnemonic string, code []byte) error {
    old, err := uc.NewUnicorn(asmsh.UnicornArch, asmsh.UnicornMode)
    if asmsh.SavedCtx != nil {
        err = old.ContextRestore(asmsh.SavedCtx)
        if err != nil {
            return err
        }
    } else {
        asmsh.SavedCtx, err = mu.ContextSave(nil)
        err = old.ContextRestore(asmsh.SavedCtx)
        if err != nil {
            return err
        }
    }
    c.ColorPrintf(asmsh.Pallet.BoldWhite, "mnemonic: %s [hex: %x]\n", mnemonic, code)
    c.ColorPrintf(asmsh.Pallet.BoldCyan, "---------------------------- CPU CONTEXT ----------------------------\n")
    for idx, key := range asmsh.RegOrder {
        reg, err := mu.RegRead(asmsh.Regs[key])
        if err != nil {
            return err
        }
        oldReg, err := old.RegRead(asmsh.Regs[key])
        if err != nil {
            return err
        }
        if idx != 0 && idx % 2 == 0 {
            c.Println("")
        }
        if key == "eflags" {
            if reg != oldReg {
                c.ColorPrintf(asmsh.Pallet.HiRed, "%s: 0x%016x", key, reg)
                c.ColorPrintf(asmsh.Pallet.HiWhite, " [ ")
                if (reg & 0x1) != (oldReg & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "CF(%d) ", reg&0x1)
                } else {
                    c.Printf("CF(%d) ", reg&0x1)
                }
                if ((reg>>2) & 0x1) != ((oldReg>>2) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "PF(%d) ", (reg>>2)&0x1)
                } else {
                    c.Printf("PF(%d) ", (reg>>2)&0x1)
                }
                if ((reg>>4) & 0x1) != ((oldReg>>4) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "AF(%d) ", (reg>>4)&0x1)
                } else {
                    c.Printf("AF(%d) ", (reg>>4)&0x1)
                }
                if ((reg>>6) & 0x1) != ((oldReg>>6) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "ZF(%d) ", (reg>>6)&0x1)
                } else {
                    c.Printf("ZF(%d) ", (reg>>6)&0x1)
                }
                if ((reg>>7) & 0x1) != ((oldReg>>7) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "SF(%d) ", (reg>>7)&0x1)
                } else {
                    c.Printf("SF(%d) ", (reg>>7)&0x1)
                }
                if ((reg>>9) & 0x1) != ((oldReg>>9) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "IF(%d) ", (reg>>9)&0x1)
                } else {
                    c.Printf("IF(%d) ", (reg>>9)&0x1)
                }
                if ((reg>>10) & 0x1) != ((oldReg>>10) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "DF(%d) ", (reg>>10)&0x1)
                } else {
                    c.Printf("DF(%d) ", (reg>>10)&0x1)
                }
                if ((reg>>11) & 0x1) != ((oldReg>>11) & 0x1) {
                    c.ColorPrintf(asmsh.Pallet.HiRed, "OF(%d) ", (reg>>10)&0x1)
                } else {
                    c.Printf("OF(%d) ", (reg>>10)&0x1)
                }
                c.Printf("]")
            } else {
                c.Printf("%s: 0x%016x [ CF(%d) PF(%d) AF(%d) ZF(%d) SF(%d) IF(%d) DF(%d) OF(%d) ]",
                  key, reg, reg & 0x1, (reg>>2)&0x1, (reg>>4)&0x1, (reg>>6)&0x1, (reg>>7)&0x1, (reg>>9)&0x1, (reg>>10)&0x1, (reg>>11)&0x1)
            }
        } else {
            if reg != oldReg {
                //c.ColorPrintf(asmsh.Pallet.HiRed, "%s:    0x%08x(old: %08x)   ", key, reg, oldReg)
                c.ColorPrintf(asmsh.Pallet.HiRed, "%s:    0x%016x   ", key, reg)
            } else {
                c.Printf("%s:    0x%016x   ", key, reg)
            }
        }
    }
    c.ColorPrintf(asmsh.Pallet.BoldYellow, "\n---------------------------- STACK TRACE ----------------------------\n")
    asmsh.HexPrint64(c, mu)
    return nil
}
// TODO: simple code
func (asmsh *AsmShell) HexPrint64(c *ishell.Context, mu uc.Unicorn) error {
    var middle uint64 = 64
    rsp, err := mu.RegRead(asmsh.Regs["rsp"])
    if err != nil {
        return err
    }
    for i := uint64(0); i < asmsh.PrintSize; i+=32 {
        c.Printf("0x%016x: ", rsp-middle+i)
        for j := uint64(0); j < 32; j+=8 {
            if middle == (i-j) {
                c.ColorPrintf(asmsh.Pallet.HiRed, "%02x%02x%02x%02x%02x%02x%02x%02x ",
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+7],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+6],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+5],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+4],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+3],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+2],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+1],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j])
            } else {
                c.ColorPrintf(asmsh.Pallet.HiYellow, "%02x%02x%02x%02x%02x%02x%02x%02x ",
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+7],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+6],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+5],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+4],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+3],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+2],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+1],
                  asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j])
            }
        }
        c.ColorPrintf(asmsh.Pallet.Yellow, "|")
        for j := uint64(0); j < 32; j+=8 {
            for k := uint64(8); k > 0; k-=1 {
                chr := asmsh.SavedStack[asmsh.SavedStackSize/2-middle+i+j+k-1]
                if chr >= 0x20 && chr <= 0x7E {
                    c.ColorPrintf(asmsh.Pallet.Yellow, "%c", chr)
                } else {
                    c.ColorPrintf(asmsh.Pallet.Yellow, ".")
                }
            }
        }
        c.ColorPrintf(asmsh.Pallet.Yellow, "|\n")
    }
    return nil
}
