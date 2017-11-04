// TODO: cmd suggestion
package main

import (
    "fmt"
    "strings"
    "os/exec"
    "github.com/jessevdk/go-flags"
    "github.com/chzyer/readline"
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
    "github.com/poppycompass/ishell"
    as "github.com/poppycompass/asmshell/go"
    utils "github.com/poppycompass/asmshell/go/utils"
)

const (
    Version  string  = "0.1.0"
)
type Machine struct {
    archType uint64
    archMode uint64
    stackSize uint64
    stackMergin uint64
    stackAddr uint64
//    savedStack []byte
}

type Options struct {
    OptHelp           bool   `short:"h" long:"help"`
    OptDiff           bool   `short:"d" long:"diff"`
    OptArch           string `short:"a" long:"arch" default:"x86"`
}
// TODO: fix f*ck help
func help() {
  fmt.Print("usage: ./asmshell [-h] [--arch ARCH] [--diff]\n\n")
  fmt.Print("Assemblar Shell\n\n")
  fmt.Print("optional arguments:\n")
  fmt.Print("  -h, --help             show this help message and exit \n")
  fmt.Print("  -a ARCH, --arch ARCH,  target architecture(default: x86). available archtecture(x86/x86_64)\n")
  fmt.Print("  -d, --diff             run diff mode(output changed register only) \n")
}

var asmshell as.AsmShell
var pallet utils.Pallet
// handle unregistered commands
func handleNotFound(c *ishell.Context) {
    // run shell command(linux only)
    // TODO: windows support
    if strings.Index(c.Args[0], "!") == 0 {
        c.Args[0] = strings.Replace(c.Args[0], "!", "", 1)
        out, _ := exec.Command("sh", "-c", strings.Join(c.Args, " ")).Output()
        c.Printf("%s", out)
        return
    }
    code, err := assemble(strings.Join(c.Args, " "))
    if err != nil {
        c.Printf("[-] %s\n", err)
        return
    }
    if err = run(c, code); err != nil {
        panic(err)
    }
    c.Printf(asmshell.Prompt)
}
// handle EOF(Ctrl-D)
func handleEOF(c *ishell.Context) {
    c.Stop()
}
// handle Ctrl-C
func handleInterrupt(c *ishell.Context, count int, name string) {
    c.Stop()
}
func finish() {
    fmt.Println("good bye:)")
}

func main() {
    var (
        err error
        conf readline.Config
    )
//    fmt.Println(strings.Split("a,b,c,d,e,f", ","))
    utils.InitPallet(&pallet)
    opts := &Options{}
    parser := flags.NewParser(opts, flags.PrintErrors)
    args, err := parser.Parse()
    if err != nil {
        help()
        return
    }

    if 0 < len(args) {
      fmt.Print(args[0] + "\n")
    }

    if opts.OptHelp {
        help()
    }
    switch opts.OptArch {
        case "x86"   : fmt.Print("")
        case "x86_64": fmt.Print("")
        default      : fmt.Print("")
    }
    asmshell.CodeAddr  = 0x100000
    asmshell.PrintSize = 64 + 16
    asmshell.PrintMergin = 32
    asmshell.StackStart = 0x300000
    asmshell.StackSize   = 2 * 1024 * 1024
    asmshell.StackAddr = asmshell.StackStart + (asmshell.StackSize / 2)

    asmshell.KeystoneArch = keystone.ARCH_X86
    asmshell.KeystoneMode = keystone.MODE_32
    asmshell.KeystoneOPTType = keystone.OPT_SYNTAX
    asmshell.KeystoneOPTVal = keystone.OPT_SYNTAX_INTEL
    asmshell.UnicornArch = uc.ARCH_X86
    asmshell.UnicornMode = uc.MODE_32
    asmshell.SavedCtx = nil
    asmshell.SavedStackSize = 255
    asmshell.SavedStack = make([]byte, asmshell.SavedStackSize)
    for i := uint64(0); i < asmshell.SavedStackSize; i++ {
        asmshell.SavedStack[i] = 0xFF
    }
    asmshell.Prompt = "(x86)> "
    conf.Prompt = asmshell.Prompt
    shell := ishell.NewWithConfig(&conf)
    shell.EOF(handleEOF)
    shell.Interrupt(handleInterrupt)
    shell.NotFound(handleNotFound)
    shell.SetHomeHistoryPath(".asmshell_history")
    shell.ColorPrintln(pallet.BoldYellow, "Assemblar Shell(v " + Version + ")")

    funcList := make(map[string]string)
    funcs := &ishell.Cmd{
        Name: "function",
        Aliases: []string{"func"},
        Help: "register Function",
        Func: func(c *ishell.Context) {
            c.SetPrompt("(input)>")
            if len(c.Args) == 0 {
                c.Println("output func help")
            }
            funcList[c.Args[0]] = c.ReadMultiLines(";")
            //c.ShowPrompt(false)
            //defer c.ShowPrompt(true)
            //for {
            //    c.Print("(func:" + "x86" + ")> ")
            //    intr = c.ReadMultiLines(";")
            //    if strings.Index(intr, "exit") == -1 || strings.Index(intr, "quit") == -1 || strings.Index(intr, "q") == -1 {
            //        break
            //    }
            //    c.Println("input: " + intr)
            //}
        },
    }
    funcs.AddCmd(&ishell.Cmd{
        Name: "show",
        Help: "show registeref functions",
        Func: func(c *ishell.Context) {
          c.Print("Names: ")
          for key, value := range funcList {
              c.Printf("%s(%s), ", key, value)
          }
        },
    })
    shell.AddCmd(&ishell.Cmd{
        Name: "set",
        Help: "set architecture and mode",
        Func: func(c *ishell.Context) {
            c.Print("set mode")
        },
    })
    shell.AddCmd(funcs)
    shell.Run()
    shell.Close()
    finish()
}

func assemble(mnemonic string) ([]byte, error){

    ks, err := keystone.New(asmshell.KeystoneArch, asmshell.KeystoneMode)
    if err != nil {
        return nil, err
    }
    defer ks.Close()

    if err := ks.Option(asmshell.KeystoneOPTType, asmshell.KeystoneOPTVal); err != nil {
        return nil, fmt.Errorf("Error: set syntax option to intel")
    }

    if code, _, ok := ks.Assemble(mnemonic, 0); !ok {
        return nil, fmt.Errorf("Error: assemble instruction")
    } else {
        return code, nil
    }
}

func run(c *ishell.Context, code []byte) error {
    mu, err := uc.NewUnicorn(asmshell.UnicornArch, asmshell.UnicornMode)
    if err != nil {
        return err
    }
    if err := mu.MemMap(asmshell.CodeAddr, asmshell.StackSize); err != nil {
        return err
    }
    if err := mu.MemWrite(asmshell.CodeAddr, code); err != nil {
        return err
    }
    // create stack
    if err := mu.MemMap(asmshell.StackStart, asmshell.StackSize); err != nil {
        return err
    }

    if asmshell.SavedCtx != nil {
        err = mu.ContextRestore(asmshell.SavedCtx)
        if err != nil {
            return err
        }
    } else {
        err = mu.RegWrite(Regs["esp"], asmshell.StackAddr)
        if err != nil {
            return err
        }
    }
    esp, err := mu.RegRead(Regs["esp"])
    if err != nil {
        return err
    }
    err = mu.MemWrite(esp - (asmshell.SavedStackSize / 2), asmshell.SavedStack)
    if err != nil {
        return err
    }
    if err := mu.Start(asmshell.CodeAddr, asmshell.CodeAddr+uint64(len(code))); err != nil {
        return err
    }
    asmshell.SavedCtx, err = mu.ContextSave(nil)
    if err != nil {
        return err
    }
    esp, err = mu.RegRead(Regs["esp"])
    if err != nil {
        return err
    }
    asmshell.SavedStack, err  = mu.MemRead(esp - (asmshell.SavedStackSize / 2), asmshell.SavedStackSize)
    if err != nil {
        return err
    }
    if err = PrintCtx(c, mu, code); err != nil {
        return err
    }
    return nil
}

var Regs = map[string]int{
    "eax": uc.X86_REG_EAX,
    "ebx": uc.X86_REG_EBX,
    "ecx": uc.X86_REG_ECX,
    "edx": uc.X86_REG_EDX,
    "eip": uc.X86_REG_EIP,
    "esp": uc.X86_REG_ESP,
    "ebp": uc.X86_REG_EBP,
    "esi": uc.X86_REG_ESI,
    "edi": uc.X86_REG_EDI,
    "eflags": uc.X86_REG_EFLAGS,
    " cs": uc.X86_REG_CS,
    " ss": uc.X86_REG_SS,
    " ds": uc.X86_REG_DS,
    " es": uc.X86_REG_ES,
    " fs": uc.X86_REG_FS,
    " gs": uc.X86_REG_GS,
}
var RegOrder = []string{"eax", "ebx", "ecx", "edx", "eip", "esp", "ebp", "esi", "edi", " cs", " ss", " ds", " es", " fs", " gs", "eflags"}
func PrintCtx(c *ishell.Context, mu uc.Unicorn, code []byte) error {
    c.ColorPrintf(pallet.BoldWhite, "mnemonic: %s[hex: %x]\n", strings.Join(c.Args, " "), code)
    c.ColorPrintf(pallet.BoldCyan, "---------------------- CPU CONTEXT ----------------------\n")
    for idx, key := range RegOrder {
        reg, err := mu.RegRead(Regs[key])
        if err != nil {
            return err
        }
        if idx != 0 && idx % 2 == 0 {
            c.Println("")
        }
        if key == "eflags" {
            c.Printf("%s: 0x%08x [ CF(%d) ZF(%d) SF(%d) ]",
              key,
              reg,
              reg & 0x1,
              (reg>>6)&0x1,
              (reg>>7)&0x1)
        } else {
            c.Printf("%s: 0x%08x   ", key, reg)
        }
    }
    c.ColorPrintf(pallet.BoldYellow, "\n---------------------- STACK TRACE ----------------------\n")
    HexPrint32(c, mu)
    return nil
}
func HexPrint32(c *ishell.Context, mu uc.Unicorn) error {
    var middle uint64 = 32
    esp, err := mu.RegRead(Regs["esp"])
    if err != nil {
        return err
    }
    for i := uint64(0); i < asmshell.PrintSize; i+=16 {
        c.Printf("0x%08x: ", esp-middle+i)
        for j := uint64(0); j < 16; j+=4 {
            if middle == i {
                c.ColorPrintf(pallet.HiRed, "%02x%02x%02x%02x ",
                  asmshell.SavedStack[asmshell.SavedStackSize/2-middle+i+j+3],
                  asmshell.SavedStack[asmshell.SavedStackSize/2-middle+i+j+2],
                  asmshell.SavedStack[asmshell.SavedStackSize/2-middle+i+j+1],
                  asmshell.SavedStack[asmshell.SavedStackSize/2-middle+i+j])
            } else {
                c.ColorPrintf(pallet.HiYellow, "%02x%02x%02x%02x ",
                  asmshell.SavedStack[asmshell.SavedStackSize/2-middle+i+j+3],
                  asmshell.SavedStack[asmshell.SavedStackSize/2-middle+i+j+2],
                  asmshell.SavedStack[asmshell.SavedStackSize/2-middle+i+j+1],
                  asmshell.SavedStack[asmshell.SavedStackSize/2-middle+i+j])
            }
        }
        c.ColorPrintf(pallet.Yellow, "|")
        for j := uint64(0); j < 16; j+=4 {
            for k := uint64(4); k > 0; k-=1 {
                chr := asmshell.SavedStack[asmshell.SavedStackSize/2-middle+i+j+k-1]
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
