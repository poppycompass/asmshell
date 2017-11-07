// TODO: test, (jmp handling,symbol resolve), custom run(http), mnemonic suggestion,arm(vector support), arm64eb support, add float and 128bit registers(x86, arm, mips), add hook?

package main

import (
    "fmt"
    "strings"
    "os/exec"
    "github.com/jessevdk/go-flags"
    "github.com/chzyer/readline"
    "github.com/poppycompass/ishell"
    as "github.com/poppycompass/asmshell/go"
//    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
    "github.com/poppycompass/asmshell/go/arch"
    utils "github.com/poppycompass/asmshell/go/utils"
)

const (
    version  string  = "0.1.0"
    availableArch string = "i8086, x86, x64, arm-thumb(eb), arm(eb), arm64(eb), mips(eb), mips64(eb), sparc(el), sparc64, [ppc|powerpc], [ppc64(el)|powerpc64(el)], [sysz|systemz|systemZ]"
)
type Options struct {
    OptHelp bool   `short:"h" long:"help"`
    OptArch string `short:"a" long:"arch" default:"x86"`
    OptList bool   `short:"L" long:"List"`
}

// TODO: fix f*ck help
func help() {
    fmt.Printf("Usage: ./asmshell [-h|--help] [-a|--arch ARCH] \n\n")
    fmt.Printf("Assembler Shell\n\n")
    fmt.Printf("optional arguments:\n")
    fmt.Printf("  -h, --help             Show this help message and exit \n")
    fmt.Printf("  -a ARCH, --arch ARCH,  Target architecture(Default: x86)\n")
    fmt.Printf("     Support: %s\n", AvailableArch)
}

func printArchList() {
    fmt.Printf("Details of supported Archtecture: \n")
    fmt.Printf("    i8086         : Intel 16-bit. iAPX 86. little endian\n")
    fmt.Printf("    x86           : Intel 32-bit. 80386/IA-32. Extended i8086 to 32-bits. little endian\n")
    fmt.Printf("    x64           : Intel 64-bit. AMD64. Extended x86 to 64-bits. little endian\n")
    fmt.Printf("    arm-thumb(eb) : Arm Thumb mode(including Thumb-2). Mainly 16-bit. arm-thumbeb is big endian.\n")
    fmt.Printf("    arm(eb)       : Advanced RISC Machine. 32-bit. armeb is big endian\n")
    fmt.Printf("    arm64(eb)     : Armv8, 64-bit. arm64eb is big endian\n")
    fmt.Printf("    mips(eb)      : MIPS, 32-bit. mipseb is big endian\n")
    fmt.Printf("    mips64(eb)    : MIPS, 64-bit. mips64eb is big endian\n")
    fmt.Printf("    sparc(el)     : SPARC, 32-bit. sparcel only supports assembly. sparcel is little endian.\n")
    fmt.Printf("    sparc64       : SPARC, 64-bit. big-endian.\n")
    fmt.Printf("    powerpc       : Support assemble only. PowerPC, 32-bit. big-endian.\n")
    fmt.Printf("    powerpc64(el) : Support assemble only. PowerPC, 64-bit. powerpc64el is little endian\n")
    fmt.Printf("    systemZ       : Support assemble only. Architecture for IBM eServer zSeries. big-endian\n")
}

var asmsh as.AsmShell

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
    err := asmsh.Emulate(c, strings.Join(c.Args, " "))
    if err != nil {
        c.Printf("[-] %s\n", err)
    }
    c.Printf("%s", asmsh.Prompt)
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
    utils.InitPallet(&asmsh.Pallet)
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
        return
    }
    if opts.OptList {
        printArchList()
        return
    }
    SetAsmShell(opts.OptArch)

    conf.Prompt = asmsh.Prompt
    shell := ishell.NewWithConfig(&conf)
    shell.EOF(handleEOF)
    shell.Interrupt(handleInterrupt)
    shell.NotFound(handleNotFound)
    shell.SetHomeHistoryPath(".asmshell_history")
    shell.ColorPrintln(asmsh.Pallet.BoldYellow, "Assembler Shell(v " + version + ")")

    fragList := make(map[string]string)
    frags := &ishell.Cmd{
        Name: "fragment",
        Aliases: []string{"frag", "f"},
        Help: "register assembler fragment",
        Func: func(c *ishell.Context) {
            if len(c.Args) == 0 {
                c.Println("Usage: [fragment/f] [<word>/show/run]")
                return
            }
            c.SetPrompt("in> ")
            fragList[c.Args[0]] = c.ReadMultiLines(";")
            fragList[c.Args[0]] = strings.Replace(fragList[c.Args[0]], "\n", ";", -1)
            c.Printf("'%s' is registered\n", c.Args[0])
            c.SetPrompt(asmsh.Prompt)
        },
    }
    frags.AddCmd(&ishell.Cmd{
        Name: "show",
        Aliases: []string{"s"},
        Help: "show registered fragments",
        Func: func(c *ishell.Context) {
          c.Print("Names: ")
          for key, value := range fragList {
              c.Printf("%s(%s), ", key, value)
          }
          c.Printf("\n")
        },
    })
    frags.AddCmd(&ishell.Cmd{
        Name: "run",
        Aliases: []string{"r"},
        Help: "run registered fragments",
        Func: func(c *ishell.Context) {
            if len(c.Args) == 0 {
                c.Println("Usage: fragment run <registered frag>")
                return
            }
            err := asmsh.Emulate(c, fragList[c.Args[0]])
            if err != nil {
                c.Printf("[-] %s\n", err)
            }
            c.Printf("%s", asmsh.Prompt)
        },
    })
    shell.AddCmd(&ishell.Cmd{
        Name: "set",
        Help: "set architecture and mode",
        Func: func(c *ishell.Context) {
            if len(c.Args) == 0 {
                c.Printf("Usage: set <arch>\n")
                c.Printf("available arch: %s\n", availableArch)
            } else {
                SetAsmShell(c.Args[0])
                c.SetPrompt(asmsh.Prompt)
            }
        },
    })
    shell.AddCmd(&ishell.Cmd{
        Name: "readExe",
        Help: "read exe file",
        Func: func(c *ishell.Context) {
            c.Print("read exe")
        },
    })
    shell.AddCmd(frags)
    shell.Run()
    shell.Close()
    finish()
}

func SetAsmShell(strArch string) {
    switch strArch {
        case "i8086"       : arch.SetI8086(&asmsh)
        case "x86"         : arch.SetX86(&asmsh)
        case "x64"         : arch.SetX64(&asmsh)
        case "arm-thumb"   : arch.SetArmThumb(&asmsh, false)
        case "arm-thumbeb" : arch.SetArmThumb(&asmsh, true)
        case "arm"         : arch.SetArm(&asmsh  , false)
        case "armeb"       : arch.SetArm(&asmsh  , true)
        case "arm64"       : arch.SetArm64(&asmsh, false)
        case "arm64eb"     : arch.SetArm64(&asmsh, true) // not implemented
        case "mips"        : arch.SetMips(&asmsh, false)
        case "mipseb"      : arch.SetMips(&asmsh, true)
        case "mips64"      : arch.SetMips64(&asmsh, false) // fixme: something wrong?
        case "mips64eb"    : arch.SetMips64(&asmsh, true) // fixme: something wrong?
        case "sparc"       : arch.SetSparc(&asmsh, true) // sparc standard is big-endian
        case "sparcel"     : arch.SetSparc(&asmsh, false) // assemble only, unicorn: UNSUPPORTED, keystone: supported
        case "sparc64"     : arch.SetSparc64(&asmsh, true) // fixme: something wrong?, sparc standard is big-endian
        case "ppc",
             "powerpc"     : arch.SetPowerPC(&asmsh, true)
        case "ppc64",
             "powerpc64"   : arch.SetPowerPC64(&asmsh, true)
        case "ppc64el",
             "powerpc64el" : arch.SetPowerPC64(&asmsh, false)
        case "sysz",
             "systemz",
             "systemZ"     : arch.SetSystemZ(&asmsh)
        //case "m68k"        : arcSetitM68k(&asmsh) // unicorn: supported, keystone: UNSUPPORTED
        default            : arch.SetX86(&asmsh)
    }
}
