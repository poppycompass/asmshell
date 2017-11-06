// TODO: mnemonic suggestion, jmp handling, custom run(http), symbol resolve, arm(vector support), arm thumb, input '#', arm64eb support
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
    Version  string  = "0.1.0"
)
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

//var asmsh as.AsmShell
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
    }
    switch opts.OptArch {
        case "i8086"       : arch.InitI8086(&asmsh)
        case "x86"         : arch.InitX86(&asmsh)
        case "x64"         : arch.InitX64(&asmsh)
        case "arm-thumb"   : arch.InitArmThumb(&asmsh, false)
        case "arm-thumbeb" : arch.InitArmThumb(&asmsh, true)
        case "arm"         : arch.InitArm(&asmsh  , false)
        case "armeb"       : arch.InitArm(&asmsh  , true)
        case "arm64"       : arch.InitArm64(&asmsh, false)
//        case "arm64eb"     : arch.InitArm64(&asmsh, true)
        case "m68k"        : arch.InitX86(&asmsh) // not implemented
        case "mips"        : arch.InitX86(&asmsh) // not implemented
        case "sparc"       : arch.InitX86(&asmsh) // not implemented
//        case "powerpc" : arch.InitX86(&asmsh)
        default            : arch.InitX86(&asmsh)
    }
    conf.Prompt = asmsh.Prompt
    shell := ishell.NewWithConfig(&conf)
    shell.EOF(handleEOF)
    shell.Interrupt(handleInterrupt)
    shell.NotFound(handleNotFound)
    shell.SetHomeHistoryPath(".asmshell_history")
    shell.ColorPrintln(asmsh.Pallet.BoldYellow, "Assemblar Shell(v " + Version + ")")

    fragList := make(map[string]string)
    frags := &ishell.Cmd{
        Name: "fragment",
        Aliases: []string{"frag", "f"},
        Help: "register assemblar fragment",
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
            c.Print("set mode")
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
