package main

import (
    "fmt"
    "strings"
    "github.com/jessevdk/go-flags"
    "github.com/abiosoft/ishell"
    "github.com/chzyer/readline"
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
//    "github.com/poppycompass/asmshell/go/utils"
)

var Version  string  = "0.1.0"
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
func promptMsg(arch string, diff bool) string {
    var prompt string = "(" + arch
    if diff {
      prompt += ":diff"
    }
    prompt += ")> "
    return prompt
}

// handle unregistered commands
func handleNotFound(c *ishell.Context) {
    code, err := assemble(strings.Join(c.Args, " "))
    if err != nil {
        c.Printf("[-] %s\n", err)
        return
    }
    run(code)
    c.Printf("%s: [%x]\n", strings.Join(c.Args, " "), code)
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
      prompt string
      conf readline.Config
    )
//    fmt.Println(strings.Split("a,b,c,d,e,f", ","))
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
    prompt = promptMsg(opts.OptArch, opts.OptDiff)
    conf.Prompt = "(master)> "
    shell := ishell.NewWithConfig(&conf)
    shell.EOF(handleEOF)
    shell.Interrupt(handleInterrupt)
    shell.NotFound(handleNotFound)
    shell.SetHomeHistoryPath(".asmshell_history")
    shell.Println("Assemblar Shell(v " + Version + ")")

    shell.AddCmd(&ishell.Cmd{
        Name: "single",
        Aliases: []string{"s"},
        Help: "simple assemblar shell",
        Func: func(c *ishell.Context) {
            var intr string = ""
            c.ShowPrompt(false)
            defer c.ShowPrompt(true)
            for {
                c.Print(prompt)
                intr = c.ReadLine()
                if intr == "exit" || intr == "q" || intr == "quit" {
                    c.Println("exit")
                    break
                }
                c.Println("input: " + intr)
            }
        },
    })

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
    shell.AddCmd(funcs)
    shell.Run()
    shell.Close()
    finish()
}

func assemble(mnemonic string) ([]byte, error){

    ks, err := keystone.New(keystone.ARCH_X86, keystone.MODE_32)
    if err != nil {
        return nil, err
    }
    defer ks.Close()

    if err := ks.Option(keystone.OPT_SYNTAX, keystone.OPT_SYNTAX_INTEL); err != nil {
        return nil, fmt.Errorf("Error: set syntax option to intel")
    }

    if code, _, ok := ks.Assemble(mnemonic, 0); !ok {
        return nil, fmt.Errorf("Error: assemble instruction")
    } else {
        return code, nil
    }
}

func run(code []byte) error {
    mu, err := uc.NewUnicorn(uc.ARCH_X86, uc.MODE_32)
    if err != nil {
        return err
    }
    if err := mu.MemMap(0x1000, 0x1000); err != nil {
        return err
    }
    if err := mu.MemWrite(0x1000, code); err != nil {
        return err
    }
    // create stack
    if err := mu.MemMap(0x4000, 0x1000); err != nil {
        return err
    }
    if err := mu.Start(0x1000, 0x1000+uint64(len(code))); err != nil {
        return err
    }
    eax, err := mu.RegRead(uc.X86_REG_EAX);
    if err != nil {
        return err
    }
    fmt.Printf("EAX: %d\n", eax)
    return nil
}
