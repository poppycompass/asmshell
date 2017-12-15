package main

import (
    "strings"
    "os/exec"
    "io/ioutil"
    "github.com/poppycompass/ishell"
    "github.com/chzyer/readline"
    "github.com/poppycompass/asmshell/go/arch"
)

// ishell settings
func initShell(prompt string) *ishell.Shell {
    var conf readline.Config
    conf.Prompt = prompt

    shell = ishell.NewWithConfig(&conf)
    shell.EOF(handleEOF)
    shell.Interrupt(handleInterrupt)
    shell.NotFound(handleNotFound)
    shell.SetHomeHistoryPath(".asmshell_history")
    frags := fragCmd()
    frags.AddCmd(fragRun())
    frags.AddCmd(fragShow())
    frags.AddCmd(fragDel())
    shell.AddCmd(frags)
    shell.AddCmd(setCmd())
    shell.AddCmd(readExeCmd())
    return shell
}

// handle unregistered commands
func handleNotFound(c *ishell.Context) {
    // run shell command(linux only), TODO: windows support
    if strings.Index(c.Args[0], "!") == 0 {
        c.Args[0] = strings.Replace(c.Args[0], "!", "", 1)
        out, _ := exec.Command("sh", "-c", strings.Join(c.Args, " ")).Output()
        c.Printf("%s", out)
        return
    }
    err := mc.IshellRun(c, strings.Join(c.Args, " "))
    if err != nil {
        c.Printf("[-] %s\n", err)
    }
    c.Printf("%s", mc.Prompt)
}

// handle EOF(Ctrl-D)
func handleEOF(c *ishell.Context) {
    c.Stop()
}

// handle Ctrl-C
func handleInterrupt(c *ishell.Context, count int, name string) {
    c.Stop()
}

func fragCmd() *ishell.Cmd {
    return &ishell.Cmd {
        Name: "fragment",
        Aliases: []string{"frag", "f"},
        Help: "register assembler fragment",
        Func: register,
    }
}
func fragRun() *ishell.Cmd {
    return &ishell.Cmd {
        Name: "run",
        Aliases: []string{"r"},
        Help: "run registered fragments",
        Func: run,
    }
}
func fragShow() *ishell.Cmd {
    return &ishell.Cmd {
        Name: "show",
        Aliases: []string{"s"},
        Help: "show registered fragments",
        Func: show,
    }
}

func fragDel() *ishell.Cmd {
    return &ishell.Cmd {
        Name: "delete",
        Aliases: []string{"del", "d"},
        Help: "delete registered fragments",
        Func: del,
    }
}
func setCmd() *ishell.Cmd {
    return &ishell.Cmd {
        Name: "set",
        Help: "set architecture and mode",
        Func: set,
    }
}

func readExeCmd() *ishell.Cmd {
    return &ishell.Cmd {
        Name: "exe",
        Help: "(Comming soon)read exe file",
        Func: readExe,
    }
}
var fragList = make(map[string]string)
// register fragment code
func register(c *ishell.Context) {
    switch len(c.Args) {
        case 1: // register from input
             c.SetPrompt("in> ")
             fragList[c.Args[0]] = c.ReadMultiLines(";")
        case 2: // register from file
             buf := make([]byte, BUFSIZE)
             buf, err := ioutil.ReadFile(c.Args[1]) // fixme: file traversal vulnueravility?
             if err != nil {
                 c.Printf("Error: read '%s'\n", c.Args[1])
                 return
             }
             fragList[c.Args[0]] = string(buf)
        default : // show help
             c.Println("Usage: [fragment/f] [<word>|file <file>|show <word>|run <word>]")
             c.Println("register: fragment <word> or fragment <word> <file>\n")
            return
    }
    fragList[c.Args[0]] = strings.Replace(fragList[c.Args[0]], "\n", ";", -1)
    c.Printf("'%s' is registered\n", c.Args[0])
    c.SetPrompt(mc.Prompt)
}
func run(c *ishell.Context) {
    switch len(c.Args) {
        case 1: // run fragment code
            err := mc.IshellRun(c, fragList[c.Args[0]])
            if err != nil {
                c.Printf("[-] %s, %s\n", c.Args[0], fragList[c.Args[0]])
                c.Printf("[-] %s\n", err)
            }
            c.Printf("%s", mc.Prompt)
        default: // show help
            c.Println("Usage: fragment run <registered frag>")
    }
}
// show arbitary symbol,  if not registered, print blank
func show(c *ishell.Context) {
    switch len(c.Args) {
        case 0: // show all
            for key, value := range fragList {
                c.Printf("'%s'\n    ", key)
                value = strings.Replace(value, ";", "\n    ", -1) // line
                value = strings.Replace(value, ":", ":  ", -1) // symbol
                c.Printf("%s\n", value)
            }
            c.Print("Name> ")
            for key, _ := range fragList {
                c.Printf("'%s', ", key)
            }
            c.Printf("\n")
        default: // show input symbol
            for _, value := range c.Args {
                c.Printf("'%s'\n    ", value)
                tmp := strings.Replace(fragList[value], ";", "\n    ", -1) // line
                tmp = strings.Replace(tmp, ":", ":  ", -1) // symbol
                c.Printf("%s\n", tmp)
            }
    }
}

// delete registered fragment
func del(c *ishell.Context) {
    switch len(c.Args) {
        case 0: // show help
            c.Println("Usage: fragment delete <registered frag>")
        default:
            c.Printf("Delete: ")
            for _, value := range c.Args {
                delete(fragList, value)
                c.Printf("'%s' ", value)
            }
            c.Printf("\n%s", mc.Prompt)
    }
}

func set(c *ishell.Context) {
    switch len(c.Args) {
        case 0:
            c.Printf("Usage: set <arch>\n")
            c.Printf("Supported: %s\n", SUPPORTED)
        default:
            mc = arch.SetArch(c.Args[0])
            c.SetPrompt(mc.Prompt)
    }
}
func readExe(c *ishell.Context) {
    switch len(c.Args) {
        case 0:
            c.Printf("Usage: exe <exe file>\n")
        default:
            c.Printf("Not implemented\n")
    }
}
