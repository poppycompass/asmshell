// TODO: README/Makefile, windows/mac/linux installer|prebuild

package main

import (
    "fmt"
    "github.com/jessevdk/go-flags"
    "github.com/poppycompass/ishell"
    "github.com/poppycompass/asmshell/go/arch"
    "github.com/poppycompass/asmshell/go/utils"
)

type options struct {
    OptHelp bool   `short:"h" long:"help"`
    OptArch string `short:"a" long:"arch" default:"x86"`
    OptList bool   `short:"L" long:"List"`
    OptHttp bool   `short:"H" long:"HTTP"`
    OptPort string `short:"p" long:"port" default:"8080"`
}

var (
    mc arch.Machine
    shell *ishell.Shell
    pallet utils.Pallet
)

func main() {
    opts, err := parseOption()
    if err != nil {
        return
    }

    pallet = utils.InitPallet()
    mc = arch.SetArch(opts.OptArch)
    shell = initShell(mc.Prompt)
    bannar()
    shell.Run()
    shell.Close()
    finish()
}

func parseOption() (options, error) {
    opts := &options{}
    parser := flags.NewParser(opts, flags.PrintErrors)
    args, err := parser.Parse()
    if err != nil || opts.OptHelp {
        help()
        return options{}, fmt.Errorf("help")
    }
    if 0 < len(args) {
        fmt.Print(args[0] + "\n")
    }
    if opts.OptList {
        showArchList()
        return options{}, fmt.Errorf("arch list")
    }
    // TODO: HTTP mode, Not implemented
    if opts.OptHttp {
        fmt.Printf("Assembler Shell on Web is not implemented\nComming soon...(port: %s)\n", opts.OptPort)
        return options{}, fmt.Errorf("Not implemented")
    }
    return *opts, nil
}

func bannar() {
    shell.Printf("Assembler Shell(v " + VERSION + ")\n")
}

func finish() {
    mc.Finalize()
    shell.Println("good bye:)")
}
