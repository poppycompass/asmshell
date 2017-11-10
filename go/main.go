// TODO: tests, README, add vector(arm), float and 128bit registers(x86, arm, mips), add hook?, arm64eb support, mnemonic suggestion, windows/mac/linux installer|prebuild

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
    mc = setArch(opts.OptArch)
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

func setArch(strArch string) arch.Machine {
    var mc arch.Machine
    switch strArch {
        case "i8086"       : mc = arch.SetI8086()
        case "x86"         : mc = arch.SetX86()
        case "x64"         : mc = arch.SetX64()
        case "arm-thumb"   : mc = arch.SetArmThumb(false) // TODO: test
        case "arm-thumbeb" : mc = arch.SetArmThumb(true) // TODO: test
        case "arm"         : mc = arch.SetArm(false)
        case "armeb"       : mc = arch.SetArm(true)
        case "arm64"       : mc = arch.SetArm64(false)  // TODO: test, fixme: something wrong?
        case "arm64eb"     : mc = arch.SetArm64(true)   // TODO: test, fixme: something wrong?
        case "mips"        : mc = arch.SetMips(false)
        case "mipseb"      : mc = arch.SetMips(true)
        case "mips64"      : mc = arch.SetMips64(false) // fixme: something wrong?
        case "mips64eb"    : mc = arch.SetMips64(true)  // fixme: something wrong?
        case "sparc"       : mc = arch.SetSparc(true)   // sparc standard is big-endian
        case "sparcel"     : mc = arch.SetSparc(false)  // assemble only, unicorn: UNSUPPORTED, keystone: supported
//        case "sparc64"     : mc = arch.SetSparc64(asmsh, true) // fixme: something wrong?, sparc standard is big-endian
//        case "ppc",
//             "powerpc"     : mc = arch.SetPowerPC(asmsh, true)
//        case "ppc64",
//             "powerpc64"   : mc = arch.SetPowerPC64(asmsh, true)
//        case "ppc64el",
//             "powerpc64el" : mc = arch.SetPowerPC64(asmsh, false)
//        case "sysz",
//             "systemz",
//             "systemZ"     : mc = arch.SetSystemZ(asmsh)
        //case "m68k"        : mc = arcSetitM68k(&asmsh) // unicorn: supported, keystone: UNSUPPORTED
        default            : mc = arch.SetX86()
    }
    return mc
}

func bannar() {
    shell.Printf("Assembler Shell(v " + VERSION + ")\n")
}

func finish() {
    mc.Finalize()
    shell.Println("good bye:)")
}
