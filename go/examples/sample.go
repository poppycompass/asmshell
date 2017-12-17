package main

import (
        "fmt"
        "github.com/poppycompass/asmshell/go/arch"
       )

func test_run(mc arch.Machine) error {
    fmt.Printf("========== simple run ==========\n")
    mc.Run("mov eax, 0xdeadbeef")
    eax, _  := mc.RegRead("eax")
    fmt.Printf("eax          : 0x%x\n", eax)

    esp, _  := mc.RegRead("esp")
    data, _ := mc.MemRead(esp, 4)
    fmt.Printf("esp          : 0x%x\n", esp)
    fmt.Printf("before [esp] : 0x%x\n", data)

    mc.Run("mov DWORD PTR [esp], 0xaabbccdd")
    data, _ = mc.MemRead(esp, 4)
    fmt.Printf("after  [esp] : 0x%x\n", data)
    fmt.Printf("========== simple run end ==========\n")
    return nil
}

// xor encrypt/decrypt
func test_encrypt(mc arch.Machine) error {
    var mnemonic = "xor ax, cx"
    var cipher = []byte("\xd8\x8b\x8d\x8a\x8c\x8b\x91\x90\xce\xd8\xdf\x96\x8c\xdf\x88\x9a\x9e\x94\xdf\x8f\x9e\x8c\x8c\x88\x90\x8d\x9b\xde")

    fmt.Printf("========== simple encrypt ==========\n")
    fmt.Printf("cipher text: %x\n", cipher)
    fmt.Printf("plain text : ")
    for _, c := range cipher {
        mc.RegWrite("eax", uint64(c))
        mc.RegWrite("ecx", uint64(0xff))
        mc.Run(mnemonic)
        val, _ := mc.RegRead("eax")
        fmt.Printf("%c", val)
    }
    fmt.Printf("\n")
    fmt.Printf("========== simple encrypt end ==========\n")
    return nil
}

func main() {
    var mc arch.Machine = arch.SetArch("x86") // i8086, x86, x64, thumb(be), arm(be), arm64, mips(be), mips64(be), sparc(le), sparc64, [ppc|powerpc], [ppc64(le)|powerpc64(le)], [sysz|systemz|systemZ] is available
    test_run(mc)
    test_encrypt(mc)
}
