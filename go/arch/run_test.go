// go test "github.com/poppycompass/asmshell/go/arch"
package arch

import (
    "encoding/hex"
    "testing"
    "reflect"
  )

var archList = []string{
    "i8086", "x86", "x64",
    "thumb", "thumbbe",
    "arm", "armbe",
    "arm64", //"arm64be",
    "mips", "mipsbe",
    "mips64", "mips64be",
    "sparc", "sparcle",
    "sparc64", "powerpc",
    "powerpc64", "powerpc64le",
    "systemZ",
}
var bit32 = []string{
    "x86", "arm", "mips", "sparc",
}

// 'key': {"correct code", "mnemonic"}
var testCodes = map[string][]string {
  "i8086"       :{ "b8221150","mov ax, 0x1122;push ax",},
  "x86"         :{ "b84433221150","mov eax, 0x11223344; push eax",},
  "x64"         :{ "48b8887766554433221150","mov rax, 0x1122334455667788;push rax",},
  "thumb"       :{ "41f222100090","mov r0, 0x1122; str r0, [sp]",},
  "thumbbe"     :{ "f24110229000","mov r0, 0x1122; str r0, [sp]",},
  "arm"         :{ "440303e3220141e300008de5","mov r0, 0x3344; movt r0, 0x1122; str r0, [sp]",},
  "armbe"       :{ "e3030344e3410122e58d0000","mov r0, 0x3344; movt r0, 0x1122; str r0, [sp]",},
  "arm64"       :{ "e00680d2410003cb","mov x0, 0x37; sub x1,x2,x3",},
  // "arm64be",  {"","mov x0, 0x37; sub x1,x2,x3",},
  "mips"        :{ "2211013c44332134204001010000a8af","addi $t0, $t0, 0x11223344;sw $t0,0($sp)",},
  "mipsbe"      :{ "3c0111223421334401014020afa80000","addi $t0, $t0, 0x11223344;sw $t0,0($sp)",},
  "mips64"      :{ "56342134","ori $at, $at, 0x3456",},
  "mips64be"    :{ "34213456","ori $at, $at, 0x3456",},
  "sparc"       :{ "8200611283286004820060028328600c820063348328600482006004c2238000","add %g1, 0x112, %g1; sll %g1, 4, %g1; add %g1, 2, %g1; sll %g1, 12, %g1; add %g1, 0x334, %g1; sll %g1, 4, %g1; add %g1, 4, %g1; st %g1, [%sp];",},
  "sparcle"     :{ "02400086","add %g1, %g2, %g3",},
  "sparc64"     :{ "86004002","add %g1, %g2, %g3",},
  "powerpc"     :{ "7c221a14","add 1,2,3",},
  "powerpc64"   :{ "7c221a14","add 1,2,3",},
  "powerpc64le" :{ "141a227c","add 1,2,3",},
  "systemZ"     :{ "5a0f1fff","a %r0, 4095(%r15,%r1)",},
}

func TestXAssemble(t *testing.T) {
    var (
        mc Machine
    )

    for _, arch := range archList {
        mc = SetArch(arch)
        correct, _ := hex.DecodeString(testCodes[arch][0])
        code,_ := mc.Assemble(testCodes[arch][1])
        if !reflect.DeepEqual(code, correct) {
            t.Errorf("[-]: %s(o: %x, x: %x)", arch, correct, code)
        }
    }
    mc.Finalize()
}

func TestXI8086Emulate(t *testing.T) {
    var (
        arch string = "i8086"
        readReg string = "ax"
        correctReg  = uint64(0x1122)
        correctData = []byte("\x22\x11")
    )
    mc := SetArch(arch)
    code, _ := hex.DecodeString(testCodes[arch][0])
    if err := mc.Emulate(code); err != nil {
        t.Errorf("[-] %s,%s ]", arch, err)
    }
    reg, _ := mc.mu.RegRead(mc.regs[readReg])
    if reg != correctReg {
        t.Errorf("[-] %s register(o: %x, x: %x) ]", arch, correctReg, reg)
    }
    sp, _ := mc.mu.RegRead(mc.sp)
    data, _ := mc.mu.MemRead(sp, uint64(mc.bit/8))
    if !reflect.DeepEqual(data, correctData) {
        t.Errorf("[-] %s stack(o: %x, x: %x)", arch, correctData, data)
    }
    mc.Finalize()
}
func TestXX86Emulate(t *testing.T) {
    var (
        arch string = "x86"
        readReg string = "eax"
        correctReg  = uint64(0x11223344)
        correctData = []byte("\x44\x33\x22\x11")
    )
    mc := SetArch(arch)
    code, _ := hex.DecodeString(testCodes[arch][0])
    if err := mc.Emulate(code); err != nil {
        t.Errorf("[-] %s,%s ]", arch, err)
    }
    reg, _ := mc.mu.RegRead(mc.regs[readReg])
    if reg != correctReg {
        t.Errorf("[-] %s register(o: %x, x: %x) ]", arch, correctReg, reg)
    }
    sp, _ := mc.mu.RegRead(mc.sp)
    data, _ := mc.mu.MemRead(sp, uint64(mc.bit/8))
    if !reflect.DeepEqual(data, correctData) {
        t.Errorf("[-] %s stack(o: %x, x: %x)", arch, correctData, data)
    }
    mc.Finalize()
}
func TestXX64Emulate(t *testing.T) {
    var (
        arch string = "x64"
        readReg string = "rax"
        correctReg  = uint64(0x1122334455667788)
        correctData = []byte("\x88\x77\x66\x55\x44\x33\x22\x11")
    )
    mc := SetArch(arch)
    code, _ := hex.DecodeString(testCodes[arch][0])
    if err := mc.Emulate(code); err != nil {
        t.Errorf("[-] %s,%s ]", arch, err)
    }
    reg, _ := mc.mu.RegRead(mc.regs[readReg])
    if reg != correctReg {
        t.Errorf("[-] %s register(o: %x, x: %x) ]", arch, correctReg, reg)
    }
    sp, _ := mc.mu.RegRead(mc.sp)
    data, _ := mc.mu.MemRead(sp, uint64(mc.bit/8))
    if !reflect.DeepEqual(data, correctData) {
        t.Errorf("[-] %s stack(o: %x, x: %x)", arch, correctData, data)
    }
    mc.Finalize()
}

func TestXMipsEmulate(t *testing.T) {
    var (
        arch string = "mips"
        readReg string = "t0"
        correctReg  = uint64(0x11223344)
        correctData = []byte("\x44\x33\x22\x11")
    )
    mc := SetArch(arch)
    code, _ := hex.DecodeString(testCodes[arch][0])
    if err := mc.Emulate(code); err != nil {
        t.Errorf("[-] %s,%s ]", arch, err)
    }
    reg, _ := mc.mu.RegRead(mc.regs[readReg])
    if reg != correctReg {
        t.Errorf("[-] %s register(o: %x, x: %x) ]", arch, correctReg, reg)
    }
    sp, _ := mc.mu.RegRead(mc.sp)
    data, _ := mc.mu.MemRead(sp, uint64(mc.bit/8))
    if !reflect.DeepEqual(data, correctData) {
        t.Errorf("[-] %s stack(o: %x, x: %x)", arch, correctData, data)
    }
    mc.Finalize()
}
func TestXMipsbeEmulate(t *testing.T) {
    var (
        arch string = "mipsbe"
        readReg string = "t0"
        correctReg  = uint64(0x11223344)
        correctData = []byte("\x11\x22\x33\x44")
    )
    mc := SetArch(arch)
    code, _ := hex.DecodeString(testCodes[arch][0])
    if err := mc.Emulate(code); err != nil {
        t.Errorf("[-] %s,%s ]", arch, err)
    }
    reg, _ := mc.mu.RegRead(mc.regs[readReg])
    if reg != correctReg {
        t.Errorf("[-] %s register(o: %x, x: %x) ]", arch, correctReg, reg)
    }
    sp, _ := mc.mu.RegRead(mc.sp)
    data, _ := mc.mu.MemRead(sp, uint64(mc.bit/8))
    if !reflect.DeepEqual(data, correctData) {
        t.Errorf("[-] %s stack(o: %x, x: %x)", arch, correctData, data)
    }
    mc.Finalize()
}

func TestXArmEmulate(t *testing.T) {
    var (
        arch string = "arm"
        readReg string = "r0"
        correctReg  = uint64(0x11223344)
        correctData = []byte("\x44\x33\x22\x11")
    )
    mc := SetArch(arch)
    code, _ := hex.DecodeString(testCodes[arch][0])
    if err := mc.Emulate(code); err != nil {
        t.Errorf("[-] %s,%s ]", arch, err)
    }
    reg, _ := mc.mu.RegRead(mc.regs[readReg])
    if reg != correctReg {
        t.Errorf("[-] %s register(o: %x, x: %x) ]", arch, correctReg, reg)
    }
    sp, _ := mc.mu.RegRead(mc.sp)
    data, _ := mc.mu.MemRead(sp, uint64(mc.bit/8))
    if !reflect.DeepEqual(data, correctData) {
        t.Errorf("[-] %s stack(o: %x, x: %x)", arch, correctData, data)
    }
    mc.Finalize()
}
func TestXArmbeEmulate(t *testing.T) {
    var (
        arch string = "armbe"
        readReg string = "r0"
        correctReg  = uint64(0x11223344)
        correctData = []byte("\x11\x22\x33\x44")
    )
    mc := SetArch(arch)
    code, _ := hex.DecodeString(testCodes[arch][0])
    if err := mc.Emulate(code); err != nil {
        t.Errorf("[-] %s,%s ]", arch, err)
    }
    reg, _ := mc.mu.RegRead(mc.regs[readReg])
    if reg != correctReg {
        t.Errorf("[-] %s register(o: %x, x: %x) ]", arch, correctReg, reg)
    }
    sp, _ := mc.mu.RegRead(mc.sp)
    data, _ := mc.mu.MemRead(sp, uint64(mc.bit/8))
    if !reflect.DeepEqual(data, correctData) {
        t.Errorf("[-] %s stack(o: %x, x: %x)", arch, correctData, data)
    }
    mc.Finalize()
}
func TestXSparcEmulate(t *testing.T) {
    var (
        arch string = "sparc"
        readReg string = "g1"
        correctReg  = uint64(0x11223344)
        correctData = []byte("\x11\x22\x33\x44")
    )
    mc := SetArch(arch)
    code, _ := hex.DecodeString(testCodes[arch][0])
    if err := mc.Emulate(code); err != nil {
        t.Errorf("[-] %s,%s ]", arch, err)
    }
    reg, _ := mc.mu.RegRead(mc.regs[readReg])
    if reg != correctReg {
        t.Errorf("[-] %s register(o: %x, x: %x) ]", arch, correctReg, reg)
    }
    sp, _ := mc.mu.RegRead(mc.sp)
    data, _ := mc.mu.MemRead(sp, uint64(mc.bit/8))
    if !reflect.DeepEqual(data, correctData) {
        t.Errorf("[-] %s stack(o: %x, x: %x)", arch, correctData, data)
    }
    mc.Finalize()
}

func TestXThumbEmulate(t *testing.T) {
    var (
        arch string = "thumb"
        readReg string = "r0"
        correctReg  = uint64(0x1122)
        correctData = []byte("\x22\x11")
    )
    mc := SetArch(arch)
    code, _ := hex.DecodeString(testCodes[arch][0])
    if err := mc.Emulate(code); err != nil {
        t.Errorf("[-] %s,%s ]", arch, err)
    }
    reg, _ := mc.mu.RegRead(mc.regs[readReg])
    if reg != correctReg {
        t.Errorf("[-] %s register(o: %x, x: %x) ]", arch, correctReg, reg)
    }
    sp, _ := mc.mu.RegRead(mc.sp)
    data, _ := mc.mu.MemRead(sp, uint64(mc.bit/8))
    if !reflect.DeepEqual(data, correctData) {
        t.Errorf("[-] %s stack(o: %x, x: %x)", arch, correctData, data)
    }
    mc.Finalize()
}
// fixme: sp+2 is correct?
func TestXThumbbeEmulate(t *testing.T) {
    var (
        arch string = "thumbbe"
        readReg string = "r0"
        correctReg  = uint64(0x1122)
        correctData = []byte("\x11\x22")
    )
    mc := SetArch(arch)
    code, _ := hex.DecodeString(testCodes[arch][0])
    if err := mc.Emulate(code); err != nil {
        t.Errorf("[-] %s,%s ]", arch, err)
    }
    reg, _ := mc.mu.RegRead(mc.regs[readReg])
    if reg != correctReg {
        t.Errorf("[-] %s register(o: %x, x: %x) ]", arch, correctReg, reg)
    }
    sp, _ := mc.mu.RegRead(mc.sp)
    data, _ := mc.mu.MemRead(sp+2, uint64(mc.bit/8))
    if !reflect.DeepEqual(data, correctData) {
        t.Errorf("[-] %s stack(o: %x, x: %x)", arch, correctData, data)
    }
    mc.Finalize()
}
