// go test "github.com/poppycompass/asmshell/go/arch"
package arch

import (
    "encoding/hex"
    "testing"
    "reflect"
  )

var archList = []string{
    "i8086", "x86", "x64",
    "arm-thumb", "arm-thumbeb",
    "arm", "armeb",
    "arm64", //"arm64eb",
    "mips", "mipseb",
    "mips64", "mips64eb",
    "sparc", "sparcel",
    "sparc64", "powerpc",
    "powerpc64", "powerpc64el",
    "systemZ",
}

// 'key': {"correct code", "mnemonic"}
var testCodes = map[string][]string {
  "i8086"       :{ "40505b41","inc ax;push ax;pop bx;inc cx",},
  "x86"         :{ "40505b41","inc eax; push eax; pop ebx; inc ecx",},
  "x64"         :{ "48ffc0505b48ffc1","inc rax; push rax; pop rbx; inc rcx",},
  "arm-thumb"   :{ "83b04ff03700a2eb0301","sub sp, 0xc; mov r0, 0x37; sub r1,r2,r3",},
  "arm-thumbeb" :{ "b083f04f0037eba20103","sub sp, 0xc; mov r0, 0x37; sub r1,r2,r3",},
  "arm"         :{ "0cd04de23700a0e3031042e0","sub sp, 0xc; mov r0, 0x37; sub r1,r2,r3",},
  "armeb"       :{ "e24dd00ce3a00037e0421003","sub sp, 0xc; mov r0, 0x37; sub r1,r2,r3",},
  "arm64"       :{ "e00680d2410003cb","mov x0, 0x37; sub x1,x2,x3",},
  // "arm64eb",  {"","mov x0, 0x37; sub x1,x2,x3",},
  "mips"        :{ "56342134","ori $at, $at, 0x3456",},
  "mipseb"      :{ "34213456","ori $at, $at, 0x3456",},
  "mips64"      :{ "56342134","ori $at, $at, 0x3456",},
  "mips64eb"    :{ "34213456","ori $at, $at, 0x3456",},
  "sparc"       :{ "86004002","add %g1, %g2, %g3",},
  "sparcel"     :{ "02400086","add %g1, %g2, %g3",},
  "sparc64"     :{ "86004002","add %g1, %g2, %g3",},
  "powerpc"     :{ "7c221a14","add 1,2,3",},
  "powerpc64"   :{ "7c221a14","add 1,2,3",},
  "powerpc64el" :{ "141a227c","add 1,2,3",},
  "systemZ"     :{ "5a0f1fff","a %r0, 4095(%r15,%r1)",},
}

func TestXAssemble(t *testing.T) {
    var (
        mc Machine
    )

    for _, arch := range archList {
        mc = SetArch(arch)
        correct, _ := hex.DecodeString(testCodes[arch][0])
        code,_ := mc.assemble(testCodes[arch][1])
        if !reflect.DeepEqual(code, correct) {
            t.Errorf("[-]: %s(o: %x, x: %x)", arch, correct, code)
        }
    }
    mc.Finalize()
}

func TestXEmulate(t *testing.T) {
    var (
        mc Machine
    )
    for _, arch := range archList {
        mc = SetArch(arch)
        code, _ := hex.DecodeString(testCodes[arch][0])
        mu.emulate(code)
    }

    mc.Finalize()
}
