// go test "github.com/poppycompass/asmshell/go/arch"
package arch

import "testing"

func TestXX86(t *testing.T) {
    var (
        mc Machine
        correct = []byte {0x40}
    )
    mc = SetX86()
    if !mc.check("inc eax", correct) {
        t.Errorf("assemble")
    }
    mc.Finalize()
}
//    t.Fatalf()
//    t.Errorf()
//    t.Logf()
