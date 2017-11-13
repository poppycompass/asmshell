package main

import (
    "fmt"
    "strings"
)

// TODO: fix f*ck help
func help() {
    fmt.Printf(strings.Join([]string{
        "Usage: asmshell [-h|--help] [-a|--arch ARCH] [-L|--List]\n\n",
        "    -h, --help             Show this help message and exit \n",
        "    -a ARCH, --arch ARCH   Target architecture(Default: x86, see '-L')\n",
        "       Supported: %s\n",
        "    -L, --List             Show details of supported architectures\n",
        "    -H, --HTTP             (Not implemented)Run with http server\n",
        "    -p PORT, --port PORT   (Not implemented)Set port(Default: 8080)\n",
    }, ""), SUPPORTED)
}

func showArchList() {
    fmt.Printf(strings.Join([]string{
        "Details of supported Archtecture: \n",
        "    i8086         : Intel 16-bit. iAPX 86. little endian\n",
        "    x86           : Intel 32-bit. 80386/IA-32. Extended i8086 to 32-bits. little endian\n",
        "    x64           : Intel 64-bit. AMD64. Extended x86 to 64-bits. little endian\n",
        "    thumb(be) : Arm Thumb mode(including Thumb-2). Mainly 16-bit. thumbbe is big endian\n",
        "    arm(be)       : Advanced RISC Machine. 32-bit. armbe is big endian\n",
        "    arm64(be)     : Armv8, 64-bit. arm64be is big endian\n",
        "    mips(be)      : MIPS, 32-bit. mipsbe is big endian\n",
        "    mips64(be)    : MIPS, 64-bit. mips64be is big endian\n",
        "    sparc(el)     : SPARC, 32-bit. sparcel only supports assembly. sparcel is little endian\n",
        "    sparc64       : SPARC, 64-bit. big-endian\n",
        "    powerpc       : Support assemble only. PowerPC, 32-bit. big-endian\n",
        "    powerpc64(el) : Support assemble only. PowerPC, 64-bit. powerpc64el is little endian\n",
        "    systemZ       : Support assemble only. Architecture for IBM eServer zSeries. big-endian\n",
    }, ""))
}
