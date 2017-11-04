package asmshell

import (
    "github.com/keystone-engine/keystone/bindings/go/keystone"
    uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)
type AsmShell struct {
    CodeAddr uint64
    StackStart uint64
    StackAddr uint64
    StackSize uint64
    PrintSize uint64
    PrintMergin uint64

    KeystoneArch keystone.Architecture
    KeystoneMode keystone.Mode
    KeystoneOPTType keystone.OptionType
    KeystoneOPTVal keystone.OptionValue
    UnicornArch int
    UnicornMode int
    SavedCtx uc.Context
    SavedStack []byte
    SavedStackSize uint64
    Prompt string
}
