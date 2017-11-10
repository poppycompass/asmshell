package utils

import "github.com/fatih/color"

type Pallet struct {
    Red         *color.Color
    Green       *color.Color
    Yellow      *color.Color
    Blue        *color.Color
    Magenta     *color.Color
    Cyan        *color.Color
    White       *color.Color
    BoldRed     *color.Color
    BoldGreen   *color.Color
    BoldYellow  *color.Color
    BoldBlue    *color.Color
    BoldMagenta *color.Color
    BoldCyan    *color.Color
    BoldWhite   *color.Color
    HiRed       *color.Color
    HiGreen     *color.Color
    HiYellow    *color.Color
    HiBlue      *color.Color
    HiMagenta   *color.Color
    HiCyan      *color.Color
    HiWhite     *color.Color
}
func InitPallet() Pallet {
    var p Pallet
    p.Red         = color.New(color.FgRed)
    p.Green       = color.New(color.FgGreen)
    p.Yellow      = color.New(color.FgYellow)
    p.Blue        = color.New(color.FgBlue)
    p.Magenta     = color.New(color.FgMagenta)
    p.Cyan        = color.New(color.FgCyan)
    p.White       = color.New(color.FgWhite)
    p.BoldRed     = color.New(color.FgRed, color.Bold)
    p.BoldGreen   = color.New(color.FgGreen, color.Bold)
    p.BoldYellow  = color.New(color.FgYellow, color.Bold)
    p.BoldBlue    = color.New(color.FgBlue, color.Bold)
    p.BoldMagenta = color.New(color.FgMagenta, color.Bold)
    p.BoldCyan    = color.New(color.FgCyan, color.Bold)
    p.BoldWhite   = color.New(color.FgWhite, color.Bold)
    p.HiRed       = color.New(color.FgHiRed)
    p.HiGreen     = color.New(color.FgHiGreen)
    p.HiYellow    = color.New(color.FgHiYellow)
    p.HiBlue      = color.New(color.FgHiBlue)
    p.HiMagenta   = color.New(color.FgHiMagenta)
    p.HiCyan      = color.New(color.FgHiCyan)
    p.HiWhite     = color.New(color.FgHiWhite)
    return p
}
