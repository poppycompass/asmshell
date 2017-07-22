#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import sys
import termios

HIST_SIZE = 256
def getkey():
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    new = termios.tcgetattr(fd)
    new[3] &= ~termios.ICANON
    new[3] &= ~termios.ECHO

    try:
        termios.tcsetattr(fd, termios.TCSANOW, new)
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, old)
    return ord(ch)

def hist_prev(hist, index):
    if index > 0 and index < len(hist):
        index = index-1
    elif index < 0:
        index = 0
    elif index >= len(hist):
        index = len(hist)-1
    sys.stdout.write('\r' + hist[index])
    return hist, index

def hist_next(hist, index):
    if index >= 0 and index < (len(hist)-1):
        index = index+1
    elif index < 0:
        index = 0
    elif index >= len(hist):
        index = len(hist)-1
    sys.stdout.write('\r' + hist[index])
    return hist, index

def cmd_parse():
    buf = ""
    hist = ['']
    index = 0
    while True:
        key = getkey()
        if key >= 0x20 and key <= 0x7e:
            sys.stdout.write(chr(key))
            buf += chr(key)
        elif key == 16: # Ctrl+p
            hist, index = hist_prev(hist, index)
            buf = hist[index]
        elif key == 14: # Ctrl+n
            hist, index = hist_next(hist, index)
            buf = hist[index]
        elif key == ord('\n'): # Enter
            sys.stdout.write(chr(key))
            hist.append(buf)
            index = len(hist)-1
            buf = ""
        elif key == ord('\b'): # Ctrl-h(backspace)
            buf = buf[0:-1]
            sys.stdout.write("\b \b")

if __name__ == '__main__':
    cmd_parse()
