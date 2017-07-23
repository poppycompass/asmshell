#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import sys
import termios

LINE_LEN = 48
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

def hist_prev(hist, index, prompt):
    if index > 0:
        index = index-1
    elif index <= 0:
        index = 0
    elif index >= len(hist):
        index = len(hist)-1
    sys.stdout.write('\r' + ' '*(LINE_LEN) + '\r' + prompt + hist[index])
    return hist, index

def hist_next(hist, index, prompt):
    if index < (len(hist)-1):
        index = index+1
    elif index <= 0:
        index = 0
    elif index >= len(hist):
        index = len(hist)-1
    sys.stdout.write('\r' + ' '*(LINE_LEN) + '\r' + prompt + hist[index])
    return hist, index

def parse_input(hist, prompt):
    buf = ""
    index = len(hist)
    while True:
        key = getkey()
        #print("key: " + str(key))
        if key >= 0x20 and key <= 0x7E:
            sys.stdout.write(chr(key))
            buf += chr(key)
        elif key == ord(''): # Ctrl+p
            hist, index = hist_prev(hist, index, prompt)
            buf = hist[index]
        elif key == ord(''): # Ctrl+n
            hist, index = hist_next(hist, index, prompt)
            buf = hist[index]
        elif key == ord(''): # Ctrl+u
            sys.stdout.write('\r' + ' '*(LINE_LEN) + '\r' + prompt)
            buf = ''
        elif key == ord('\b') or key == 127: # Ctrl-h and backspace
            if len(buf):
                buf = buf[0:-1]
                sys.stdout.write("\b \b")
        elif key == ord(''): # not implemented. Ctrl-a
            sys.stdout.write('')
        elif key == ord(''): # not implemented. Ctrl-e
            sys.stdout.write('')
        elif key == ord(''): # Ctrl-d(EOF)
            buf = 'quit'
            return buf, hist
        elif key == ord('\n'): # Enter
            sys.stdout.write(chr(key))
            hist.append(buf)
            index = len(hist)-1
            return buf, hist
