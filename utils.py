#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

# change output color
def red(s,e="\n"): print("\033[91m{}\033[00m".format(s), end=e)
def green(s,e="\n"): print("\033[92m{}\033[00m".format(s), end=e)
def yellow(s,e="\n"): print("\033[93m{}\033[00m".format(s), end=e)
def lightPurple(s,e="\n") : print("\033[94m{}\033[00m".format(s), end=e)
def purple(s,e="\n"): print("\033[95m{}\033[00m".format(s), end=e)
def cyan(s,e="\n"): print("\033[96m{}\033[00m".format(s), end=e)
def lightGray(s,e="\n"): print("\033[97m{}\033[00m".format(s), end=e)
def black(s,e="\n"): print("\033[98m{}\033[00m".format(s), end=e)
def white(s,e="\n"): print("\033[00m", end=e)
def bold_green(s,e="\n"): print("\033[92m\033[1m{}\033[00m".format(s), end=e)
def bold_yellow(s,e="\n"): print("\033[93m\033[1m{}\033[00m".format(s), end=e)
