#!/bin/sh

sudo apt install git radare2 gcc
git clone https://github.com/unicorn-engine/unicorn
cd unicorn
./make.sh
sudo make install
