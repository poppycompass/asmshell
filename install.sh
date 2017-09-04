#!/bin/sh

sudo apt install git gcc
PWD=$(pwd)
echo "Install radare2 from github..."
git clone https://github.com/radare/radare2
cd radare2
sys/install.sh
cd ${PWD}
echo "Install unicorn from github..."
git clone https://github.com/unicorn-engine/unicorn
cd unicorn
./make.sh
sudo make install
sudo python ./bindings/python/setup.py install
echo "Done!"
