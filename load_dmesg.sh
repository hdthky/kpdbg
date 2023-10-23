#!/usr/bin/env bash

sudo make unload; make && sudo dmesg -C && sudo make load && clear && sudo dmesg
