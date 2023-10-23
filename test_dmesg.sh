#!/usr/bin/env bash

make test && sudo dmesg -C && clear && ./test && sudo dmesg
