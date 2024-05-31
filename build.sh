#!/bin/bash

set -xe

# Create the out folder if not present
mkdir -p out

gcc -std=c11 -Wall -Wextra -pedantic main.c -o out/demo

cd out

# Program usage N visualizers_count
./demo 100 10