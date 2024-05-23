#!/bin/bash

set -xe

mkdir -p out

gcc -std=c11 -Wall -Wextra -pedantic main.c -o out/demo

cd out

./demo 10