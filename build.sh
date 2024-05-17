#!/bin/bash

set -xe

gcc -std=c11 -Wall -Wextra -pedantic -ggdb main.c -o out/demo
./out/demo 10