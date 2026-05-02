#!/bin/bash

function build_netcat_cpp()
{
    rm -rf *.out; g++ -std=c++17 -Og -O0 -g -D DEBUG=1 -D HAVE_CONFIG_H=1 ./*.cpp -I ../ -o nc_cpp.out;
}

build_netcat_cpp