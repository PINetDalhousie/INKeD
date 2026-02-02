#!/bin/bash

tc filter del dev eno1 ingress
tc filter del dev eno1 egress
tc filter del dev eno2 ingress
tc filter del dev eno2 egress
rm /sys/fs/bpf/tc/globals/*
make clean
