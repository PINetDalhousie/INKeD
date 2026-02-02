#!/bin/bash

rm /sys/fs/bpf/tc/globals/*
make TIME_NS=$((i*1000000)) SIZE_B=6500 GROUP_S=6 MAX_FLOWS=10240
tc filter add dev eno1 ingress bpf da obj kern.o sec tc
tc filter add dev eno1 egress bpf da obj kern.o sec tc
tc filter add dev eno2 ingress bpf da obj kern.o sec tc
tc filter add dev eno2 egress bpf da obj kern.o sec tc
