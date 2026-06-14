#!/bin/sh

if [ ! -e ./data/disk.img ]; then
	dd if=/dev/zero of=./data/disk.img bs=1M count=8
fi

printf '3737 2 10000 159.54.172.190:3737 146.235.230.124:3737\004' | \
	./tools/q32 bin/tabernacle \
	--disk=./data/disk.img \
	--net \
	--hostfwd=udp::3737-:3737
