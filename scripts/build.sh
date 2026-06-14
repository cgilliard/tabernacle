#!/bin/sh
set -e

CPU="rv32,m=false,a=false,f=false,d=false,c=false,\
zawrs=false,zfa=false,zfh=false,zfhmin=false,zcb=false,\
zcd=false,zcf=false,zcmp=false,zcmt=false,zicsr=false,zifencei=false"
MEM="128M"

run() {
	out=$1; asm=$2; shift 2
	disk_args=""; disk=""
	if [ "$1" = "--disk" ]; then
		disk=$2
		disk_args="-drive file=$disk,format=raw,if=none,id=hd0 \
-device virtio-blk-device,drive=hd0"
		shift 2
	fi
	[ $# -gt 0 ] && echo "Building $* → $out" >&2
	([ $# -gt 0 ] && cat "$@"; printf '\004') | qemu-system-riscv32 \
		-machine virt -m "$MEM" -cpu "$CPU" \
		-display none -bios none \
		-chardev stdio,id=ser0,mux=off,signal=off \
		-serial chardev:ser0 \
		-device loader,file="$asm",addr=0x80000000 \
		$disk_args > "$out"
}

pack() {
        in=$1; out=$2
        echo "Packing $in → $out" >&2
        N=$(stat -c %s "$in")
        { printf "$(printf '\\%03o' $((N&255)) $(((N>>8)&255)) $(((N>>16)&255)) $(((N>>24)&255)))"
          cat "$in"
        } | qemu-system-riscv32 -machine virt -m "$MEM" -cpu "$CPU" \
                -display none -bios none \
                -chardev stdio,id=ser0,mux=off,signal=off -serial chardev:ser0 \
                -device loader,file=bin/fampack,addr=0x80000000 > "$out"
}

patch_config() {
        bin=$1; data=$2
        echo "Patching $bin (bin_size + hash of $data)" >&2
        N=$(stat -c %s "$data")
        NCHUNKS=$(( (N + 1399) / 1400 ))
        TAB_SIZE=$(stat -c %s "$bin")
        # Layout at end of tabernacle: [nchunks 4B][bin_size 4B][hash 32B]
        # Write nchunks (LE) at TAB_SIZE-40
        printf "$(printf '\\%03o' $((NCHUNKS&255)) $(((NCHUNKS>>8)&255)) $(((NCHUNKS>>16)&255)) $(((NCHUNKS>>24)&255)))" \
                | dd of="$bin" bs=1 seek=$((TAB_SIZE - 40)) conv=notrunc 2>/dev/null
        # Write bin_size (LE) at TAB_SIZE-36
        printf "$(printf '\\%03o' $((N&255)) $(((N>>8)&255)) $(((N>>16)&255)) $(((N>>24)&255)))" \
                | dd of="$bin" bs=1 seek=$((TAB_SIZE - 36)) conv=notrunc 2>/dev/null
        # Write hash at TAB_SIZE-32
        ghash_input=$(mktemp)
        { printf "$(printf '\\%03o' $((N&255)) $(((N>>8)&255)) $(((N>>16)&255)) $(((N>>24)&255)))"
          cat "$data"
        } > "$ghash_input"
        HASH=$(qemu-system-riscv32 -machine virt -m "$MEM" -cpu "$CPU" \
                -display none -bios none \
                -chardev stdio,id=ser0,mux=off,signal=off -serial chardev:ser0 \
                -device loader,file=bin/gen_hash,addr=0x80000000 \
                -device loader,file="$ghash_input",addr=0x80800000 2>/dev/null)
        rm -f "$ghash_input"
        [ $(echo $HASH | wc -w) -eq 8 ] || { echo "gen_hash failed"; exit 1; }
        LEHEX=""
        for word in $HASH; do
                LEHEX="${LEHEX}$(echo "$word" | sed 's/\(..\)\(..\)\(..\)\(..\)/\4\3\2\1/')"
        done
        echo "$LEHEX" | xxd -r -p | dd of="$bin" bs=1 seek=$((TAB_SIZE - 32)) conv=notrunc 2>/dev/null
}

run bin/fam0 fam0.seed src/fam0.fam0
cmp ./bin/fam0 ./fam0.seed || { echo "fam0: binaries don't match!"; exit 1; }
run bin/fam.uncompressed bin/fam0 src/fam.fam0
run bin/fampack bin/fam.uncompressed lib/stdlib.fam lib/asm.fam src/fampack.fam
pack bin/fam.uncompressed bin/fam
run bin/gen_hash bin/fam lib/stdlib.fam lib/asm.fam src/gen_hash.fam
run bin/tabernacle.uncompressed bin/fam0 src/tabernacle.fam0
run bin/full_node.bin \
	bin/fam \
	lib/stdlib.fam \
	lib/build.fam \
	src/fence.fam \
	src/disk.fam \
	src/net.fam \
	src/node_serve.fam \
	src/full_node.fam
cat resources/bible.compressed >> bin/full_node.bin
patch_config bin/tabernacle.uncompressed bin/full_node.bin
pack bin/tabernacle.uncompressed bin/tabernacle

