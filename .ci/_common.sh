# Shared helpers for the .ci/ proof scripts.  Source it:
#     . "$(dirname "$0")/_common.sh"
# The verifiers (tools/verify_fsm.py, tools/verify_wx.py) are pure Python; the
# only build dependency is qemu-system-riscv32 to run the bootstrap chain.

setup_qemu() {
	if [ "$GITHUB_ACTIONS" != "true" ]; then
		echo "setup_qemu: skipping (not GitHub Actions CI)" >&2
		return 0
	fi

    sudo apt-get update -qq
    sudo apt-get install -y -qq qemu-system-misc >/dev/null
    qemu-system-riscv32 --version | head -1
}

# Build bin/fam0, bin/fam.uncompressed, bin/fampack, bin/fam from committed
# sources (also re-checks the fam0 self-reproduction via cmp inside build.sh).
build_fam() {
    mkdir -p bin
    sh scripts/build.sh
    ls -l bin/
}
