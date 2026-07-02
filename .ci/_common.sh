setup_qemu() {
	if [ "$GITHUB_ACTIONS" != "true" ]; then
		echo "setup_qemu: skipping (not GitHub Actions CI)" >&2
		return 0
	fi

    # GitHub runners run unattended-upgrades at boot, which holds the dpkg lock.
    # Without DPkg::Lock::Timeout, apt-get blocks on the lock INDEFINITELY with no
    # output (the old `-qq ... >/dev/null` hid it) -> the random "hangs forever".
    # So: bound the lock wait (fail loud, not forever), retry transient mirror
    # errors, wrap each call in `timeout`, and keep output visible for diagnosis.
    export DEBIAN_FRONTEND=noninteractive
    apt="sudo apt-get -o DPkg::Lock::Timeout=240 -o Acquire::Retries=3"
    n=0
    until [ "$n" -ge 3 ]; do
        if timeout 300 $apt update && timeout 300 $apt install -y qemu-system-misc; then
            break
        fi
        n=$((n + 1))
        echo "setup_qemu: apt attempt $n/3 failed, retrying in 15s..." >&2
        sleep 15
    done
    [ "$n" -lt 3 ] || { echo "setup_qemu: apt failed after 3 attempts" >&2; return 1; }
    qemu-system-riscv32 --version | head -1
}

